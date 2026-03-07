use std::sync::Arc;

use rmcp::{ServiceExt,
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use pqvault_core::audit::log_access;
use pqvault_core::health::check_health;
use pqvault_core::smart::{generate_dashboard, generate_key_status, UsageTracker};
use pqvault_core::vault::VaultHolder;

#[derive(Clone)]
pub struct PqVaultHealthMcp {
    vault: Arc<Mutex<VaultHolder>>,
    tracker: Arc<Mutex<UsageTracker>>,
    tool_router: ToolRouter<PqVaultHealthMcp>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyParam {
    /// Secret key name
    pub key: String,
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl PqVaultHealthMcp {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(VaultHolder::new())),
            tracker: Arc::new(Mutex::new(UsageTracker::new())),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check rotation warnings, expired keys, orphaned keys, and smart alerts")]
    async fn vault_health(&self) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;
        let mut tracker = self.tracker.lock().await;

        let report = check_health(data);
        let mut lines = vec![format!("Total: {} secrets", report.total_secrets)];

        if !report.expired.is_empty() {
            lines.push(format!("EXPIRED: {}", report.expired.join(", ")));
        }
        if !report.needs_rotation.is_empty() {
            lines.push(format!("NEEDS ROTATION: {}", report.needs_rotation.join(", ")));
        }
        if !report.orphaned.is_empty() {
            let display: Vec<&str> = report.orphaned.iter().take(10).map(|s| s.as_str()).collect();
            lines.push(format!("ORPHANED (no project): {}", display.join(", ")));
        }

        for (k, s) in &data.secrets {
            tracker.ensure_key(k, &s.value);
            tracker.check_smart_alerts(k, &s.rotated, s.rotation_days);
        }
        tracker.save();

        let alerts = tracker.get_active_alerts();
        if !alerts.is_empty() {
            lines.push(String::new());
            lines.push(format!("SMART ALERTS ({}):", alerts.len()));
            for (key, a) in &alerts {
                let icon = match a.severity.as_str() {
                    "critical" => "!!",
                    "warning" => "!",
                    _ => "i",
                };
                lines.push(format!("  [{}] {}: {}", icon, key, a.message));
            }
        }

        if report.is_healthy() && alerts.is_empty() {
            lines.push("Status: HEALTHY".to_string());
        }

        text_result(lines.join("\n"))
    }

    #[tool(description = "Full smart dashboard: all keys with usage stats, rate limits, costs, alerts")]
    async fn vault_dashboard(&self) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;
        let mut tracker = self.tracker.lock().await;

        for (k, s) in &data.secrets {
            tracker.ensure_key(k, &s.value);
            tracker.check_smart_alerts(k, &s.rotated, s.rotation_days);
        }
        tracker.save();

        let text = generate_dashboard(&data.secrets, &tracker);
        log_access("dashboard", "", "", "mcp");
        text_result(text)
    }

    #[tool(description = "Detailed usage stats for a specific key: requests, rate limit %, cost estimate, alerts")]
    async fn vault_usage(
        &self,
        Parameters(params): Parameters<KeyParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;
        let key = &params.key;

        let secret = match data.secrets.get(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("Key not found: {}", key)),
        };

        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, &secret.value);
        tracker.check_smart_alerts(key, &secret.rotated, secret.rotation_days);
        tracker.save();

        let text = generate_key_status(key, secret, &tracker);
        text_result(text)
    }
}

#[tool_handler]
impl ServerHandler for PqVaultHealthMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("pqvault-health", "2.1.0"))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions("PQVault Health: Monitoring and intelligence. Tools: vault_health (rotation/expiry warnings), vault_dashboard (full usage overview), vault_usage (per-key stats).".to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting PQVault Health MCP server");

    let service = PqVaultHealthMcp::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
