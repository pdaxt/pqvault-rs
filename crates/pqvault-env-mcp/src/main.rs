use std::sync::Arc;

use chrono::Local;
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
use pqvault_core::env_gen::generate_env;
use pqvault_core::smart::UsageTracker;
use pqvault_core::vault::{save_vault, VaultHolder};

#[derive(Clone)]
pub struct PqVaultEnvMcp {
    vault: Arc<Mutex<VaultHolder>>,
    tracker: Arc<Mutex<UsageTracker>>,
    tool_router: ToolRouter<PqVaultEnvMcp>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProjectParam {
    /// Project name
    pub project: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteEnvParam {
    /// Project name (must be registered in vault)
    pub project: String,
    /// Absolute path to directory where .env file will be written
    pub directory: String,
    /// Filename to write (default: ".env.local")
    #[serde(default)]
    pub filename: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RotateParam {
    /// Secret key name
    pub key: String,
    /// New secret value
    pub new_value: String,
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl PqVaultEnvMcp {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(VaultHolder::new())),
            tracker: Arc::new(Mutex::new(UsageTracker::new())),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get .env file content for a registered project")]
    async fn vault_project_env(
        &self,
        Parameters(params): Parameters<ProjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        match generate_env(data, &params.project) {
            Ok(env) => {
                log_access("export", "", &params.project, "mcp");
                text_result(env)
            }
            Err(e) => text_result(e),
        }
    }

    #[tool(
        description = "Write .env file for a project directly to disk -- secret values are written to file but NEVER returned to the caller."
    )]
    async fn vault_write_env(
        &self,
        Parameters(params): Parameters<WriteEnvParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let env_content = match generate_env(data, &params.project) {
            Ok(content) => content,
            Err(e) => return text_result(e),
        };

        let dir = std::path::Path::new(&params.directory);

        if !dir.exists() || !dir.is_dir() {
            return text_result(format!(
                "Directory does not exist: {}",
                params.directory
            ));
        }

        let canonical = dir.canonicalize().map_err(|e| {
            McpError::internal_error(format!("Cannot resolve path: {}", e), None)
        })?;
        let canonical_str = canonical.to_string_lossy();
        if canonical_str.starts_with("/etc")
            || canonical_str.starts_with("/usr")
            || canonical_str.starts_with("/var")
            || canonical_str.starts_with("/System")
            || canonical_str.contains("/.ssh")
            || canonical_str.contains("/.gnupg")
        {
            return text_result(format!(
                "Refusing to write env file to sensitive path: {}",
                canonical_str
            ));
        }

        let filename = params.filename.as_deref().unwrap_or(".env.local");
        let filepath = canonical.join(filename);

        let secret_count = env_content
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count();

        std::fs::write(&filepath, &env_content).map_err(|e| {
            McpError::internal_error(format!("Failed to write env file: {}", e), None)
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &filepath,
                std::fs::Permissions::from_mode(0o600),
            );
        }

        log_access("write_env", "", &params.project, "mcp");
        text_result(format!(
            "Wrote {} secrets to {}",
            secret_count,
            filepath.display()
        ))
    }

    #[tool(description = "Rotate a secret (update value and rotation timestamp)")]
    async fn vault_rotate(
        &self,
        Parameters(params): Parameters<RotateParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get_mut().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let secret = match data.secrets.get_mut(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("Key not found: {}", key)),
        };

        secret.value = params.new_value;
        secret.rotated = Local::now().format("%Y-%m-%d").to_string();

        if let Err(e) = save_vault(data) {
            return text_result(format!("Failed to save: {}", e));
        }
        vault.mark_saved();

        let tracker = self.tracker.lock().await;
        tracker.save();

        log_access("rotate", key, "", "mcp");
        text_result(format!("Rotated: {} (rotation alerts cleared)", key))
    }
}

#[tool_handler]
impl ServerHandler for PqVaultEnvMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("pqvault-env", "2.1.0"))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions("PQVault Env: Environment and rotation management. Tools: vault_project_env (get .env content), vault_write_env (write .env file to disk), vault_rotate (update secret value).".to_string())
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

    tracing::info!("Starting PQVault Env MCP server");

    let service = PqVaultEnvMcp::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
