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
use pqvault_core::models::{auto_categorize, SecretEntry, VaultData};
use pqvault_core::providers::{detect_provider, PROVIDERS};
use pqvault_core::smart::UsageTracker;
use pqvault_core::vault::{meta_file, open_vault, save_vault, vault_exists};

#[derive(Clone)]
pub struct PqVaultMcp {
    vault: Arc<Mutex<Option<VaultData>>>,
    tracker: Arc<Mutex<UsageTracker>>,
    tool_router: ToolRouter<PqVaultMcp>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeyParam {
    /// Secret key name
    pub key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetParam {
    /// Secret key name
    pub key: String,
    /// Which tool/MCP is requesting (for audit trail)
    #[serde(default)]
    pub caller: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListParam {
    /// Filter by category (optional)
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParam {
    /// Search pattern
    pub pattern: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddParam {
    /// Secret key name
    pub key: String,
    /// Secret value
    pub value: String,
    /// Category: ai, payment, cloud, social, email, database, auth, search, general
    #[serde(default)]
    pub category: Option<String>,
    /// Description of this secret
    #[serde(default)]
    pub description: Option<String>,
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl PqVaultMcp {
    pub fn new() -> Self {
        let vault_data = if vault_exists() {
            open_vault().ok()
        } else {
            None
        };

        Self {
            vault: Arc::new(Mutex::new(vault_data)),
            tracker: Arc::new(Mutex::new(UsageTracker::new())),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Vault health summary: encryption info, key count, health status")]
    async fn vault_status(&self) -> Result<CallToolResult, McpError> {
        let vault = self.vault.lock().await;
        let data = vault.as_ref().ok_or_else(|| {
            McpError::internal_error("Vault not initialized. Run 'pqvault init'.", None)
        })?;
        let tracker = self.tracker.lock().await;

        let meta: serde_json::Value = if meta_file().exists() {
            serde_json::from_str(&std::fs::read_to_string(meta_file()).unwrap_or_default())
                .unwrap_or_default()
        } else {
            serde_json::Value::Null
        };

        let report = pqvault_core::health::check_health(data);
        let alerts = tracker.get_active_alerts();

        let text = format!(
            "Encryption: {}\nPQ Algorithm: {}\nTotal Secrets: {}\nProjects: {}\nHealth: {}\nExpired: {}\nNeeds Rotation: {}\nActive Alerts: {}\nCategories: {}",
            meta.get("encryption").and_then(|v| v.as_str()).unwrap_or("unknown"),
            meta.get("pq_algorithm").and_then(|v| v.as_str()).unwrap_or("unknown"),
            report.total_secrets,
            data.projects.len(),
            if report.is_healthy() { "HEALTHY" } else { "ISSUES FOUND" },
            report.expired.len(),
            report.needs_rotation.len(),
            alerts.len(),
            serde_json::to_string(&report.by_category).unwrap_or_default(),
        );
        log_access("status", "", "", "mcp");
        text_result(text)
    }

    #[tool(description = "Get a secret value by key name. Rate-limited and usage-tracked.")]
    async fn vault_get(
        &self,
        Parameters(params): Parameters<GetParam>,
    ) -> Result<CallToolResult, McpError> {
        let vault = self.vault.lock().await;
        let data = vault.as_ref().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let caller = params.caller.as_deref().unwrap_or("mcp");

        let secret = match data.secrets.get(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("Key not found: {}", key)),
        };

        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, &secret.value);

        let limit_result = tracker.check_rate_limit(key);
        if !limit_result.allowed {
            tracker.save();
            log_access("get_blocked", key, "", caller);
            return text_result(format!("RATE LIMITED: {}", limit_result.reason));
        }

        tracker.record_access(key, caller);
        tracker.check_smart_alerts(key, &secret.rotated, secret.rotation_days);
        log_access("get", key, "", caller);

        let usage = tracker.get_usage(key);
        let mut contents = vec![Content::text(secret.value.clone())];
        if let Some(u) = usage {
            let mut usage_text = format!(
                "Usage: {} today | {} this month | {} total",
                u.requests_today(),
                u.requests_this_month(),
                u.total_requests
            );
            if limit_result.remaining >= 0 {
                usage_text.push_str(&format!(" | {} remaining", limit_result.remaining));
            }
            if limit_result.usage_pct > 0.0 {
                usage_text.push_str(&format!(" | {:.0}% of limit", limit_result.usage_pct));
            }
            contents.push(Content::text(usage_text));
        }
        Ok(CallToolResult::success(contents))
    }

    #[tool(description = "List all secrets with metadata and usage stats (no values shown)")]
    async fn vault_list(
        &self,
        Parameters(params): Parameters<ListParam>,
    ) -> Result<CallToolResult, McpError> {
        let vault = self.vault.lock().await;
        let data = vault.as_ref().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;
        let tracker = self.tracker.lock().await;
        let category = params.category.as_deref().unwrap_or("");

        let mut entries = Vec::new();
        let mut sorted_keys: Vec<&String> = data.secrets.keys().collect();
        sorted_keys.sort();

        for k in sorted_keys {
            let s = &data.secrets[k];
            if !category.is_empty() && s.category != category {
                continue;
            }
            let usage = tracker.get_usage(k);
            let usage_str = usage.map_or("usage=0".to_string(), |u| {
                format!("usage={}", u.total_requests)
            });
            let provider_str = usage
                .filter(|u| !u.provider.is_empty())
                .map_or(String::new(), |u| format!("provider={}", u.provider));

            entries.push(format!(
                "{} [{}] {} {} projects={} rotated={}",
                k,
                s.category,
                provider_str,
                usage_str,
                s.projects.join(","),
                s.rotated,
            ));
        }

        log_access("list", "", "", "mcp");
        let result = if entries.is_empty() {
            "No secrets found.".to_string()
        } else {
            entries.join("\n")
        };
        text_result(result)
    }

    #[tool(description = "Search secrets by name, tag, or description")]
    async fn vault_search(
        &self,
        Parameters(params): Parameters<SearchParam>,
    ) -> Result<CallToolResult, McpError> {
        let vault = self.vault.lock().await;
        let data = vault.as_ref().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;
        let pattern = params.pattern.to_lowercase();

        let mut matches = Vec::new();
        for (k, s) in &data.secrets {
            if k.to_lowercase().contains(&pattern)
                || s.description.to_lowercase().contains(&pattern)
                || s.category.to_lowercase().contains(&pattern)
                || s.tags.iter().any(|t| t.to_lowercase().contains(&pattern))
            {
                matches.push(format!("{} [{}] {}", k, s.category, s.description));
            }
        }

        let result = if matches.is_empty() {
            format!("No matches for '{}'", params.pattern)
        } else {
            matches.join("\n")
        };
        text_result(result)
    }

    #[tool(description = "Add a new secret to the vault with auto-detected provider and rate limits")]
    async fn vault_add(
        &self,
        Parameters(params): Parameters<AddParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.as_mut().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let value = &params.value;
        let cat = params
            .category
            .clone()
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| auto_categorize(key));
        let desc = params.description.clone().unwrap_or_default();

        if data.secrets.contains_key(key.as_str()) {
            return text_result(format!("Key '{}' already exists.", key));
        }

        data.secrets.insert(
            key.clone(),
            SecretEntry {
                value: value.clone(),
                category: cat.clone(),
                description: desc,
                created: Local::now().format("%Y-%m-%d").to_string(),
                rotated: Local::now().format("%Y-%m-%d").to_string(),
                expires: None,
                rotation_days: 90,
                projects: vec![],
                tags: vec![],
                account: None,
                environment: None,
                related_keys: vec![],
                last_verified: None,
                last_error: None,
                key_status: "unknown".to_string(),
            },
        );

        if let Err(e) = save_vault(data) {
            return text_result(format!("Failed to save vault: {}", e));
        }

        let provider = detect_provider(key, value);
        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, value);
        tracker.save();

        let mut text = format!("Added: {} [{}]", key, cat);

        if let Some(ref prov_name) = provider {
            if let Some(prov) = PROVIDERS.get(prov_name.as_str()) {
                text.push_str(&format!("\nProvider: {}", prov.display_name));
                let mut limits = Vec::new();
                if let Some(rpm) = prov.requests_per_minute {
                    limits.push(format!("{}/min", rpm));
                }
                if let Some(rpd) = prov.requests_per_day {
                    limits.push(format!("{}/day", rpd));
                }
                if let Some(rpm) = prov.requests_per_month {
                    limits.push(format!("{}/month", rpm));
                }
                if !limits.is_empty() {
                    text.push_str(&format!("\nRate limits: {}", limits.join(", ")));
                }
            }
        }

        log_access("add", key, "", "mcp");
        text_result(text)
    }

    #[tool(description = "Delete a secret from the vault and remove all usage data")]
    async fn vault_delete(
        &self,
        Parameters(params): Parameters<KeyParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.as_mut().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let secret = match data.secrets.remove(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("Key not found: {}", key)),
        };

        for proj in data.projects.values_mut() {
            proj.keys.retain(|k| k != key);
        }

        if let Err(e) = save_vault(data) {
            return text_result(format!("Failed to save: {}", e));
        }

        log_access("delete", key, "", "mcp");
        text_result(format!("Deleted: {} [{}]", key, secret.category))
    }

    #[tool(description = "Import API keys from ~/.claude.json env blocks into the vault")]
    async fn vault_import_claude(&self) -> Result<CallToolResult, McpError> {
        let claude_path = dirs::home_dir().unwrap().join(".claude.json");
        if !claude_path.exists() {
            return text_result("~/.claude.json not found.".to_string());
        }

        let content = std::fs::read_to_string(&claude_path)
            .map_err(|e| McpError::internal_error(format!("Failed to read: {}", e), None))?;
        let claude_data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| McpError::internal_error(format!("Invalid JSON: {}", e), None))?;

        let mut vault = self.vault.lock().await;
        let data = vault.as_mut().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key_patterns = ["API_KEY", "SECRET", "TOKEN", "KEY"];
        let mut imported = 0u32;
        let mut skipped = 0u32;
        let mut results = Vec::new();
        let mut imported_keys: Vec<(String, String)> = Vec::new();

        if let Some(servers) = claude_data.get("mcpServers").and_then(|v| v.as_object()) {
            for (server_name, server_config) in servers {
                if let Some(env) = server_config.get("env").and_then(|v| v.as_object()) {
                    for (env_name, env_value) in env {
                        let val = match env_value.as_str() {
                            Some(v) if !v.is_empty() && !v.starts_with("NEEDS_") => v,
                            _ => continue,
                        };

                        let upper = env_name.to_uppercase();
                        if !key_patterns.iter().any(|p| upper.contains(p)) {
                            continue;
                        }

                        if data.secrets.contains_key(env_name.as_str()) {
                            skipped += 1;
                            results.push(format!("SKIP {} (exists)", env_name));
                            continue;
                        }

                        let cat = auto_categorize(env_name);
                        let provider = detect_provider(env_name, val);
                        data.secrets.insert(
                            env_name.clone(),
                            SecretEntry {
                                value: val.to_string(),
                                category: cat,
                                description: format!(
                                    "Imported from claude.json ({})",
                                    server_name
                                ),
                                created: Local::now().format("%Y-%m-%d").to_string(),
                                rotated: Local::now().format("%Y-%m-%d").to_string(),
                                expires: None,
                                rotation_days: 90,
                                projects: vec![],
                                tags: vec![],
                                account: None,
                                environment: None,
                                related_keys: vec![],
                                last_verified: None,
                                last_error: None,
                                key_status: "unknown".to_string(),
                            },
                        );

                        imported_keys.push((env_name.clone(), val.to_string()));

                        imported += 1;
                        let prov_label = provider
                            .as_ref()
                            .and_then(|p| PROVIDERS.get(p.as_str()))
                            .map(|p| p.display_name.clone())
                            .unwrap_or_else(|| auto_categorize(env_name));
                        results.push(format!(
                            "OK   {} -> {} (from {})",
                            env_name, prov_label, server_name
                        ));
                    }
                }
            }
        }

        if imported > 0 {
            if let Err(e) = save_vault(data) {
                return text_result(format!("Imported but failed to save: {}", e));
            }
        }

        drop(vault);

        if !imported_keys.is_empty() {
            let mut tracker = self.tracker.lock().await;
            for (name, val) in &imported_keys {
                tracker.ensure_key(name, val);
            }
            tracker.save();
        }

        log_access("import_claude", "", "", "mcp");
        let text = format!(
            "## Import from ~/.claude.json\n\nImported: {} | Skipped: {}\n\n{}",
            imported,
            skipped,
            if results.is_empty() {
                "No API keys found in env blocks.".to_string()
            } else {
                results.iter().map(|r| format!("- {}", r)).collect::<Vec<_>>().join("\n")
            }
        );
        text_result(text)
    }
}

#[tool_handler]
impl ServerHandler for PqVaultMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("pqvault", "2.1.0"))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions("PQVault: Quantum-proof centralized secrets management. Tools: vault_status (vault summary), vault_get (retrieve secret by key), vault_list (list all secrets), vault_search (search by name/tag), vault_add (add new secret), vault_delete (remove secret), vault_import_claude (import from ~/.claude.json). For API proxy use pqvault-proxy-mcp. For health/dashboard use pqvault-health-mcp.".to_string())
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

    tracing::info!("Starting PQVault MCP server");

    let service = PqVaultMcp::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
