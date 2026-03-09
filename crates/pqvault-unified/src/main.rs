// PQVault Unified MCP — all 14 vault tools in a single server.
// Merges: pqvault-mcp (7), pqvault-env-mcp (3), pqvault-health-mcp (3), pqvault-proxy-mcp (1)

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Local;
use reqwest::header::HeaderMap;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use pqvault_core::audit::log_access;
use pqvault_core::env_gen::generate_env;
use pqvault_core::health::check_health;
use pqvault_core::models::{auto_categorize, SecretEntry};
use pqvault_core::providers::{detect_provider, get_provider, PROVIDERS};
use pqvault_core::proxy;
use pqvault_core::smart::{generate_dashboard, generate_key_status, UsageTracker};
use pqvault_core::vault::{meta_file, save_vault, VaultHolder};

// ── Param types ─────────────────────────────────────────────────────────────

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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProxyParam {
    /// Vault key name that holds the API credential
    pub key: String,
    /// HTTP method: GET, POST, PUT, PATCH, DELETE
    pub method: String,
    /// URL path (e.g. "/v1/balance") or full URL (e.g. "https://api.stripe.com/v1/balance")
    pub url: String,
    /// Request body (JSON string)
    #[serde(default)]
    pub body: Option<String>,
    /// Extra headers (NOT for auth -- auth is auto-injected)
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// Extra query parameters
    #[serde(default)]
    pub query: Option<HashMap<String, String>>,
    /// Which tool is calling (for audit trail)
    #[serde(default)]
    pub caller: Option<String>,
    /// Override auth method for unknown providers: "bearer", "basic", "header:X-Key", "query:api_key"
    #[serde(default)]
    pub auth_override: Option<String>,
}

// ── Unified server ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PqVaultUnified {
    vault: Arc<Mutex<VaultHolder>>,
    tracker: Arc<Mutex<UsageTracker>>,
    http_client: reqwest::Client,
    tool_router: ToolRouter<PqVaultUnified>,
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl PqVaultUnified {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(VaultHolder::new())),
            tracker: Arc::new(Mutex::new(UsageTracker::new())),
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
        }
    }

    // ── Core tools (from pqvault-mcp) ───────────────────────────────────

    #[tool(description = "Vault health summary: encryption info, key count, health status")]
    async fn vault_status(&self) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
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
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
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
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
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
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
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
        let data = vault.get_mut().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let value = &params.value;
        let cat = params.category.clone().filter(|c| !c.is_empty())
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
                lifecycle: "active".to_string(),
                lifecycle_reason: None,
                lifecycle_changed: None,
                versions: vec![],
                max_versions: 10,
                rotation_policy: None,
            },
        );

        if let Err(e) = save_vault(data) {
            return text_result(format!("Failed to save vault: {}", e));
        }
        vault.mark_saved();

        let provider = detect_provider(key, value);
        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, value);
        tracker.save();

        let mut text = format!("Added: {} [{}]", key, cat);
        if let Some(ref prov_name) = provider {
            if let Some(prov) = PROVIDERS.get(prov_name.as_str()) {
                text.push_str(&format!("\nProvider: {}", prov.display_name));
                let mut limits = Vec::new();
                if let Some(rpm) = prov.requests_per_minute { limits.push(format!("{}/min", rpm)); }
                if let Some(rpd) = prov.requests_per_day { limits.push(format!("{}/day", rpd)); }
                if let Some(rpm) = prov.requests_per_month { limits.push(format!("{}/month", rpm)); }
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
        let data = vault.get_mut().ok_or_else(|| {
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
        vault.mark_saved();

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
        let data = vault.get_mut().ok_or_else(|| {
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
                        if !key_patterns.iter().any(|p| upper.contains(p)) { continue; }
                        if data.secrets.contains_key(env_name.as_str()) {
                            skipped += 1;
                            results.push(format!("SKIP {} (exists)", env_name));
                            continue;
                        }
                        let cat = auto_categorize(env_name);
                        data.secrets.insert(
                            env_name.clone(),
                            SecretEntry {
                                value: val.to_string(),
                                category: cat,
                                description: format!("Imported from claude.json ({})", server_name),
                                created: Local::now().format("%Y-%m-%d").to_string(),
                                rotated: Local::now().format("%Y-%m-%d").to_string(),
                                expires: None, rotation_days: 90,
                                projects: vec![], tags: vec![],
                                account: None, environment: None, related_keys: vec![],
                                last_verified: None, last_error: None,
                                key_status: "unknown".to_string(),
                                lifecycle: "active".to_string(),
                                lifecycle_reason: None, lifecycle_changed: None,
                                versions: vec![], max_versions: 10, rotation_policy: None,
                            },
                        );
                        imported_keys.push((env_name.clone(), val.to_string()));
                        imported += 1;
                        let prov_label = detect_provider(env_name, val)
                            .as_ref()
                            .and_then(|p| PROVIDERS.get(p.as_str()))
                            .map(|p| p.display_name.clone())
                            .unwrap_or_else(|| auto_categorize(env_name));
                        results.push(format!("OK   {} -> {} (from {})", env_name, prov_label, server_name));
                    }
                }
            }
        }

        if imported > 0 {
            if let Err(e) = save_vault(data) {
                return text_result(format!("Imported but failed to save: {}", e));
            }
            vault.mark_saved();
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
            imported, skipped,
            if results.is_empty() { "No API keys found in env blocks.".to_string() }
            else { results.iter().map(|r| format!("- {}", r)).collect::<Vec<_>>().join("\n") }
        );
        text_result(text)
    }

    // ── Env tools (from pqvault-env-mcp) ────────────────────────────────

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
            Ok(env) => { log_access("export", "", &params.project, "mcp"); text_result(env) }
            Err(e) => text_result(e),
        }
    }

    #[tool(description = "Write .env file for a project directly to disk -- secret values are written to file but NEVER returned to the caller.")]
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
            return text_result(format!("Directory does not exist: {}", params.directory));
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
            return text_result(format!("Refusing to write env file to sensitive path: {}", canonical_str));
        }

        let filename = params.filename.as_deref().unwrap_or(".env.local");
        let filepath = canonical.join(filename);
        let secret_count = env_content.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count();

        std::fs::write(&filepath, &env_content).map_err(|e| {
            McpError::internal_error(format!("Failed to write env file: {}", e), None)
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&filepath, std::fs::Permissions::from_mode(0o600));
        }

        log_access("write_env", "", &params.project, "mcp");
        text_result(format!("Wrote {} secrets to {}", secret_count, filepath.display()))
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

    // ── Health tools (from pqvault-health-mcp) ──────────────────────────

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

    // ── Proxy tools (from pqvault-proxy-mcp) ────────────────────────────

    #[tool(description = "Proxy an API call through the vault -- key is injected as auth, never exposed to the caller. Use this instead of vault_get when you need to call an external API.")]
    async fn vault_proxy(
        &self,
        Parameters(params): Parameters<ProxyParam>,
    ) -> Result<CallToolResult, McpError> {
        let mut vault = self.vault.lock().await;
        let data = vault.get().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let caller = params.caller.as_deref().unwrap_or("mcp");

        let secret = match data.secrets.get(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("PROXY ERROR: Key not found: {}", key)),
        };

        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, &secret.value);
        let limit_result = tracker.check_rate_limit(key);
        if !limit_result.allowed {
            tracker.save();
            log_access("proxy_blocked", key, "", caller);
            return text_result(format!("PROXY ERROR: RATE LIMITED -- {}", limit_result.reason));
        }

        let provider_name = detect_provider(key, &secret.value);
        let provider = provider_name.as_deref().and_then(get_provider);

        let auth_method = if let Some(ref override_str) = params.auth_override {
            proxy::parse_auth_override(override_str)
                .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?
        } else {
            provider
                .and_then(|p| p.auth_method.clone())
                .ok_or_else(|| {
                    McpError::internal_error(
                        "PROXY ERROR: No auth method for this key -- use auth_override param (e.g. \"bearer\", \"header:X-Api-Key\")",
                        None,
                    )
                })?
        };

        let mut url = proxy::resolve_url(&params.url, provider)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        let allowed_domains = if let Some(p) = provider { &p.allowed_domains } else { &vec![] };

        if !allowed_domains.is_empty() {
            proxy::validate_url(&url, allowed_domains)
                .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;
        } else {
            proxy::validate_url(&url, &[url.host_str().unwrap_or("").to_string()])
                .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;
        }

        let method = proxy::parse_method(&params.method)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        let mut headers = HeaderMap::new();
        proxy::inject_auth(&mut headers, &mut url, &secret.value, &auth_method)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        tracker.record_access(key, caller);
        tracker.check_smart_alerts(key, &secret.rotated, secret.rotation_days);
        tracker.save();
        drop(tracker);
        drop(vault);

        log_access("proxy", key, "", caller);

        let result = proxy::execute_proxy(
            &self.http_client, method, url, headers,
            params.body, params.headers.as_ref(), params.query.as_ref(),
        )
        .await
        .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        text_result(result)
    }
}

#[tool_handler]
impl ServerHandler for PqVaultUnified {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::new("pqvault", "3.0.0"))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions(
            "PQVault: Quantum-proof centralized secrets management. \
             Tools: vault_status, vault_get, vault_list, vault_search, vault_add, vault_delete, \
             vault_import_claude, vault_project_env, vault_write_env, vault_rotate, \
             vault_health, vault_dashboard, vault_usage, vault_proxy."
                .to_string(),
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting PQVault Unified MCP (14 tools)");

    let service = PqVaultUnified::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| tracing::error!("serving error: {:?}", e))?;

    service.waiting().await?;
    Ok(())
}
