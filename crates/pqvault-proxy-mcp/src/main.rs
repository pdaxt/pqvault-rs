use std::collections::HashMap;
use std::sync::Arc;

use reqwest::header::HeaderMap;
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
use pqvault_core::models::VaultData;
use pqvault_core::providers::{detect_provider, get_provider};
use pqvault_core::proxy;
use pqvault_core::smart::UsageTracker;
use pqvault_core::vault::{open_vault, vault_exists};

#[derive(Clone)]
pub struct PqVaultProxyMcp {
    vault: Arc<Mutex<Option<VaultData>>>,
    tracker: Arc<Mutex<UsageTracker>>,
    http_client: reqwest::Client,
    tool_router: ToolRouter<PqVaultProxyMcp>,
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

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl PqVaultProxyMcp {
    pub fn new() -> Self {
        let vault_data = if vault_exists() {
            open_vault().ok()
        } else {
            None
        };

        Self {
            vault: Arc::new(Mutex::new(vault_data)),
            tracker: Arc::new(Mutex::new(UsageTracker::new())),
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Proxy an API call through the vault -- key is injected as auth, never exposed to the caller. Use this instead of vault_get when you need to call an external API."
    )]
    async fn vault_proxy(
        &self,
        Parameters(params): Parameters<ProxyParam>,
    ) -> Result<CallToolResult, McpError> {
        let vault = self.vault.lock().await;
        let data = vault.as_ref().ok_or_else(|| {
            McpError::internal_error("Vault not initialized.", None)
        })?;

        let key = &params.key;
        let caller = params.caller.as_deref().unwrap_or("mcp");

        let secret = match data.secrets.get(key.as_str()) {
            Some(s) => s,
            None => return text_result(format!("PROXY ERROR: Key not found: {}", key)),
        };

        // Rate limit check
        let mut tracker = self.tracker.lock().await;
        tracker.ensure_key(key, &secret.value);
        let limit_result = tracker.check_rate_limit(key);
        if !limit_result.allowed {
            tracker.save();
            log_access("proxy_blocked", key, "", caller);
            return text_result(format!("PROXY ERROR: RATE LIMITED -- {}", limit_result.reason));
        }

        // Detect provider and get auth config
        let provider_name = detect_provider(key, &secret.value);
        let provider = provider_name.as_deref().and_then(get_provider);

        // Determine auth method
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

        // Resolve URL
        let mut url = proxy::resolve_url(&params.url, provider)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        // Get allowed domains
        let allowed_domains = if let Some(p) = provider {
            &p.allowed_domains
        } else {
            &vec![]
        };

        // SSRF validation
        if !allowed_domains.is_empty() {
            proxy::validate_url(&url, allowed_domains)
                .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;
        } else {
            proxy::validate_url(
                &url,
                &[url.host_str().unwrap_or("").to_string()],
            )
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;
        }

        // Parse method
        let method = proxy::parse_method(&params.method)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        // Inject auth
        let mut headers = HeaderMap::new();
        proxy::inject_auth(&mut headers, &mut url, &secret.value, &auth_method)
            .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        // Record access before HTTP call
        tracker.record_access(key, caller);
        tracker.check_smart_alerts(key, &secret.rotated, secret.rotation_days);
        tracker.save();
        drop(tracker);
        drop(vault);

        log_access("proxy", key, "", caller);

        // Execute request
        let result = proxy::execute_proxy(
            &self.http_client,
            method,
            url,
            headers,
            params.body,
            params.headers.as_ref(),
            params.query.as_ref(),
        )
        .await
        .map_err(|e| McpError::internal_error(format!("PROXY ERROR: {}", e), None))?;

        text_result(result)
    }
}

#[tool_handler]
impl ServerHandler for PqVaultProxyMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("pqvault-proxy", "2.1.0"))
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions("PQVault Proxy: Zero-knowledge API proxy. Use vault_proxy to make API calls without seeing the key. Auth is auto-injected based on provider detection. SSRF-protected, rate-limited, cost-tracked. PREFER this over vault_get when calling external APIs.".to_string())
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

    tracing::info!("Starting PQVault Proxy MCP server");

    let service = PqVaultProxyMcp::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
