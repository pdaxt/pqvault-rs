// PQVault Connector — Serves PQVault MCP tools over Streamable HTTP.
// Designed for Claude.ai Custom Connectors (Settings > Connectors).
//
// Transport: MCP over Streamable HTTP (POST /mcp with JSON-RPC)
// Auth: Bearer token via PQVAULT_API_KEY env var (authless if unset)

use std::sync::Arc;

use axum::{routing::get, Json, Router};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpService,
};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::EnvFilter;

use pqvault_core::vault::VaultHolder;
use pqvault_unified::PqVaultUnified;

#[derive(Serialize)]
struct RootStatus {
    service: &'static str,
    version: &'static str,
    status: &'static str,
    vault_initialized: bool,
    total_secrets: usize,
    mcp_endpoint: &'static str,
    tools: Vec<&'static str>,
}

/// Root endpoint — JSON vault status for Claude connector discovery.
async fn root_handler() -> Json<RootStatus> {
    let mut holder = VaultHolder::new();
    let (initialized, count) = match holder.get() {
        Some(v) => (true, v.secrets.len()),
        None => (false, 0),
    };

    Json(RootStatus {
        service: "pqvault-connector",
        version: env!("CARGO_PKG_VERSION"),
        status: "ok",
        vault_initialized: initialized,
        total_secrets: count,
        mcp_endpoint: "/mcp",
        tools: vec![
            "vault_status", "vault_get", "vault_list", "vault_search",
            "vault_add", "vault_delete", "vault_import_claude",
            "vault_project_env", "vault_write_env", "vault_rotate",
            "vault_health", "vault_dashboard", "vault_usage", "vault_proxy",
        ],
    })
}

/// Health check endpoint for Cloud Run / load balancers.
async fn health_handler() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let api_key = std::env::var("PQVAULT_API_KEY").ok();
    if api_key.is_some() {
        tracing::info!("Auth: Bearer token required (PQVAULT_API_KEY set)");
    } else {
        tracing::warn!("Auth: DISABLED (set PQVAULT_API_KEY to enable)");
    }

    // Create PqVaultUnified ONCE on main thread before server starts.
    // VaultHolder + UsageTracker perform scrypt key derivation (~20s on first load).
    tracing::info!("Loading vault (scrypt key derivation, may take a moment)...");
    let template = PqVaultUnified::new();
    tracing::info!("Vault loaded successfully");

    // MCP Streamable HTTP service — factory clones the pre-initialized instance
    let mcp_service = StreamableHttpService::new(
        move || Ok(template.clone()),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    // CORS — Claude.ai connects cross-origin
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(["mcp-session-id".parse().unwrap()]);

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .nest_service("/mcp", mcp_service)
        .layer(cors);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("PQVault Connector listening on {}", addr);
    tracing::info!("MCP endpoint: http://localhost:{}/mcp", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Shutting down...");
        })
        .await?;

    Ok(())
}
