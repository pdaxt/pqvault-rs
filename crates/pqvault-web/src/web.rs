use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::Local;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use pqvault_core::audit::log_access;
use pqvault_core::health::check_health;
use pqvault_core::models::{auto_categorize, mask_value, SecretEntry, VaultData};
use pqvault_core::providers::{get_provider, AuthMethod};
use pqvault_core::smart::UsageTracker;
use pqvault_core::vault::{meta_file, open_vault, save_vault, vault_exists, vault_file, VaultHolder};

use crate::auth;

struct AppState {
    vault: Mutex<VaultData>,
    tracker: Mutex<UsageTracker>,
    http_client: reqwest::Client,
    reload_tx: broadcast::Sender<String>,
}

// --- Response types ---

#[derive(Serialize)]
struct StatusResponse {
    encryption: String,
    pq_algorithm: String,
    total_secrets: usize,
    projects: usize,
    healthy: bool,
    expired: usize,
    needs_rotation: usize,
    categories: HashMap<String, usize>,
    providers: HashMap<String, usize>,
    status_counts: StatusCounts,
}

#[derive(Serialize)]
struct StatusCounts {
    active: usize,
    error: usize,
    unknown: usize,
}

#[derive(Serialize)]
struct SecretInfo {
    key: String,
    masked_value: String,
    category: String,
    provider: String,
    provider_display: String,
    account: Option<String>,
    environment: Option<String>,
    key_status: String,
    projects: Vec<String>,
    rotated: String,
    created: String,
    description: String,
    tags: Vec<String>,
    related_keys: Vec<String>,
    usage: u64,
    last_used: Option<String>,
    last_verified: Option<String>,
    last_error: Option<String>,
    can_verify: bool,
    lifecycle: String,
    lifecycle_reason: Option<String>,
    version_count: usize,
}

#[derive(Serialize)]
struct SecretsResponse {
    secrets: Vec<SecretInfo>,
}

#[derive(Serialize)]
struct HealthResponse {
    total: usize,
    healthy: bool,
    expired: Vec<String>,
    needs_rotation: Vec<String>,
    orphaned: Vec<String>,
    categories: HashMap<String, usize>,
}

#[derive(Serialize)]
struct ApiResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct VerifyResult {
    ok: bool,
    key: String,
    status: String,
    message: String,
}

// --- Request types ---

#[derive(Deserialize)]
struct AddRequest {
    key: String,
    value: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Deserialize)]
struct RotateRequest {
    new_value: String,
}

#[derive(Deserialize)]
struct UpdateMetaRequest {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

// --- Helper ---

fn build_secret_info(
    k: &str,
    s: &SecretEntry,
    tracker: &UsageTracker,
) -> SecretInfo {
    let usage = tracker.get_usage(k);
    let provider_name = usage.map_or(String::new(), |u| u.provider.clone());
    let provider_display = if provider_name.is_empty() {
        String::new()
    } else {
        get_provider(&provider_name)
            .map(|p| p.display_name.clone())
            .unwrap_or(provider_name.clone())
    };
    let can_verify = get_provider(&provider_name)
        .and_then(|p| p.verify_path.as_ref())
        .is_some();

    SecretInfo {
        key: k.to_string(),
        masked_value: mask_value(&s.value),
        category: s.category.clone(),
        provider: provider_name,
        provider_display,
        account: s.account.clone(),
        environment: s.environment.clone(),
        key_status: s.key_status.clone(),
        projects: s.projects.clone(),
        rotated: s.rotated.clone(),
        created: s.created.clone(),
        description: s.description.clone(),
        tags: s.tags.clone(),
        related_keys: s.related_keys.clone(),
        usage: usage.map_or(0, |u| u.total_requests),
        last_used: usage.and_then(|u| u.last_used.clone()),
        last_verified: s.last_verified.clone(),
        last_error: s.last_error.clone(),
        can_verify,
        lifecycle: s.lifecycle.clone(),
        lifecycle_reason: s.lifecycle_reason.clone(),
        version_count: s.versions.len(),
    }
}

// --- Handlers ---

async fn index_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn login_page_handler() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let vault = state.vault.lock().await;
    let tracker = state.tracker.lock().await;
    let report = check_health(&vault);

    let meta: serde_json::Value = if meta_file().exists() {
        serde_json::from_str(&std::fs::read_to_string(meta_file()).unwrap_or_default())
            .unwrap_or_default()
    } else {
        serde_json::Value::Null
    };

    // Count providers
    let mut providers: HashMap<String, usize> = HashMap::new();
    let mut status_active = 0usize;
    let mut status_error = 0usize;
    let mut status_unknown = 0usize;

    for (k, s) in &vault.secrets {
        let prov = tracker
            .get_usage(k)
            .map(|u| u.provider.clone())
            .unwrap_or_default();
        let prov_label = if prov.is_empty() {
            "(none)".to_string()
        } else {
            get_provider(&prov)
                .map(|p| p.display_name.clone())
                .unwrap_or(prov)
        };
        *providers.entry(prov_label).or_insert(0) += 1;

        match s.key_status.as_str() {
            "active" => status_active += 1,
            "error" => status_error += 1,
            _ => status_unknown += 1,
        }
    }

    Json(StatusResponse {
        encryption: meta
            .get("encryption")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        pq_algorithm: meta
            .get("pq_algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        total_secrets: report.total_secrets,
        projects: vault.projects.len(),
        healthy: report.is_healthy(),
        expired: report.expired.len(),
        needs_rotation: report.needs_rotation.len(),
        categories: report.by_category,
        providers,
        status_counts: StatusCounts {
            active: status_active,
            error: status_error,
            unknown: status_unknown,
        },
    })
}

async fn list_handler(State(state): State<Arc<AppState>>) -> Json<SecretsResponse> {
    let vault = state.vault.lock().await;
    let tracker = state.tracker.lock().await;

    let mut secrets: Vec<SecretInfo> = vault
        .secrets
        .iter()
        .map(|(k, s)| build_secret_info(k, s, &tracker))
        .collect();

    secrets.sort_by(|a, b| a.key.cmp(&b.key));
    Json(SecretsResponse { secrets })
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let vault = state.vault.lock().await;
    let report = check_health(&vault);

    Json(HealthResponse {
        total: report.total_secrets,
        healthy: report.is_healthy(),
        expired: report.expired,
        needs_rotation: report.needs_rotation,
        orphaned: report.orphaned,
        categories: report.by_category,
    })
}

async fn search_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchQuery>,
) -> Json<SecretsResponse> {
    let vault = state.vault.lock().await;
    let tracker = state.tracker.lock().await;
    let pattern = params.q.to_lowercase();

    let mut secrets: Vec<SecretInfo> = vault
        .secrets
        .iter()
        .filter(|(k, s)| {
            k.to_lowercase().contains(&pattern)
                || s.description.to_lowercase().contains(&pattern)
                || s.category.to_lowercase().contains(&pattern)
                || s.tags.iter().any(|t| t.to_lowercase().contains(&pattern))
                || s.projects
                    .iter()
                    .any(|p| p.to_lowercase().contains(&pattern))
                || s.account
                    .as_deref()
                    .map_or(false, |a| a.to_lowercase().contains(&pattern))
        })
        .map(|(k, s)| build_secret_info(k, s, &tracker))
        .collect();

    secrets.sort_by(|a, b| a.key.cmp(&b.key));
    Json(SecretsResponse { secrets })
}

async fn add_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddRequest>,
) -> (StatusCode, Json<ApiResult>) {
    let key = req.key.trim().to_string();
    let value = req.value.clone();

    if key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResult {
                ok: false,
                message: "Key name cannot be empty".to_string(),
            }),
        );
    }

    if value.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResult {
                ok: false,
                message: "Secret value cannot be empty".to_string(),
            }),
        );
    }

    let mut vault = state.vault.lock().await;

    if vault.secrets.contains_key(&key) {
        return (
            StatusCode::CONFLICT,
            Json(ApiResult {
                ok: false,
                message: format!("Key '{}' already exists", key),
            }),
        );
    }

    let cat = req
        .category
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| auto_categorize(&key));

    vault.secrets.insert(
        key.clone(),
        SecretEntry {
            value,
            category: cat.clone(),
            description: req.description.unwrap_or_default(),
            created: Local::now().format("%Y-%m-%d").to_string(),
            rotated: Local::now().format("%Y-%m-%d").to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec![],
            tags: vec![],
            account: req.account,
            environment: req.environment,
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

    if let Err(e) = save_vault(&vault) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResult {
                ok: false,
                message: format!("Failed to save: {}", e),
            }),
        );
    }

    let mut tracker = state.tracker.lock().await;
    tracker.ensure_key(&key, &req.value);
    tracker.save();

    log_access("add", &key, "", "web");

    (
        StatusCode::CREATED,
        Json(ApiResult {
            ok: true,
            message: format!("Added: {} [{}]", key, cat),
        }),
    )
}

async fn delete_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> (StatusCode, Json<ApiResult>) {
    let mut vault = state.vault.lock().await;

    if vault.secrets.remove(&key).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResult {
                ok: false,
                message: format!("Key not found: {}", key),
            }),
        );
    }

    for proj in vault.projects.values_mut() {
        proj.keys.retain(|k| k != &key);
    }

    if let Err(e) = save_vault(&vault) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResult {
                ok: false,
                message: format!("Failed to save: {}", e),
            }),
        );
    }

    log_access("delete", &key, "", "web");

    (
        StatusCode::OK,
        Json(ApiResult {
            ok: true,
            message: format!("Deleted: {}", key),
        }),
    )
}

async fn rotate_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(req): Json<RotateRequest>,
) -> (StatusCode, Json<ApiResult>) {
    let mut vault = state.vault.lock().await;

    let secret = match vault.secrets.get_mut(&key) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResult {
                    ok: false,
                    message: format!("Key not found: {}", key),
                }),
            )
        }
    };

    // Store old value in version history
    secret.versions.push(pqvault_core::models::SecretVersion {
        value: secret.value.clone(),
        rotated_at: Local::now().to_rfc3339(),
        rotated_by: "web".to_string(),
        reason: String::new(),
    });
    // Trim versions if exceeding max
    if secret.max_versions > 0 && secret.versions.len() > secret.max_versions {
        let excess = secret.versions.len() - secret.max_versions;
        secret.versions.drain(0..excess);
    }

    secret.value = req.new_value;
    secret.rotated = Local::now().format("%Y-%m-%d").to_string();
    secret.key_status = "unknown".to_string();
    secret.last_verified = None;
    secret.last_error = None;

    if let Err(e) = save_vault(&vault) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResult {
                ok: false,
                message: format!("Failed to save: {}", e),
            }),
        );
    }

    log_access("rotate", &key, "", "web");

    (
        StatusCode::OK,
        Json(ApiResult {
            ok: true,
            message: format!("Rotated: {}", key),
        }),
    )
}

async fn update_meta_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(req): Json<UpdateMetaRequest>,
) -> (StatusCode, Json<ApiResult>) {
    let mut vault = state.vault.lock().await;

    let secret = match vault.secrets.get_mut(&key) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResult {
                    ok: false,
                    message: format!("Key not found: {}", key),
                }),
            )
        }
    };

    if let Some(account) = req.account {
        secret.account = if account.is_empty() {
            None
        } else {
            Some(account)
        };
    }
    if let Some(env) = req.environment {
        secret.environment = if env.is_empty() {
            None
        } else {
            Some(env)
        };
    }
    if let Some(desc) = req.description {
        secret.description = desc;
    }

    if let Err(e) = save_vault(&vault) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResult {
                ok: false,
                message: format!("Failed to save: {}", e),
            }),
        );
    }

    log_access("update_meta", &key, "", "web");

    (
        StatusCode::OK,
        Json(ApiResult {
            ok: true,
            message: format!("Updated: {}", key),
        }),
    )
}

async fn verify_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> (StatusCode, Json<VerifyResult>) {
    let vault = state.vault.lock().await;

    let secret = match vault.secrets.get(&key) {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(VerifyResult {
                    ok: false,
                    key: key.clone(),
                    status: "error".into(),
                    message: "Key not found".into(),
                }),
            )
        }
    };

    let tracker = state.tracker.lock().await;
    let provider_name = tracker
        .get_usage(&key)
        .map(|u| u.provider.clone())
        .unwrap_or_default();
    drop(tracker);

    let provider = match get_provider(&provider_name) {
        Some(p) => p.clone(),
        None => {
            // Update status to unknown — no provider to verify against
            drop(vault);
            return (
                StatusCode::OK,
                Json(VerifyResult {
                    ok: false,
                    key,
                    status: "unknown".into(),
                    message: "No provider configured — cannot verify".into(),
                }),
            );
        }
    };

    let verify_path = match &provider.verify_path {
        Some(p) => p.clone(),
        None => {
            drop(vault);
            return (
                StatusCode::OK,
                Json(VerifyResult {
                    ok: false,
                    key,
                    status: "unknown".into(),
                    message: format!(
                        "No verify endpoint for {}",
                        provider.display_name
                    ),
                }),
            );
        }
    };

    let base_url = match &provider.base_url {
        Some(u) => u.clone(),
        None => {
            drop(vault);
            return (
                StatusCode::OK,
                Json(VerifyResult {
                    ok: false,
                    key,
                    status: "unknown".into(),
                    message: "No base URL configured".into(),
                }),
            );
        }
    };

    let url = format!("{}{}", base_url, verify_path);
    let value = secret.value.clone();
    drop(vault);

    // Build request with auth
    let client = &state.http_client;
    let mut request = client.get(&url);

    if let Some(ref auth_method) = provider.auth_method {
        match auth_method {
            AuthMethod::BearerToken => {
                request = request.bearer_auth(&value);
            }
            AuthMethod::CustomHeader { header_name } => {
                request = request.header(header_name.as_str(), &value);
            }
            AuthMethod::BasicAuth => {
                request = request.basic_auth(&value, Option::<&str>::None);
            }
            AuthMethod::QueryParam { param_name } => {
                request = request.query(&[(param_name.as_str(), value.as_str())]);
            }
        }
    }

    // Provider-specific headers
    if provider_name == "anthropic" {
        request = request.header("anthropic-version", "2023-06-01");
    }

    let result = request.send().await;

    let (new_status, message) = match result {
        Ok(resp) => {
            let status_code = resp.status();
            let code = status_code.as_u16();
            if status_code.is_success() {
                ("active".to_string(), format!("{} — key is valid", status_code))
            } else if code == 401 || code == 403 {
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                // Some APIs return 401/403 for restricted keys that are actually valid
                // e.g. Resend send-only key can't access /api-keys but IS valid
                if body_lower.contains("restricted") || body_lower.contains("insufficient_permissions")
                    || body_lower.contains("scope") {
                    (
                        "active".to_string(),
                        format!("{} — key is valid (restricted scope)", status_code),
                    )
                } else {
                    (
                        "error".to_string(),
                        format!("{} — key is invalid or expired: {}", status_code, &body[..body.len().min(200)]),
                    )
                }
            } else if code == 400 {
                // 400 = request malformed but auth passed → key is valid
                ("active".to_string(), format!("{} — key is valid (auth passed)", status_code))
            } else if code >= 500 {
                ("unknown".to_string(), format!("{} — server error, try later", status_code))
            } else {
                let body = resp.text().await.unwrap_or_default();
                (
                    "active".to_string(),
                    format!("{} — key accepted ({})", status_code, &body[..body.len().min(100)]),
                )
            }
        }
        Err(e) => (
            "error".to_string(),
            format!("Connection failed: {}", e),
        ),
    };

    // Update vault with verification result
    let mut vault = state.vault.lock().await;
    if let Some(s) = vault.secrets.get_mut(&key) {
        s.key_status = new_status.clone();
        s.last_verified = Some(Local::now().to_rfc3339());
        if new_status == "error" {
            s.last_error = Some(message.clone());
        } else {
            s.last_error = None;
        }
        let _ = save_vault(&vault);
    }

    log_access("verify", &key, "", "web");

    let ok = new_status == "active";
    (
        StatusCode::OK,
        Json(VerifyResult {
            ok,
            key,
            status: new_status,
            message,
        }),
    )
}

// --- WebSocket handler ---

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.reload_tx.subscribe();

    loop {
        tokio::select! {
            Ok(msg) = rx.recv() => {
                if socket.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

// --- Server startup ---

/// Health check endpoint for Cloud Run / load balancers.
async fn health_check() -> &'static str {
    "ok"
}

pub async fn start_web(port: u16) -> anyhow::Result<()> {
    // Use VaultHolder: gracefully handles missing vault (returns empty data)
    let mut holder = VaultHolder::new();
    let vault_data = holder.get().cloned().unwrap_or_default();

    let (reload_tx, _) = broadcast::channel::<String>(16);
    let sessions = auth::new_sessions();

    let state = Arc::new(AppState {
        vault: Mutex::new(vault_data),
        tracker: Mutex::new(UsageTracker::new()),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
        reload_tx: reload_tx.clone(),
    });

    // File watcher for vault.enc — only when vault exists on disk
    let _watcher: Option<RecommendedWatcher> = if vault_exists() {
        let watcher_state = state.clone();
        let vault_path = vault_file();
        let watch_dir = vault_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Vault path has no parent"))?
            .to_path_buf();
        let vault_filename = vault_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<()>(100);

        let watcher = {
            let event_tx = event_tx.clone();
            let vault_filename = vault_filename.clone();
            let mut w = RecommendedWatcher::new(
                move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        match event.kind {
                            EventKind::Modify(_) | EventKind::Create(_) => {
                                let is_vault = event.paths.iter().any(|p| {
                                    p.file_name()
                                        .map(|f| f.to_string_lossy() == vault_filename)
                                        .unwrap_or(false)
                                });
                                if is_vault {
                                    let _ = event_tx.blocking_send(());
                                }
                            }
                            _ => {}
                        }
                    }
                },
                Config::default(),
            )?;
            w.watch(&watch_dir, RecursiveMode::NonRecursive)?;
            w
        };

        let reload_tx = reload_tx.clone();
        tokio::spawn(async move {
            let mut pending = false;
            loop {
                tokio::select! {
                    Some(()) = event_rx.recv() => {
                        pending = true;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)), if pending => {
                        pending = false;
                        match open_vault() {
                            Ok(new_data) => {
                                let count = new_data.secrets.len();
                                let mut vault = watcher_state.vault.lock().await;
                                *vault = new_data;
                                drop(vault);
                                let msg = serde_json::json!({
                                    "type": "vault_reload",
                                    "timestamp": chrono::Utc::now().to_rfc3339(),
                                    "entry_count": count,
                                });
                                let _ = reload_tx.send(msg.to_string());
                                tracing::info!("[watcher] Vault reloaded: {} entries", count);
                            }
                            Err(e) => {
                                tracing::warn!("[watcher] Failed to reload vault: {}", e);
                            }
                        }
                    }
                    else => {
                        if event_rx.recv().await.is_some() {
                            pending = true;
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        Some(watcher)
    } else {
        tracing::info!("No local vault — file watcher disabled (Cloud Run mode)");
        None
    };

    let app = Router::new()
        // Health check (public, outside auth middleware)
        .route("/health", get(health_check))
        // Auth routes (public)
        .route("/login", get(login_page_handler))
        .route(
            "/api/auth/login",
            post(auth::login_handler).with_state(sessions.clone()),
        )
        .route(
            "/api/auth/logout",
            post(auth::logout_handler).with_state(sessions.clone()),
        )
        .route(
            "/api/auth/session",
            get(auth::session_handler).with_state(sessions.clone()),
        )
        // Protected routes
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .route("/api/status", get(status_handler))
        .route("/api/secrets", get(list_handler))
        .route("/api/secrets", post(add_handler))
        .route("/api/secrets/{key}", delete(delete_handler))
        .route("/api/secrets/{key}/rotate", put(rotate_handler))
        .route("/api/secrets/{key}/meta", put(update_meta_handler))
        .route("/api/secrets/{key}/verify", post(verify_handler))
        .route("/api/health", get(health_handler))
        .route("/api/search", get(search_handler))
        .layer(middleware::from_fn_with_state(
            sessions.clone(),
            auth::auth_middleware,
        ))
        .with_state(state);

    // Bind to 0.0.0.0 for Cloud Run compatibility (also works locally)
    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("PQVault Web UI: http://localhost:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// HTML loaded from separate static files at compile time
const DASHBOARD_HTML: &str = include_str!("../static/index.html");
const LOGIN_HTML: &str = include_str!("../static/login.html");
