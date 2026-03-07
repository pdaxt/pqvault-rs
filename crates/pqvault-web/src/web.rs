use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use pqvault_core::audit::log_access;
use pqvault_core::health::check_health;
use pqvault_core::models::{auto_categorize, mask_value, SecretEntry};
use pqvault_core::providers::{get_provider, AuthMethod};
use pqvault_core::smart::UsageTracker;
use pqvault_core::vault::{meta_file, open_vault, save_vault};

struct AppState {
    vault: Mutex<pqvault_core::models::VaultData>,
    tracker: Mutex<UsageTracker>,
    http_client: reqwest::Client,
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
    }
}

// --- Handlers ---

async fn index_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
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

// --- Server startup ---

pub async fn start_web(port: u16) -> anyhow::Result<()> {
    let vault_data = open_vault()?;

    let state = Arc::new(AppState {
        vault: Mutex::new(vault_data),
        tracker: Mutex::new(UsageTracker::new()),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
    });

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        .route("/api/secrets", get(list_handler))
        .route("/api/secrets", post(add_handler))
        .route("/api/secrets/{key}", delete(delete_handler))
        .route("/api/secrets/{key}/rotate", put(rotate_handler))
        .route("/api/secrets/{key}/meta", put(update_meta_handler))
        .route("/api/secrets/{key}/verify", post(verify_handler))
        .route("/api/health", get(health_handler))
        .route("/api/search", get(search_handler))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    eprintln!("PQVault Web UI: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// --- Embedded HTML ---

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQVault</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#08080d;--surface:#111118;--card:#16161f;--border:#1e1e2a;
  --text:#e4e4e7;--muted:#71717a;--accent:#7c3aed;--accent2:#a78bfa;
  --green:#22c55e;--yellow:#eab308;--red:#ef4444;--blue:#3b82f6;
  --radius:8px;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,monospace;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent2);text-decoration:none}

/* Header */
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:18px;font-weight:700;letter-spacing:-.5px}
.header h1 span{color:var(--accent);font-weight:300}
.hdr-right{display:flex;gap:8px;align-items:center}
.badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.3px}
.badge-green{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.2)}
.badge-red{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.badge-purple{background:rgba(124,58,237,.12);color:var(--accent2);border:1px solid rgba(124,58,237,.2)}
.badge-blue{background:rgba(59,130,246,.12);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.badge-yellow{background:rgba(234,179,8,.12);color:var(--yellow);border:1px solid rgba(234,179,8,.2)}

/* Layout */
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:200px;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;padding:12px 0}
.main{flex:1;overflow-y:auto;padding:16px 20px}

/* Sidebar */
.sb-section{padding:0 12px;margin-bottom:16px}
.sb-title{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:6px;padding:0 4px}
.sb-item{display:flex;justify-content:space-between;align-items:center;padding:5px 8px;border-radius:6px;cursor:pointer;font-size:12px;color:var(--muted);transition:all .15s}
.sb-item:hover{background:var(--card);color:var(--text)}
.sb-item.active{background:rgba(124,58,237,.12);color:var(--accent2)}
.sb-item .count{font-size:11px;opacity:.6}
.sb-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.dot-green{background:var(--green)}
.dot-red{background:var(--red)}
.dot-gray{background:var(--muted)}

/* Controls */
.controls{display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.search-box{flex:1;min-width:200px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:8px 12px;color:var(--text);font-size:13px;outline:none;transition:border-color .2s}
.search-box:focus{border-color:var(--accent)}
.search-box::placeholder{color:var(--muted)}
.btn{padding:6px 14px;border-radius:var(--radius);font-size:12px;font-weight:600;cursor:pointer;border:none;transition:all .15s;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#6d28d9}
.btn-sm{padding:3px 8px;font-size:11px}
.btn-danger{background:transparent;color:var(--red);border:1px solid rgba(239,68,68,.3)}
.btn-danger:hover{background:rgba(239,68,68,.1)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--muted)}
.btn-verify{background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.btn-verify:hover{background:rgba(59,130,246,.2)}

/* Provider Groups */
.prov-group{margin-bottom:12px}
.prov-header{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;user-select:none}
.prov-header:hover{border-color:var(--accent)}
.prov-header .arrow{color:var(--muted);font-size:10px;transition:transform .2s}
.prov-header.collapsed .arrow{transform:rotate(-90deg)}
.prov-header .prov-name{font-size:13px;font-weight:600;flex:1}
.prov-header .prov-count{font-size:11px;color:var(--muted)}
.prov-body{border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);overflow:hidden}
.prov-header.collapsed+.prov-body{display:none}

/* Table */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:6px 10px;color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);background:var(--card)}
td{padding:7px 10px;border-bottom:1px solid rgba(30,30,42,.5);vertical-align:middle}
tr:hover td{background:rgba(124,58,237,.04)}
.mono{font-family:monospace;font-size:11px}
.mask{color:var(--muted);font-family:monospace;font-size:11px;letter-spacing:-.5px}
.env-badge{font-size:9px;padding:2px 6px;border-radius:10px;text-transform:uppercase;font-weight:600;letter-spacing:.5px}
.env-prod{background:rgba(239,68,68,.12);color:var(--red)}
.env-dev{background:rgba(59,130,246,.12);color:var(--blue)}
.env-test{background:rgba(234,179,8,.12);color:var(--yellow)}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.st-active{background:var(--green)}
.st-error{background:var(--red)}
.st-unknown{background:var(--muted)}
.td-actions{display:flex;gap:4px;justify-content:flex-end}
.proj-tags{display:flex;flex-wrap:wrap;gap:2px;max-width:200px}
.proj-tag{font-size:10px;background:rgba(124,58,237,.08);color:var(--accent2);padding:1px 5px;border-radius:3px}
.acct{font-size:11px;color:var(--accent2)}
.key-name{font-weight:600;cursor:pointer}
.key-name:hover{color:var(--accent2)}

/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto}
.modal h2{font-size:16px;margin-bottom:14px}
.modal label{display:block;font-size:11px;color:var(--muted);margin-bottom:3px;margin-top:10px}
.modal input,.modal select,.modal textarea{width:100%;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:8px 10px;color:var(--text);font-size:13px;outline:none;font-family:inherit}
.modal input:focus,.modal select:focus,.modal textarea:focus{border-color:var(--accent)}
.modal textarea{resize:vertical;min-height:50px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}

/* Detail panel */
.detail{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:16px}
.detail h3{font-size:14px;margin-bottom:10px}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.detail-item{font-size:12px}
.detail-item .dl{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px}
.detail-item .dv{margin-top:2px}

/* Toast */
.toast{position:fixed;bottom:20px;right:20px;padding:10px 16px;border-radius:var(--radius);font-size:12px;font-weight:500;z-index:300;animation:slideIn .3s ease,fadeOut .3s ease 2.7s}
.toast-success{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.toast-error{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.toast-info{background:rgba(59,130,246,.15);color:var(--blue);border:1px solid rgba(59,130,246,.3)}
@keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
@keyframes fadeOut{to{opacity:0}}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

.empty{text-align:center;padding:40px;color:var(--muted)}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>

<div class="header">
  <h1>PQ<span>Vault</span></h1>
  <div class="hdr-right">
    <span class="badge badge-purple" id="h-enc">ML-KEM-768</span>
    <span class="badge" id="h-health">...</span>
    <span class="badge badge-blue" id="h-count">...</span>
  </div>
</div>

<div class="layout">
  <div class="sidebar" id="sidebar"></div>
  <div class="main" id="main">
    <div class="controls">
      <input type="search" class="search-box" id="search" placeholder="Search keys, providers, accounts..." autocomplete="off">
      <button class="btn btn-primary" onclick="openAddModal()">+ Add</button>
    </div>
    <div id="content"></div>
  </div>
</div>

<!-- Add Modal -->
<div class="modal-overlay" id="add-modal">
  <div class="modal">
    <h2>Add Secret</h2>
    <label>Key Name</label>
    <input id="add-key" placeholder="MY_API_KEY">
    <label>Value</label>
    <input id="add-value" type="password" placeholder="secret value">
    <label>Category</label>
    <select id="add-cat">
      <option value="">Auto-detect</option>
      <option>ai</option><option>payment</option><option>cloud</option>
      <option>social</option><option>email</option><option>database</option>
      <option>auth</option><option>search</option><option>general</option>
    </select>
    <label>Account</label>
    <input id="add-account" placeholder="pranjal@dataxlr8.com">
    <label>Environment</label>
    <select id="add-env">
      <option value="">—</option>
      <option value="production">Production</option>
      <option value="development">Development</option>
      <option value="test">Test</option>
    </select>
    <label>Description</label>
    <textarea id="add-desc" placeholder="What is this key for?"></textarea>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('add-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="addSecret()">Add</button>
    </div>
  </div>
</div>

<!-- Rotate Modal -->
<div class="modal-overlay" id="rotate-modal">
  <div class="modal">
    <h2>Rotate Secret</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:10px">Key: <strong id="rotate-key-label" style="color:var(--text)"></strong></p>
    <label>New Value</label>
    <input id="rotate-value" type="password" placeholder="new secret value">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('rotate-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="rotateSecret()">Rotate</button>
    </div>
  </div>
</div>

<!-- Delete Modal -->
<div class="modal-overlay" id="delete-modal">
  <div class="modal">
    <h2>Delete Secret</h2>
    <p style="color:var(--muted);font-size:12px">Delete <strong id="delete-key-label" style="color:var(--red)"></strong>? This cannot be undone.</p>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('delete-modal')">Cancel</button>
      <button class="btn btn-danger" onclick="deleteSecret()">Delete</button>
    </div>
  </div>
</div>

<!-- Edit Meta Modal -->
<div class="modal-overlay" id="edit-modal">
  <div class="modal">
    <h2>Edit Key Metadata</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:10px">Key: <strong id="edit-key-label" style="color:var(--text)"></strong></p>
    <label>Account</label>
    <input id="edit-account" placeholder="pranjal@dataxlr8.com">
    <label>Environment</label>
    <select id="edit-env">
      <option value="">—</option>
      <option value="production">Production</option>
      <option value="development">Development</option>
      <option value="test">Test</option>
    </select>
    <label>Description</label>
    <textarea id="edit-desc" placeholder="Description"></textarea>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('edit-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="saveEdit()">Save</button>
    </div>
  </div>
</div>

<script>
let allSecrets = [];
let statusData = {};
let sidebarFilter = {type:'all',value:''};
let rotateKey = '', deleteKey = '', editKey = '';
const collapsed = new Set();

async function load() {
  const [st, sec] = await Promise.all([
    fetch('/api/status').then(r=>r.json()),
    fetch('/api/secrets').then(r=>r.json())
  ]);
  statusData = st;
  allSecrets = sec.secrets;

  document.getElementById('h-enc').textContent = st.pq_algorithm||'ML-KEM-768';
  const hh = document.getElementById('h-health');
  hh.textContent = st.healthy?'HEALTHY':'ISSUES';
  hh.className = 'badge '+(st.healthy?'badge-green':'badge-red');
  document.getElementById('h-count').textContent = st.total_secrets+' secrets';

  renderSidebar();
  renderContent();
}

function renderSidebar() {
  const st = statusData;
  const provs = Object.entries(st.providers||{}).sort((a,b)=>b[1]-a[1]);
  const sc = st.status_counts||{};
  const cats = Object.entries(st.categories||{}).sort((a,b)=>b[1]-a[1]);

  let html = `
    <div class="sb-section">
      <div class="sb-title">View</div>
      <div class="sb-item ${sf('all','')?' active':''}" onclick="setFilter('all','')">
        <span>All Keys</span><span class="count">${st.total_secrets}</span>
      </div>
    </div>
    <div class="sb-section">
      <div class="sb-title">Providers</div>
      ${provs.map(([p,n])=>`
        <div class="sb-item ${sf('provider',p)?' active':''}" onclick="setFilter('provider','${esc(p)}')">
          <span>${esc(p)}</span><span class="count">${n}</span>
        </div>
      `).join('')}
    </div>
    <div class="sb-section">
      <div class="sb-title">Status</div>
      <div class="sb-item ${sf('status','active')?' active':''}" onclick="setFilter('status','active')">
        <span><span class="sb-dot dot-green"></span>Active</span><span class="count">${sc.active||0}</span>
      </div>
      <div class="sb-item ${sf('status','unknown')?' active':''}" onclick="setFilter('status','unknown')">
        <span><span class="sb-dot dot-gray"></span>Unknown</span><span class="count">${sc.unknown||0}</span>
      </div>
      <div class="sb-item ${sf('status','error')?' active':''}" onclick="setFilter('status','error')">
        <span><span class="sb-dot dot-red"></span>Error</span><span class="count">${sc.error||0}</span>
      </div>
    </div>
    <div class="sb-section">
      <div class="sb-title">Categories</div>
      ${cats.map(([c,n])=>`
        <div class="sb-item ${sf('category',c)?' active':''}" onclick="setFilter('category','${esc(c)}')">
          <span>${c}</span><span class="count">${n}</span>
        </div>
      `).join('')}
    </div>`;
  document.getElementById('sidebar').innerHTML = html;
}

function sf(type,value) {
  return sidebarFilter.type===type && sidebarFilter.value===value;
}

function setFilter(type,value) {
  sidebarFilter = {type,value};
  renderSidebar();
  renderContent();
}

function getFiltered() {
  const q = document.getElementById('search').value.toLowerCase();
  let list = allSecrets;

  // Sidebar filter
  const f = sidebarFilter;
  if (f.type==='provider') {
    list = list.filter(s => {
      const pd = s.provider_display || (s.provider ? s.provider : '(none)');
      return pd === f.value;
    });
  } else if (f.type==='status') {
    list = list.filter(s => s.key_status === f.value);
  } else if (f.type==='category') {
    list = list.filter(s => s.category === f.value);
  }

  // Search
  if (q) {
    list = list.filter(s =>
      s.key.toLowerCase().includes(q) ||
      s.category.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      (s.provider_display||'').toLowerCase().includes(q) ||
      (s.account||'').toLowerCase().includes(q) ||
      (s.environment||'').toLowerCase().includes(q) ||
      s.masked_value.toLowerCase().includes(q) ||
      s.projects.some(p => p.toLowerCase().includes(q))
    );
  }

  return list;
}

function renderContent() {
  const filtered = getFiltered();
  if (!filtered.length) {
    document.getElementById('content').innerHTML = '<div class="empty">No secrets match your filter</div>';
    return;
  }

  // Group by provider
  const groups = {};
  for (const s of filtered) {
    const g = s.provider_display || (s.provider || '(No Provider)');
    if (!groups[g]) groups[g] = [];
    groups[g].push(s);
  }

  // Sort groups: named providers first, then (No Provider)
  const sortedGroups = Object.entries(groups).sort((a,b) => {
    if (a[0]==='(No Provider)') return 1;
    if (b[0]==='(No Provider)') return -1;
    return a[0].localeCompare(b[0]);
  });

  let html = '';
  for (const [provName, secrets] of sortedGroups) {
    const isCollapsed = collapsed.has(provName);
    const hasVerifiable = secrets.some(s => s.can_verify);
    html += `
    <div class="prov-group">
      <div class="prov-header ${isCollapsed?'collapsed':''}" onclick="toggleGroup('${esc(provName)}')">
        <span class="arrow">▼</span>
        <span class="prov-name">${esc(provName)}</span>
        <span class="prov-count">${secrets.length} key${secrets.length>1?'s':''}</span>
        ${hasVerifiable?`<button class="btn btn-verify btn-sm" onclick="event.stopPropagation();verifyGroup('${esc(provName)}')">Verify All</button>`:''}
      </div>
      <div class="prov-body">
        <table>
          <tr><th style="width:20px"></th><th>Key</th><th>Masked</th><th>Account</th><th>Env</th><th>Last Used</th><th>Usage</th><th>Rotated</th><th style="width:140px">Actions</th></tr>
          ${secrets.map(s => renderRow(s)).join('')}
        </table>
      </div>
    </div>`;
  }

  document.getElementById('content').innerHTML = html;
}

function renderRow(s) {
  const statusClass = s.key_status==='active'?'st-active':s.key_status==='error'?'st-error':'st-unknown';
  const lastUsed = s.last_used ? timeSince(s.last_used) : '—';
  const envClass = s.environment==='production'?'env-prod':s.environment==='development'?'env-dev':s.environment==='test'?'env-test':'';
  const envLabel = s.environment ? s.environment.slice(0,4) : '—';
  const verified = s.last_verified ? 'Verified '+timeSince(s.last_verified) : '';

  return `<tr>
    <td><span class="status-dot ${statusClass}" title="${s.key_status}${verified?' — '+verified:''}${s.last_error?' — '+esc(s.last_error):''}"></span></td>
    <td>
      <span class="key-name mono" onclick="openEditModal('${esc(s.key)}')" title="Click to edit metadata">${esc(s.key)}</span>
      ${s.projects.length?`<div class="proj-tags">${s.projects.slice(0,3).map(p=>`<span class="proj-tag">${esc(p)}</span>`).join('')}${s.projects.length>3?`<span class="proj-tag">+${s.projects.length-3}</span>`:''}</div>`:''}
    </td>
    <td><span class="mask">${esc(s.masked_value)}</span></td>
    <td>${s.account?`<span class="acct">${esc(s.account)}</span>`:'—'}</td>
    <td>${s.environment?`<span class="env-badge ${envClass}">${envLabel}</span>`:'—'}</td>
    <td style="color:var(--muted)">${lastUsed}</td>
    <td style="color:var(--muted)">${s.usage}</td>
    <td style="color:var(--muted)">${s.rotated}</td>
    <td>
      <div class="td-actions">
        ${s.can_verify?`<button class="btn btn-verify btn-sm" onclick="verifyKey('${esc(s.key)}',this)">Verify</button>`:''}
        <button class="btn btn-ghost btn-sm" onclick="openRotateModal('${esc(s.key)}')">Rotate</button>
        <button class="btn btn-danger btn-sm" onclick="openDeleteModal('${esc(s.key)}')">Del</button>
      </div>
    </td>
  </tr>`;
}

function toggleGroup(name) {
  if (collapsed.has(name)) collapsed.delete(name); else collapsed.add(name);
  renderContent();
}

// Verify
async function verifyKey(key, btn) {
  if (btn) { btn.innerHTML = '<span class="spinner"></span>'; btn.disabled = true; }
  try {
    const res = await fetch(`/api/secrets/${encodeURIComponent(key)}/verify`, {method:'POST'});
    const data = await res.json();
    toast(data.message, data.ok?'success':'error');
    // Update local state
    const s = allSecrets.find(s=>s.key===key);
    if (s) { s.key_status = data.status; }
    // Reload to get updated status counts
    await load();
  } catch(e) {
    toast('Verify failed: '+e.message, 'error');
  }
}

async function verifyGroup(provName) {
  const keys = allSecrets.filter(s => (s.provider_display||(s.provider||'(No Provider)'))===provName && s.can_verify);
  toast(`Verifying ${keys.length} keys...`, 'info');
  for (const s of keys) {
    await verifyKey(s.key, null);
  }
}

function timeSince(iso) {
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (secs < 0) return 'just now';
  if (secs < 60) return 'just now';
  if (secs < 3600) return Math.floor(secs/60)+'m';
  if (secs < 86400) return Math.floor(secs/3600)+'h';
  return Math.floor(secs/86400)+'d';
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

// Modals
function openAddModal() { document.getElementById('add-modal').classList.add('open'); document.getElementById('add-key').focus(); }
function openRotateModal(key) { rotateKey=key; document.getElementById('rotate-key-label').textContent=key; document.getElementById('rotate-modal').classList.add('open'); }
function openDeleteModal(key) { deleteKey=key; document.getElementById('delete-key-label').textContent=key; document.getElementById('delete-modal').classList.add('open'); }
function openEditModal(key) {
  editKey = key;
  const s = allSecrets.find(s=>s.key===key);
  if (!s) return;
  document.getElementById('edit-key-label').textContent = key;
  document.getElementById('edit-account').value = s.account||'';
  document.getElementById('edit-env').value = s.environment||'';
  document.getElementById('edit-desc').value = s.description||'';
  document.getElementById('edit-modal').classList.add('open');
}
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => { if (e.target===el) el.classList.remove('open'); });
});
document.addEventListener('keydown', e => {
  if (e.key==='Escape') document.querySelectorAll('.modal-overlay.open').forEach(el=>el.classList.remove('open'));
});

function toast(msg, type) {
  const t = document.createElement('div');
  t.className = 'toast toast-'+type;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3000);
}

async function addSecret() {
  const key = document.getElementById('add-key').value.trim();
  const value = document.getElementById('add-value').value;
  if (!key||!value) { toast('Key and value required','error'); return; }
  const res = await fetch('/api/secrets', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      key, value,
      category: document.getElementById('add-cat').value||null,
      account: document.getElementById('add-account').value||null,
      environment: document.getElementById('add-env').value||null,
      description: document.getElementById('add-desc').value||null
    })
  });
  const data = await res.json();
  if (data.ok) {
    toast(data.message,'success'); closeModal('add-modal');
    ['add-key','add-value','add-account','add-desc'].forEach(id=>document.getElementById(id).value='');
    load();
  } else toast(data.message,'error');
}

async function rotateSecret() {
  const value = document.getElementById('rotate-value').value;
  if (!value) { toast('Value required','error'); return; }
  const res = await fetch(`/api/secrets/${encodeURIComponent(rotateKey)}/rotate`, {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({new_value:value})
  });
  const data = await res.json();
  if (data.ok) { toast(data.message,'success'); closeModal('rotate-modal'); document.getElementById('rotate-value').value=''; load(); }
  else toast(data.message,'error');
}

async function deleteSecret() {
  const res = await fetch(`/api/secrets/${encodeURIComponent(deleteKey)}`, {method:'DELETE'});
  const data = await res.json();
  if (data.ok) { toast(data.message,'success'); closeModal('delete-modal'); load(); }
  else toast(data.message,'error');
}

async function saveEdit() {
  const res = await fetch(`/api/secrets/${encodeURIComponent(editKey)}/meta`, {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      account: document.getElementById('edit-account').value,
      environment: document.getElementById('edit-env').value,
      description: document.getElementById('edit-desc').value
    })
  });
  const data = await res.json();
  if (data.ok) { toast(data.message,'success'); closeModal('edit-modal'); load(); }
  else toast(data.message,'error');
}

let searchTimer;
document.getElementById('search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(renderContent, 150);
});

load();
</script>
</body>
</html>
"##;
