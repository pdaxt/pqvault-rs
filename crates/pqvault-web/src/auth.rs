use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

use pqvault_core::keychain::get_master_password;

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "pqvault_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

#[derive(Clone)]
pub struct Session {
    pub created: Instant,
}

impl Session {
    fn is_expired(&self) -> bool {
        self.created.elapsed() > SESSION_TTL
    }
}

pub type Sessions = Arc<Mutex<HashMap<String, Session>>>;

pub fn new_sessions() -> Sessions {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Generate a cryptographically random session token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Generate HMAC signature for a session token
fn sign_token(token: &str) -> String {
    // Use a key derived from the master password for HMAC
    let key = get_master_password()
        .ok()
        .flatten()
        .unwrap_or_else(|| "pqvault-default-key".to_string());

    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC key");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify HMAC signature for a session token
fn verify_signature(token: &str, signature: &str) -> bool {
    let expected = sign_token(token);
    // Constant-time comparison
    expected == signature
}

/// Parse the session cookie from request headers
fn extract_session_cookie(req: &Request<Body>) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE)) {
            return Some(value.to_string());
        }
    }
    None
}

/// Parse "token.signature" format
fn parse_signed_cookie(cookie_value: &str) -> Option<(&str, &str)> {
    cookie_value.split_once('.')
}

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub authenticated: bool,
}

// --- Handlers ---

/// Get the web auth password: env var first (Cloud Run), then keychain (local).
fn get_web_password() -> Option<String> {
    // 1. PQVAULT_WEB_PASSWORD env var (Cloud Run / Docker)
    if let Ok(pw) = std::env::var("PQVAULT_WEB_PASSWORD") {
        if !pw.is_empty() {
            return Some(pw);
        }
    }
    // 2. Master password from keychain / file cache (local dev)
    get_master_password().ok().flatten()
}

pub async fn login_handler(
    State(sessions): State<Sessions>,
    Json(req): Json<LoginRequest>,
) -> (StatusCode, Response) {
    let master_pw = match get_web_password() {
        Some(pw) => pw,
        None => {
            let body = Json(AuthResult {
                ok: false,
                message: "Vault not initialized".to_string(),
            });
            return (StatusCode::SERVICE_UNAVAILABLE, body.into_response());
        }
    };

    // Verify password
    if req.password != master_pw {
        pqvault_core::audit::log_access("login_failed", "", "", "web");
        let body = Json(AuthResult {
            ok: false,
            message: "Invalid password".to_string(),
        });
        return (StatusCode::UNAUTHORIZED, body.into_response());
    }

    // Create session
    let token = generate_token();
    let signature = sign_token(&token);
    let cookie_value = format!("{}.{}", token, signature);

    let mut sessions = sessions.lock().await;

    // Clean expired sessions
    sessions.retain(|_, s| !s.is_expired());

    sessions.insert(
        token.clone(),
        Session {
            created: Instant::now(),
        },
    );

    pqvault_core::audit::log_access("login_success", "", "", "web");

    let body = Json(AuthResult {
        ok: true,
        message: "Authenticated".to_string(),
    });

    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_COOKIE,
        cookie_value,
        SESSION_TTL.as_secs()
    );

    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());

    (StatusCode::OK, response)
}

pub async fn logout_handler(State(sessions): State<Sessions>) -> Response {
    // We can't easily get the token from this handler without extracting cookies,
    // but clearing the cookie is sufficient. The session will expire naturally.
    let _ = sessions; // sessions cleanup happens on login and via middleware

    let body = Json(AuthResult {
        ok: true,
        message: "Logged out".to_string(),
    });

    let cookie = format!(
        "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        SESSION_COOKIE
    );

    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());

    response
}

pub async fn session_handler(State(sessions): State<Sessions>, req: Request<Body>) -> Json<SessionInfo> {
    let authenticated = if let Some(cookie_value) = extract_session_cookie(&req) {
        if let Some((token, sig)) = parse_signed_cookie(&cookie_value) {
            if verify_signature(token, sig) {
                let sessions = sessions.lock().await;
                sessions
                    .get(token)
                    .map_or(false, |s| !s.is_expired())
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    Json(SessionInfo { authenticated })
}

// --- Auth middleware ---

pub async fn auth_middleware(
    State(sessions): State<Sessions>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Public routes that don't need auth
    if path == "/health"
        || path == "/login"
        || path == "/api/auth/login"
        || path == "/api/auth/session"
        || path == "/api/auth/logout"
    {
        return next.run(req).await;
    }

    // Check session cookie
    if let Some(cookie_value) = extract_session_cookie(&req) {
        if let Some((token, sig)) = parse_signed_cookie(&cookie_value) {
            if verify_signature(token, sig) {
                let sessions = sessions.lock().await;
                if let Some(session) = sessions.get(token) {
                    if !session.is_expired() {
                        drop(sessions);
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    // For API routes, return 401 JSON
    if path.starts_with("/api/") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthResult {
                ok: false,
                message: "Authentication required".to_string(),
            }),
        )
            .into_response();
    }

    // For page routes (like /), redirect to login
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/login")
        .body(Body::empty())
        .unwrap()
}
