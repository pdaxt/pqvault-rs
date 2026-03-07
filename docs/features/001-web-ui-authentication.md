# Feature 001: Web UI Authentication

## Status: Planned
## Phase: 1 (v2.1)
## Priority: Critical

## Problem

The web dashboard at `localhost:3000` has zero authentication. Anyone with network access to the machine can browse, view, copy, and delete every secret in the vault. This is unacceptable for any secrets manager — even one running locally. Shared workstations, malicious local software, or accidental port-forwarding could expose every stored credential.

## Solution

Add TOTP-based (Time-based One-Time Password) login to the web dashboard. The user sets up a TOTP secret via CLI (`pqvault web --setup-auth`), scans it with any authenticator app (Google Authenticator, Authy, 1Password), and must enter a 6-digit code to access the dashboard. Sessions are maintained via HMAC-signed cookies with a configurable TTL (default 24 hours).

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/src/auth.rs` — TOTP verification, session creation, session middleware, HMAC signing
- `crates/pqvault-web/src/lib.rs` — Wire auth middleware into Axum router
- `crates/pqvault-web/static/login.html` — Login page with TOTP code input
- `crates/pqvault-cli/src/main.rs` — Add `web --setup-auth` subcommand
- `crates/pqvault-core/src/models.rs` — Add `auth_config` to VaultMetadata

### Data Model Changes

```rust
/// Stored in VaultMetadata
#[derive(Serialize, Deserialize, Clone)]
pub struct WebAuthConfig {
    /// TOTP secret (base32-encoded), encrypted at rest with vault master key
    pub totp_secret: String,
    /// HMAC signing key for session cookies (32 bytes, hex-encoded)
    pub session_signing_key: String,
    /// Session TTL in seconds (default: 86400 = 24h)
    pub session_ttl_seconds: u64,
    /// Whether auth is enabled (false = legacy open mode)
    pub enabled: bool,
}

/// Session token stored in signed cookie
#[derive(Serialize, Deserialize)]
pub struct SessionToken {
    /// Random session ID
    pub session_id: String,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Expiry timestamp (Unix epoch seconds)
    pub expires_at: u64,
}
```

Add to `VaultMetadata`:
```rust
pub struct VaultMetadata {
    // ... existing fields ...
    pub auth_config: Option<WebAuthConfig>,
}
```

### MCP Tools

Not directly applicable — authentication is a web-only concern. However, the `vault_status` MCP tool should report whether web auth is enabled:

```rust
// In vault_status response:
{
    "web_auth_enabled": true,
    "web_auth_configured": true
}
```

### CLI Commands

**Setup TOTP authentication:**
```bash
# Interactive setup — generates TOTP secret, shows QR code URL
pqvault web --setup-auth

# Output:
# Web UI authentication setup
# Scan this QR code with your authenticator app:
# otpauth://totp/PQVault:user@localhost?secret=JBSWY3DPEHPK3PXP&issuer=PQVault
#
# Or enter this secret manually: JBSWY3DPEHPK3PXP
#
# Enter the 6-digit code from your app to verify: 123456
# ✓ Authentication configured successfully
# Web dashboard now requires TOTP login
```

**Disable authentication:**
```bash
pqvault web --disable-auth
# Requires entering a valid TOTP code to confirm
```

**Regenerate session signing key (invalidates all sessions):**
```bash
pqvault web --rotate-sessions
```

### Web UI Changes

**New page: `/login`**
- Clean, minimal login form with single 6-digit code input
- Auto-focus on input, auto-submit when 6 digits entered
- Error message for invalid codes with rate limiting (max 5 attempts per minute)
- Redirect to `/` on success

**Modified: All existing routes**
- Axum middleware checks for valid session cookie before serving any page
- If no valid session, redirect to `/login`
- Session cookie: `pqvault_session`, HttpOnly, SameSite=Strict, Secure (if HTTPS)

**New endpoint: `POST /api/auth/login`**
```rust
// Request
{ "code": "123456" }

// Success response (sets cookie)
{ "success": true, "expires_at": 1700000000 }

// Failure response
{ "success": false, "error": "Invalid code", "attempts_remaining": 4 }
```

**New endpoint: `POST /api/auth/logout`**
```rust
// Clears session cookie
{ "success": true }
```

### Auth Middleware Implementation

```rust
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Skip auth for login page and login API
    let path = req.uri().path();
    if path == "/login" || path == "/api/auth/login" || path.starts_with("/static/") {
        return next.run(req).await;
    }

    // Check if auth is configured
    let vault = state.vault.read().await;
    let auth_config = match &vault.metadata.auth_config {
        Some(config) if config.enabled => config,
        _ => return next.run(req).await, // No auth configured, allow access
    };

    // Extract and verify session cookie
    let cookie = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_session_cookie(cookies));

    match cookie {
        Some(token) if verify_session(&token, &auth_config.session_signing_key) => {
            next.run(req).await
        }
        _ => Redirect::to("/login").into_response(),
    }
}

fn verify_session(token: &str, signing_key: &str) -> bool {
    // Split token into payload.signature
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }

    let (signature, payload) = (parts[0], parts[1]);

    // Verify HMAC
    let key_bytes = hex::decode(signing_key).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(&key_bytes).expect("HMAC key");
    mac.update(payload.as_bytes());

    let expected = hex::decode(signature).unwrap_or_default();
    if mac.verify_slice(&expected).is_err() {
        return false;
    }

    // Check expiry
    let session: SessionToken = match serde_json::from_str(payload) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    session.expires_at > now
}
```

### TOTP Verification

```rust
use totp_rs::{Algorithm, TOTP, Secret};

pub fn verify_totp(secret_base32: &str, code: &str) -> bool {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,       // digits
        1,       // skew (allows 1 period before/after)
        30,      // period in seconds
        Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .expect("valid base32"),
    )
    .expect("valid TOTP config");

    totp.check_current(code).unwrap_or(false)
}

pub fn generate_totp_secret() -> String {
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

pub fn get_totp_url(secret_base32: &str) -> String {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6, 1, 30,
        Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .expect("valid base32"),
    )
    .expect("valid TOTP config");

    totp.get_url("user@localhost", "PQVault")
}
```

## Dependencies

- `totp-rs = "5"` — TOTP generation and verification (RFC 6238)
- `hmac = "0.12"` — HMAC-SHA256 for session cookie signing
- `sha2 = "0.10"` — SHA-256 digest for HMAC
- `hex = "0.4"` — Hex encoding for keys and signatures
- `rand = "0.8"` — Random session IDs and signing key generation
- Requires Feature 009 (Separate Web UI Files) for login.html

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_roundtrip() {
        let secret = generate_totp_secret();
        let totp = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            Secret::Encoded(secret.clone()).to_bytes().unwrap(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp(&secret, &code));
    }

    #[test]
    fn test_invalid_totp_code() {
        let secret = generate_totp_secret();
        assert!(!verify_totp(&secret, "000000"));
    }

    #[test]
    fn test_session_token_signing() {
        let signing_key = hex::encode(rand::random::<[u8; 32]>());
        let session = SessionToken {
            session_id: "test-123".into(),
            created_at: now(),
            expires_at: now() + 86400,
        };
        let token = sign_session(&session, &signing_key);
        assert!(verify_session(&token, &signing_key));
    }

    #[test]
    fn test_expired_session_rejected() {
        let signing_key = hex::encode(rand::random::<[u8; 32]>());
        let session = SessionToken {
            session_id: "test-456".into(),
            created_at: now() - 86401,
            expires_at: now() - 1, // Already expired
        };
        let token = sign_session(&session, &signing_key);
        assert!(!verify_session(&token, &signing_key));
    }

    #[test]
    fn test_tampered_session_rejected() {
        let signing_key = hex::encode(rand::random::<[u8; 32]>());
        let session = SessionToken {
            session_id: "test-789".into(),
            created_at: now(),
            expires_at: now() + 86400,
        };
        let token = sign_session(&session, &signing_key);
        let tampered = token.replace("test-789", "test-HACKED");
        assert!(!verify_session(&tampered, &signing_key));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_unauthenticated_redirects_to_login() {
    let app = create_test_app_with_auth().await;
    let response = app.get("/").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

#[tokio::test]
async fn test_login_page_accessible_without_auth() {
    let app = create_test_app_with_auth().await;
    let response = app.get("/login").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_valid_totp_sets_session_cookie() {
    let app = create_test_app_with_auth().await;
    let code = generate_current_code(&app.totp_secret);
    let response = app.post("/api/auth/login")
        .json(&json!({ "code": code }))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_some());
}

#[tokio::test]
async fn test_rate_limiting_on_failed_attempts() {
    let app = create_test_app_with_auth().await;
    for _ in 0..5 {
        app.post("/api/auth/login")
            .json(&json!({ "code": "000000" }))
            .await;
    }
    let response = app.post("/api/auth/login")
        .json(&json!({ "code": "000000" }))
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
```

### Manual Verification

1. Run `pqvault web --setup-auth`, scan QR code with authenticator app
2. Open `http://localhost:3000` — should redirect to `/login`
3. Enter valid TOTP code — should redirect to dashboard
4. Close browser, reopen — session cookie should persist (within 24h)
5. Wait for session expiry or run `--rotate-sessions` — should require re-login

## Example Usage

```bash
# First-time setup
$ pqvault web --setup-auth
Web UI authentication setup
Scan this QR code with your authenticator app:
otpauth://totp/PQVault:user@localhost?secret=JBSWY3DPEHPK3PXP&issuer=PQVault

Or enter this secret manually: JBSWY3DPEHPK3PXP

Enter the 6-digit code from your app to verify: 847293
Authentication configured successfully.
Web dashboard now requires TOTP login.

# Start web server
$ pqvault web
PQVault dashboard: http://localhost:3000
Authentication: enabled (TOTP)

# In browser: navigate to localhost:3000
# -> Redirected to /login
# -> Enter TOTP code
# -> Dashboard loads with 24h session

# Disable auth (requires valid TOTP to confirm)
$ pqvault web --disable-auth
Enter TOTP code to confirm: 193847
Authentication disabled. Dashboard is now open.
```
