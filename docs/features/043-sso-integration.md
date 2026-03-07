# Feature 043: SSO Integration

## Status: Done
## Phase: 5 (v2.5)
## Priority: High

## Problem

The web UI currently has no authentication mechanism beyond TOTP (Feature 1 scope). There is no way to integrate with existing corporate identity providers. Each user must manage a separate password for PQVault, which is both a security risk (password reuse) and an operational burden (password resets, onboarding). Enterprise users expect Single Sign-On through their existing Google Workspace, GitHub, or OIDC-compatible identity provider.

## Solution

Implement OpenID Connect (OIDC) integration supporting Google, GitHub, and any OIDC-compliant identity provider. The web UI redirects unauthenticated users to the configured IdP, receives an ID token on callback, and creates or matches a PQVault user account. Session management uses signed JWT tokens stored as httpOnly cookies. Auto-provisioning creates new PQVault users on first login with a configurable default role.

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/src/sso.rs` — OIDC flow handler (authorize, callback, token validation)
- `crates/pqvault-web/src/session.rs` — JWT session management
- `crates/pqvault-web/src/routes.rs` — Add `/auth/login`, `/auth/callback`, `/auth/logout` routes
- `crates/pqvault-team-mcp/src/sso_config.rs` — SSO provider configuration
- `crates/pqvault-core/src/config.rs` — SSO configuration storage

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SSO provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProvider {
    pub id: String,
    pub name: String,               // "google", "github", "custom"
    pub client_id: String,
    pub client_secret: String,       // Encrypted in vault
    pub issuer_url: String,          // OIDC discovery URL
    pub scopes: Vec<String>,
    pub auto_provision: bool,        // Create user on first login
    pub default_role: String,        // Role for auto-provisioned users
    pub allowed_domains: Vec<String>, // e.g., ["company.com"]
    pub enabled: bool,
}

/// OIDC token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    pub sub: String,          // Subject identifier
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
}

/// Session token (JWT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub workspace_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub sso_provider: Option<String>,
}

/// SSO state parameter (CSRF protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub nonce: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
}

impl SsoProvider {
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            id: "google".into(),
            name: "Google".into(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            issuer_url: "https://accounts.google.com".into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            auto_provision: true,
            default_role: "developer".into(),
            allowed_domains: vec![],
            enabled: true,
        }
    }

    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self {
            id: "github".into(),
            name: "GitHub".into(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            issuer_url: "https://github.com".into(),
            scopes: vec!["read:user".into(), "user:email".into()],
            auto_provision: true,
            default_role: "developer".into(),
            allowed_domains: vec![],
            enabled: true,
        }
    }
}
```

### HTTP Handlers

```rust
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};

/// GET /auth/login — Redirect to IdP
pub async fn login_handler(
    State(state): State<AppState>,
    Query(params): Query<LoginParams>,
) -> impl IntoResponse {
    let provider = state.sso.get_provider(&params.provider).await?;
    let (auth_url, state_param) = build_auth_url(&provider, &state.config.callback_url);
    state.auth_states.insert(state_param.nonce.clone(), state_param).await;
    Redirect::temporary(&auth_url)
}

/// GET /auth/callback — Handle IdP callback
pub async fn callback_handler(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // 1. Verify state parameter (CSRF)
    let auth_state = state.auth_states.remove(&params.state).await
        .ok_or("Invalid state parameter")?;

    // 2. Exchange code for tokens
    let tokens = exchange_code(&state.sso_provider, &params.code).await?;

    // 3. Validate ID token
    let claims = validate_id_token(&tokens.id_token, &state.sso_provider).await?;

    // 4. Check domain allowlist
    if !state.sso_provider.allowed_domains.is_empty() {
        let domain = claims.email.as_deref()
            .and_then(|e| e.split('@').nth(1))
            .ok_or("No email domain")?;
        if !state.sso_provider.allowed_domains.contains(&domain.to_string()) {
            return Err("Domain not allowed");
        }
    }

    // 5. Find or create user
    let user = state.users.find_or_create_sso(&claims, &state.sso_provider).await?;

    // 6. Issue session JWT
    let session = SessionToken::new(&user, Duration::from_secs(86400));
    let jwt = encode_jwt(&session, &state.jwt_secret)?;

    // 7. Set cookie and redirect
    let cookie = format!("pqvault_session={}; HttpOnly; Secure; SameSite=Lax; Path=/", jwt);
    Ok(([(SET_COOKIE, cookie)], Redirect::to("/dashboard")))
}

/// POST /auth/logout — Clear session
pub async fn logout_handler() -> impl IntoResponse {
    let cookie = "pqvault_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    ([(SET_COOKIE, cookie)], Redirect::to("/auth/login"))
}
```

### MCP Tools

```rust
/// Configure SSO provider
#[tool(name = "sso_configure")]
async fn sso_configure(
    &self,
    #[arg(description = "Provider: google, github, or custom")] provider: String,
    #[arg(description = "OAuth client ID")] client_id: String,
    #[arg(description = "OAuth client secret")] client_secret: String,
    #[arg(description = "Allowed email domains (comma-separated)")] allowed_domains: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List configured SSO providers
#[tool(name = "sso_list")]
async fn sso_list(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Disable SSO provider
#[tool(name = "sso_disable")]
async fn sso_disable(
    &self,
    #[arg(description = "Provider ID")] provider: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Configure Google SSO
pqvault sso configure google \
  --client-id "123456.apps.googleusercontent.com" \
  --client-secret "GOCSPX-..." \
  --allowed-domains "company.com"

# Configure GitHub SSO
pqvault sso configure github \
  --client-id "Iv1.abc123" \
  --client-secret "ghp_..."

# List SSO providers
pqvault sso list

# Set default role for auto-provisioned users
pqvault sso set-default-role google --role viewer

# Disable a provider
pqvault sso disable github
```

### Web UI Changes

- SSO login buttons on login page ("Sign in with Google", "Sign in with GitHub")
- SSO provider configuration in admin settings
- User profile showing SSO provider linkage
- Session management page showing active sessions

## Dependencies

- `openidconnect = "3"` — OIDC client library (new dependency)
- `jsonwebtoken = "9"` — JWT encoding/decoding (new dependency)
- `reqwest = "0.12"` (existing) — HTTP client for token exchange
- `axum = "0.8"` (existing) — HTTP routing
- Feature 041 (RBAC) — User model and role system

## Testing

### Unit Tests

```rust
#[test]
fn session_token_expiry() {
    let token = SessionToken::new_test("user1", "admin", Duration::from_secs(3600));
    assert!(!token.is_expired());

    let expired = SessionToken {
        expires_at: (Utc::now() - chrono::Duration::hours(1)).timestamp(),
        ..token
    };
    assert!(expired.is_expired());
}

#[test]
fn domain_allowlist_validation() {
    let provider = SsoProvider {
        allowed_domains: vec!["company.com".into()],
        ..SsoProvider::google("id", "secret")
    };
    assert!(is_domain_allowed("user@company.com", &provider));
    assert!(!is_domain_allowed("user@other.com", &provider));
}

#[test]
fn empty_allowlist_allows_all() {
    let provider = SsoProvider {
        allowed_domains: vec![],
        ..SsoProvider::google("id", "secret")
    };
    assert!(is_domain_allowed("user@anywhere.com", &provider));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn login_redirects_to_google() {
    let app = test_app_with_sso().await;
    let response = app.client
        .get(&format!("http://{}/auth/login?provider=google", app.addr))
        .send().await.unwrap();

    assert_eq!(response.status(), 307);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://accounts.google.com"));
}

#[tokio::test]
async fn logout_clears_session() {
    let app = test_app_with_sso().await;
    let response = app.client
        .post(&format!("http://{}/auth/logout", app.addr))
        .send().await.unwrap();

    let cookie = response.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("Max-Age=0"));
}
```

### Manual Verification

1. Configure Google SSO with valid OAuth credentials
2. Navigate to login page, click "Sign in with Google"
3. Complete Google OAuth flow
4. Verify redirect back to dashboard with session cookie
5. Verify user was auto-provisioned with correct role
6. Logout and verify session is cleared

## Example Usage

```bash
# Setup SSO for a team:
pqvault sso configure google \
  --client-id "123456.apps.googleusercontent.com" \
  --client-secret "$(pqvault get GOOGLE_OAUTH_SECRET)" \
  --allowed-domains "dataxlr8.com" \
  --default-role developer

# Users visit https://vault.dataxlr8.com/auth/login
# Click "Sign in with Google"
# Redirected to Google → consent → callback → dashboard
# First-time users auto-created as "developer" role
```
