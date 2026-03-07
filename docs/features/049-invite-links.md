# Feature 049: Invite Links

## Status: Done
## Phase: 5 (v2.5)
## Priority: Low

## Problem

Onboarding new team members involves sharing keys through insecure channels — Slack DMs, email, or sticky notes. Even with PQVault managing secrets, the initial key sharing step often involves plaintext transmission. There is no secure, self-service mechanism for sharing specific keys with new team members that provides both security and convenience.

## Solution

Generate secure one-time invite links that grant access to specific keys. Each link is a URL containing a cryptographically random token. When the recipient visits the link, they authenticate (via SSO or password) and receive access to the specified keys. Links expire after a configurable time (default: 48 hours) and can only be used once. The sender controls which keys and permissions are included.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/invite.rs` — Invite link generation and redemption
- `crates/pqvault-team-mcp/src/lib.rs` — Register invite tools
- `crates/pqvault-web/src/invite_handler.rs` — HTTP handler for invite link redemption
- `crates/pqvault-web/src/routes.rs` — Add `/invite/:token` route

### Data Model Changes

```rust
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Invite link configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteLink {
    pub id: String,
    pub token: String,          // Cryptographically random, URL-safe
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub key_grants: Vec<InviteKeyGrant>,
    pub target_email: Option<String>, // Restrict to specific email
    pub target_role: Option<String>,  // Auto-assign role on accept
    pub workspace_id: Option<String>,
    pub message: Option<String>,      // Message to show recipient
    pub status: InviteStatus,
    pub redeemed_by: Option<String>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub max_uses: u32,
    pub use_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteKeyGrant {
    pub key_name: String,
    pub permission: String,     // "read", "proxy"
    pub duration: Option<Duration>, // None = permanent
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum InviteStatus {
    Active,
    Redeemed,
    Expired,
    Revoked,
}

/// Invite manager
pub struct InviteManager {
    invites: Vec<InviteLink>,
}

impl InviteManager {
    pub fn create_invite(
        &mut self,
        created_by: &str,
        key_grants: Vec<InviteKeyGrant>,
        expiry_hours: u32,
        target_email: Option<String>,
        message: Option<String>,
    ) -> InviteLink {
        let token = generate_secure_token(32); // 256-bit random token
        let invite = InviteLink {
            id: uuid::Uuid::new_v4().to_string(),
            token: token.clone(),
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(expiry_hours as i64),
            key_grants,
            target_email,
            target_role: None,
            workspace_id: None,
            message,
            status: InviteStatus::Active,
            redeemed_by: None,
            redeemed_at: None,
            max_uses: 1,
            use_count: 0,
        };
        self.invites.push(invite.clone());
        invite
    }

    pub fn redeem(
        &mut self,
        token: &str,
        user_id: &str,
        user_email: Option<&str>,
    ) -> Result<Vec<InviteKeyGrant>, String> {
        let invite = self.invites.iter_mut()
            .find(|i| i.token == token)
            .ok_or("Invalid invite link")?;

        if invite.status != InviteStatus::Active {
            return Err("Invite is no longer active".into());
        }

        if Utc::now() > invite.expires_at {
            invite.status = InviteStatus::Expired;
            return Err("Invite has expired".into());
        }

        if invite.use_count >= invite.max_uses {
            return Err("Invite has been fully redeemed".into());
        }

        // Check email restriction
        if let Some(ref target_email) = invite.target_email {
            if user_email != Some(target_email.as_str()) {
                return Err(format!("This invite is for {}", target_email));
            }
        }

        invite.use_count += 1;
        invite.redeemed_by = Some(user_id.to_string());
        invite.redeemed_at = Some(Utc::now());
        if invite.use_count >= invite.max_uses {
            invite.status = InviteStatus::Redeemed;
        }

        Ok(invite.key_grants.clone())
    }

    pub fn revoke(&mut self, invite_id: &str) -> Result<(), String> {
        let invite = self.invites.iter_mut()
            .find(|i| i.id == invite_id && i.status == InviteStatus::Active)
            .ok_or("Invite not found or not active")?;
        invite.status = InviteStatus::Revoked;
        Ok(())
    }
}

fn generate_secure_token(bytes: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token_bytes: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();
    base64_url::encode(&token_bytes)
}
```

### MCP Tools

```rust
/// Create an invite link
#[tool(name = "create_invite")]
async fn create_invite(
    &self,
    #[arg(description = "Keys to share (comma-separated)")] keys: String,
    #[arg(description = "Permission: read, proxy")] permission: Option<String>,
    #[arg(description = "Expiry in hours")] expiry_hours: Option<u32>,
    #[arg(description = "Restrict to specific email")] email: Option<String>,
    #[arg(description = "Message to show recipient")] message: Option<String>,
) -> Result<CallToolResult, McpError> {
    let permission = permission.unwrap_or("read".into());
    let expiry = expiry_hours.unwrap_or(48);
    let key_names: Vec<&str> = keys.split(',').map(|k| k.trim()).collect();

    let grants: Vec<InviteKeyGrant> = key_names.iter().map(|k| InviteKeyGrant {
        key_name: k.to_string(),
        permission: permission.clone(),
        duration: None,
    }).collect();

    let invite = self.invite_mgr.create_invite(
        &self.current_user_id, grants, expiry, email, message,
    );

    let url = format!("{}/invite/{}", self.base_url, invite.token);
    Ok(CallToolResult::success(format!(
        "Invite link created:\n  URL: {}\n  Keys: {}\n  Permission: {}\n  Expires: {} ({} hours)\n  {}",
        url, keys, permission, invite.expires_at, expiry,
        email.map(|e| format!("Restricted to: {}", e)).unwrap_or_default()
    )))
}

/// List active invites
#[tool(name = "list_invites")]
async fn list_invites(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Revoke an invite
#[tool(name = "revoke_invite")]
async fn revoke_invite(
    &self,
    #[arg(description = "Invite ID")] invite_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Create invite for new developer
pqvault invite create \
  --keys STAGING_DB_URL,STAGING_REDIS_URL,DEV_API_KEY \
  --permission read \
  --expiry 48h \
  --email new-dev@company.com \
  --message "Welcome to the team! Here are your staging credentials."
# Invite link: https://vault.company.com/invite/aBcDeFgHiJkLmN...
# Expires in 48 hours, restricted to new-dev@company.com

# Create invite for contractor (proxy only, 4-hour grant)
pqvault invite create \
  --keys CLIENT_API_KEY \
  --permission proxy \
  --expiry 24h \
  --duration 4h

# List active invites
pqvault invite list
# inv-abc | 3 keys | read | new-dev@company.com | expires in 36h | Active

# Revoke invite
pqvault invite revoke inv-abc
```

### Web UI Changes

- "Share Keys" button on key detail page
- Invite link creation dialog with key picker
- Invite landing page with SSO login and key display
- Sent invites management panel
- Invite redemption confirmation page

## Dependencies

- `rand = "0.8"` (existing) — Secure token generation
- `base64 = "0.22"` — URL-safe token encoding
- `uuid = "1"` (existing) — Invite IDs
- Feature 041 (RBAC) — User authentication on redemption
- Feature 043 (SSO) — SSO login on invite redemption

## Testing

### Unit Tests

```rust
#[test]
fn token_is_url_safe() {
    let token = generate_secure_token(32);
    assert!(token.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}

#[test]
fn invite_single_use() {
    let mut mgr = InviteManager::new();
    let invite = mgr.create_invite("admin", vec![], 48, None, None);
    mgr.redeem(&invite.token, "user1", None).unwrap();
    assert!(mgr.redeem(&invite.token, "user2", None).is_err());
}

#[test]
fn invite_expired() {
    let mut mgr = InviteManager::new();
    let invite = mgr.create_invite("admin", vec![], 0, None, None); // Expires immediately
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(mgr.redeem(&invite.token, "user1", None).is_err());
}

#[test]
fn invite_email_restriction() {
    let mut mgr = InviteManager::new();
    let invite = mgr.create_invite("admin", vec![], 48, Some("alice@co.com".into()), None);
    assert!(mgr.redeem(&invite.token, "u1", Some("bob@co.com")).is_err());
    assert!(mgr.redeem(&invite.token, "u1", Some("alice@co.com")).is_ok());
}

#[test]
fn revoked_invite_cannot_be_redeemed() {
    let mut mgr = InviteManager::new();
    let invite = mgr.create_invite("admin", vec![], 48, None, None);
    mgr.revoke(&invite.id).unwrap();
    assert!(mgr.redeem(&invite.token, "user1", None).is_err());
}
```

### Integration Tests

```rust
#[tokio::test]
async fn invite_grants_key_access() {
    let mcp = test_team_mcp().await;
    mcp.vault.store("KEY1", "secret").await.unwrap();

    let invite = mcp.create_invite("KEY1", Some("read"), Some(48), None, None).await.unwrap();
    let token = extract_token(&invite);

    // Redeem as new user
    mcp.login_as("new_user").await;
    mcp.redeem_invite(&token).await.unwrap();

    // New user can now read KEY1
    assert!(mcp.vault_get("KEY1").await.is_ok());
}
```

### Manual Verification

1. Create invite link for specific keys
2. Open link in incognito browser
3. Authenticate and verify key access is granted
4. Attempt to reuse the link — verify it fails
5. Create invite with email restriction, test with wrong email
6. Revoke invite before redemption, verify it fails

## Example Usage

```bash
# Onboarding flow:
# 1. Admin creates invite for new hire
pqvault invite create --keys STAGING_DB,STAGING_REDIS,DEV_STRIPE \
  --email newhire@company.com --message "Welcome! These are your dev environment keys."

# 2. Send link via Slack/email (link itself is not a secret)
# 3. New hire clicks link, logs in via SSO
# 4. Keys are automatically granted
# 5. Link is marked as redeemed

# Contractor sharing:
pqvault invite create --keys CLIENT_API_KEY --permission proxy \
  --expiry 24h --duration 8h \
  --message "Proxy-only access for integration testing"
```
