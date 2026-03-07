# Feature 048: Temporary Access Grants

## Status: Planned
## Phase: 5 (v2.5)
## Priority: Medium

## Problem

Access is either permanent or nonexistent. When a developer needs access to a production key for a 4-hour debugging session, the only option is to grant permanent access and hope someone remembers to revoke it later. This leads to permission accumulation, security risk, and compliance violations. Time-limited access should be the default, not the exception.

## Solution

Implement time-limited access grants with automatic revocation. Access is specified with an explicit duration: "Give dev-X access to PROD_DB_URL for 4 hours." When the duration expires, access is automatically revoked without requiring manual intervention. Grants can be extended, revoked early, or converted to permanent by an admin. All grants are tracked with full audit trail.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/temp_access.rs` — Temporary access grant management
- `crates/pqvault-team-mcp/src/lib.rs` — Register temporary access tools
- `crates/pqvault-team-mcp/src/expiry_worker.rs` — Background worker for automatic revocation

### Data Model Changes

```rust
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Temporary access grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempGrant {
    pub id: String,
    pub user_id: String,
    pub key_name: String,
    pub permission: String,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
    pub status: GrantStatus,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub extended_count: u32,
    pub original_duration: Duration,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum GrantStatus {
    Active,
    Expired,
    Revoked,
    Extended,
}

impl TempGrant {
    pub fn is_active(&self) -> bool {
        self.status == GrantStatus::Active && Utc::now() < self.expires_at
    }

    pub fn remaining(&self) -> Duration {
        if self.is_active() {
            self.expires_at - Utc::now()
        } else {
            Duration::zero()
        }
    }
}

/// Temporary access manager
pub struct TempAccessManager {
    grants: Vec<TempGrant>,
    max_extensions: u32,
    max_duration_hours: u32,
}

impl TempAccessManager {
    pub fn grant(
        &mut self,
        user_id: &str,
        key_name: &str,
        permission: &str,
        duration: Duration,
        granted_by: &str,
        reason: &str,
    ) -> Result<TempGrant, String> {
        if duration > Duration::hours(self.max_duration_hours as i64) {
            return Err(format!("Max duration is {} hours", self.max_duration_hours));
        }

        let grant = TempGrant {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            key_name: key_name.to_string(),
            permission: permission.to_string(),
            granted_by: granted_by.to_string(),
            granted_at: Utc::now(),
            expires_at: Utc::now() + duration,
            reason: reason.to_string(),
            status: GrantStatus::Active,
            revoked_at: None,
            revoked_by: None,
            extended_count: 0,
            original_duration: duration,
        };
        self.grants.push(grant.clone());
        Ok(grant)
    }

    pub fn extend(
        &mut self,
        grant_id: &str,
        additional_hours: u32,
        extended_by: &str,
    ) -> Result<&TempGrant, String> {
        let grant = self.grants.iter_mut()
            .find(|g| g.id == grant_id && g.is_active())
            .ok_or("Grant not found or not active")?;

        if grant.extended_count >= self.max_extensions {
            return Err(format!("Max {} extensions allowed", self.max_extensions));
        }

        grant.expires_at = grant.expires_at + Duration::hours(additional_hours as i64);
        grant.extended_count += 1;
        grant.status = GrantStatus::Extended;
        Ok(grant)
    }

    pub fn revoke(&mut self, grant_id: &str, revoked_by: &str) -> Result<(), String> {
        let grant = self.grants.iter_mut()
            .find(|g| g.id == grant_id && g.is_active())
            .ok_or("Grant not found or not active")?;

        grant.status = GrantStatus::Revoked;
        grant.revoked_at = Some(Utc::now());
        grant.revoked_by = Some(revoked_by.to_string());
        Ok(())
    }

    /// Expire all grants past their deadline
    pub fn expire_stale(&mut self) -> Vec<String> {
        let mut expired = Vec::new();
        for grant in &mut self.grants {
            if grant.status == GrantStatus::Active && Utc::now() >= grant.expires_at {
                grant.status = GrantStatus::Expired;
                expired.push(grant.id.clone());
            }
        }
        expired
    }

    /// Check if user has active access to a key
    pub fn has_access(&self, user_id: &str, key_name: &str) -> bool {
        self.grants.iter().any(|g| {
            g.user_id == user_id && g.key_name == key_name && g.is_active()
        })
    }
}
```

### MCP Tools

```rust
/// Grant temporary access to a key
#[tool(name = "grant_temp_access")]
async fn grant_temp_access(
    &self,
    #[arg(description = "User ID")] user_id: String,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Permission: read, proxy, rotate")] permission: String,
    #[arg(description = "Duration (e.g., '4h', '30m', '1d')")] duration: String,
    #[arg(description = "Reason for access")] reason: String,
) -> Result<CallToolResult, McpError> {
    let dur = parse_duration(&duration)?;
    let grant = self.temp_mgr.grant(&user_id, &key_name, &permission, dur, &self.current_user_id, &reason)?;
    Ok(CallToolResult::success(format!(
        "Temporary access granted:\n  User: {}\n  Key: {}\n  Permission: {}\n  Expires: {} ({} remaining)\n  Grant ID: {}",
        user_id, key_name, permission, grant.expires_at, duration, grant.id
    )))
}

/// Extend an active grant
#[tool(name = "extend_grant")]
async fn extend_grant(
    &self,
    #[arg(description = "Grant ID")] grant_id: String,
    #[arg(description = "Additional hours")] hours: u32,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Revoke a grant early
#[tool(name = "revoke_grant")]
async fn revoke_grant(
    &self,
    #[arg(description = "Grant ID")] grant_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List active temporary grants
#[tool(name = "list_grants")]
async fn list_grants(
    &self,
    #[arg(description = "User ID filter")] user_id: Option<String>,
    #[arg(description = "Key name filter")] key_name: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Grant 4-hour access
pqvault grant --user alice --key PROD_DB_URL --permission read \
  --duration 4h --reason "Debugging issue #1234"

# Grant 30-minute access
pqvault grant --user bob --key STAGING_KEY --permission proxy --duration 30m

# List active grants
pqvault grants list
# tg-abc | alice | PROD_DB_URL | read | expires in 3h12m
# tg-def | bob | STAGING_KEY | proxy | expires in 18m

# Extend a grant
pqvault grant extend tg-abc --hours 2

# Revoke early
pqvault grant revoke tg-def

# View expired grants
pqvault grants list --status expired
```

### Web UI Changes

- "Grant Temporary Access" button on key detail page
- Active grants dashboard with countdown timers
- Expiry notification banner 15 minutes before revocation
- Grant extension dialog
- Grant history timeline

## Dependencies

- `uuid = "1"` (existing) — Grant IDs
- `chrono = "0.4"` (existing) — Duration and expiry
- `tokio = "1"` (existing) — Background expiry worker
- Feature 041 (RBAC) — Permission model

## Testing

### Unit Tests

```rust
#[test]
fn grant_expires_automatically() {
    let mut mgr = TempAccessManager::new(3, 24);
    let grant = mgr.grant("user1", "KEY", "read", Duration::seconds(0), "admin", "test").unwrap();
    assert!(!grant.is_active()); // Already expired
    assert!(grant.remaining() == Duration::zero());
}

#[test]
fn has_access_checks_expiry() {
    let mut mgr = TempAccessManager::new(3, 24);
    mgr.grant("user1", "KEY", "read", Duration::hours(4), "admin", "test").unwrap();
    assert!(mgr.has_access("user1", "KEY"));
    assert!(!mgr.has_access("user2", "KEY"));
}

#[test]
fn extension_limit_enforced() {
    let mut mgr = TempAccessManager::new(2, 24); // max 2 extensions
    let grant = mgr.grant("user1", "KEY", "read", Duration::hours(1), "admin", "test").unwrap();
    mgr.extend(&grant.id, 1, "admin").unwrap();
    mgr.extend(&grant.id, 1, "admin").unwrap();
    assert!(mgr.extend(&grant.id, 1, "admin").is_err());
}

#[test]
fn max_duration_enforced() {
    let mut mgr = TempAccessManager::new(3, 8); // max 8 hours
    let result = mgr.grant("user1", "KEY", "read", Duration::hours(24), "admin", "test");
    assert!(result.is_err());
}

#[test]
fn expire_stale_marks_expired() {
    let mut mgr = TempAccessManager::new(3, 24);
    mgr.grant("user1", "KEY", "read", Duration::seconds(0), "admin", "test").unwrap();
    let expired = mgr.expire_stale();
    assert_eq!(expired.len(), 1);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn temp_access_revoked_after_expiry() {
    let mcp = test_team_mcp().await;
    mcp.grant_temp_access("user1", "KEY", "read", "1s", "test").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    mcp.expire_stale_grants().await;
    assert!(!mcp.has_access("user1", "KEY").await);
}
```

### Manual Verification

1. Grant temporary access for 5 minutes
2. Verify access works within the window
3. Wait for expiry, verify access is revoked
4. Extend a grant, verify new expiry time
5. Revoke a grant early, verify immediate revocation

## Example Usage

```bash
# Common patterns:
# Debugging session (4 hours):
pqvault grant --user dev1 --key PROD_DB --permission read --duration 4h \
  --reason "Debugging connection timeout issue"

# One-time deployment (30 minutes):
pqvault grant --user deploy-bot --key AWS_PROD_KEY --permission proxy --duration 30m \
  --reason "Deploying v2.3.1"

# Contractor access (1 day):
pqvault grant --user contractor1 --key STAGING_API --permission read --duration 1d \
  --reason "Integration testing for client project"
```
