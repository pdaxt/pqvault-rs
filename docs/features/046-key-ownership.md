# Feature 046: Key Ownership

## Status: Done
## Phase: 5 (v2.5)
## Priority: Medium

## Problem

Nobody is explicitly responsible for any specific key in the vault. When a key expires, nobody is notified. When a key has anomalous usage, nobody owns the investigation. When rotation is overdue, nobody is accountable. This leads to neglected keys, delayed incident response, and a diffusion of responsibility across the team.

## Solution

Every key has a mandatory `owner` field — the user responsible for that key's lifecycle. Owners receive notifications on health issues, rotation reminders, anomaly alerts, and access requests for their keys. Ownership can be transferred between users. An "orphan detection" tool finds keys whose owner has left the organization. The owner field is required on key creation and displayed prominently in all views.

## Implementation

### Files to Create/Modify

- `crates/pqvault-core/src/ownership.rs` — Ownership management and notification routing
- `crates/pqvault-core/src/models.rs` — Add `owner_id` and `backup_owner_id` fields
- `crates/pqvault-mcp/src/lib.rs` — Enforce ownership on key creation
- `crates/pqvault-health-mcp/src/orphans.rs` — Orphan key detection

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Key ownership record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOwnership {
    pub key_name: String,
    pub owner_id: String,
    pub backup_owner_id: Option<String>,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: String,
    pub transfer_history: Vec<OwnershipTransfer>,
}

/// Ownership transfer record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipTransfer {
    pub from_user: String,
    pub to_user: String,
    pub transferred_at: DateTime<Utc>,
    pub reason: String,
}

/// Orphan key — owner no longer active
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanKey {
    pub key_name: String,
    pub last_owner_id: String,
    pub last_owner_name: String,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub key_health_score: f64,
    pub last_used: Option<DateTime<Utc>>,
}

/// Notification to key owner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerNotification {
    pub key_name: String,
    pub owner_id: String,
    pub notification_type: OwnerNotificationType,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OwnerNotificationType {
    RotationDue,
    HealthAlert,
    AnomalyDetected,
    AccessRequested,
    KeyExpiring,
    CostSpike,
}

/// Ownership enforcer
pub struct OwnershipManager {
    ownerships: Vec<KeyOwnership>,
}

impl OwnershipManager {
    /// Validate that a key has an owner before creation
    pub fn validate_creation(&self, key_name: &str, owner_id: &str) -> Result<(), String> {
        if owner_id.is_empty() {
            return Err("Key must have an owner. Specify --owner <user_id>".into());
        }
        Ok(())
    }

    /// Transfer ownership
    pub fn transfer(
        &mut self,
        key_name: &str,
        from_user: &str,
        to_user: &str,
        reason: &str,
    ) -> Result<(), String> {
        let ownership = self.ownerships.iter_mut()
            .find(|o| o.key_name == key_name)
            .ok_or("Key not found")?;

        if ownership.owner_id != from_user {
            return Err("Only the current owner can transfer ownership".into());
        }

        ownership.transfer_history.push(OwnershipTransfer {
            from_user: from_user.to_string(),
            to_user: to_user.to_string(),
            transferred_at: Utc::now(),
            reason: reason.to_string(),
        });
        ownership.owner_id = to_user.to_string();
        ownership.assigned_at = Utc::now();
        Ok(())
    }

    /// Detect orphan keys (owner is inactive)
    pub fn detect_orphans(&self, active_users: &[String]) -> Vec<OrphanKey> {
        self.ownerships.iter()
            .filter(|o| !active_users.contains(&o.owner_id))
            .map(|o| OrphanKey {
                key_name: o.key_name.clone(),
                last_owner_id: o.owner_id.clone(),
                last_owner_name: String::new(),
                deactivated_at: None,
                key_health_score: 0.0,
                last_used: None,
            })
            .collect()
    }
}
```

### MCP Tools

```rust
/// Set or change key owner
#[tool(name = "set_owner")]
async fn set_owner(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "New owner user ID")] owner_id: String,
    #[arg(description = "Backup owner (optional)")] backup_owner_id: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Transfer ownership
#[tool(name = "transfer_ownership")]
async fn transfer_ownership(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "New owner user ID")] to_user: String,
    #[arg(description = "Reason for transfer")] reason: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Detect orphan keys
#[tool(name = "detect_orphans")]
async fn detect_orphans(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List keys owned by a user
#[tool(name = "list_owned_keys")]
async fn list_owned_keys(
    &self,
    #[arg(description = "User ID (current user if omitted)")] user_id: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Set owner on key creation
pqvault set STRIPE_KEY sk-... --owner alice

# Change owner
pqvault owner set STRIPE_KEY --owner bob

# Transfer ownership
pqvault owner transfer STRIPE_KEY --to bob --reason "Alice leaving team"

# List my owned keys
pqvault owner mine
# STRIPE_KEY (Healthy, 92/100)
# DATABASE_URL (Rotation due in 5 days)
# REDIS_URL (OK)

# Detect orphan keys
pqvault owner orphans
# 3 orphan keys found:
#   OLD_API_KEY — last owner: charlie (deactivated 2026-01-15)
#   LEGACY_DB — last owner: charlie (deactivated 2026-01-15)
#   TEST_KEY — last owner: dave (deactivated 2026-02-20)

# Bulk reassign orphans
pqvault owner reassign --from charlie --to alice --reason "charlie left the team"
```

### Web UI Changes

- Owner field on key creation form (required)
- Owner badge displayed on each key in list view
- "My Keys" dashboard showing keys you own with health summary
- Orphan keys alert in admin panel
- Ownership transfer dialog with history

## Dependencies

- `pqvault-core` (existing) — Key metadata
- `chrono = "0.4"` (existing) — Timestamps
- Feature 041 (RBAC) — User management

## Testing

### Unit Tests

```rust
#[test]
fn owner_required_on_creation() {
    let mgr = OwnershipManager::new();
    assert!(mgr.validate_creation("KEY", "").is_err());
    assert!(mgr.validate_creation("KEY", "alice").is_ok());
}

#[test]
fn transfer_records_history() {
    let mut mgr = OwnershipManager::new();
    mgr.assign("KEY", "alice", "admin");
    mgr.transfer("KEY", "alice", "bob", "team change").unwrap();
    let ownership = mgr.get("KEY").unwrap();
    assert_eq!(ownership.owner_id, "bob");
    assert_eq!(ownership.transfer_history.len(), 1);
    assert_eq!(ownership.transfer_history[0].from_user, "alice");
}

#[test]
fn only_owner_can_transfer() {
    let mut mgr = OwnershipManager::new();
    mgr.assign("KEY", "alice", "admin");
    assert!(mgr.transfer("KEY", "bob", "charlie", "unauthorized").is_err());
}

#[test]
fn detect_orphans_finds_inactive_owners() {
    let mut mgr = OwnershipManager::new();
    mgr.assign("KEY1", "alice", "admin");
    mgr.assign("KEY2", "bob", "admin");
    let orphans = mgr.detect_orphans(&["alice".into()]); // bob is inactive
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].key_name, "KEY2");
}
```

### Integration Tests

```rust
#[tokio::test]
async fn key_creation_requires_owner() {
    let mcp = test_mcp().await;
    let result = mcp.vault_set_without_owner("KEY", "value").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must have an owner"));
}

#[tokio::test]
async fn owner_receives_notifications() {
    let mcp = test_mcp().await;
    mcp.vault_set_with_owner("KEY", "value", "alice").await.unwrap();
    mcp.trigger_rotation_reminder("KEY").await;

    let notifications = mcp.get_notifications("alice").await.unwrap();
    assert!(notifications.iter().any(|n| matches!(n.notification_type, OwnerNotificationType::RotationDue)));
}
```

### Manual Verification

1. Create key without owner — verify rejection
2. Create key with owner — verify owner is recorded
3. Transfer ownership and check history
4. Deactivate a user, run orphan detection
5. Verify notifications reach key owners for health alerts

## Example Usage

```bash
# Every key has an accountable owner:
pqvault set STRIPE_KEY sk-... --owner alice --backup-owner bob
pqvault set DATABASE_URL postgres://... --owner bob

# When rotation is due, alice gets notified:
# "Your key STRIPE_KEY is due for rotation (last rotated 85 days ago)"

# When alice leaves:
pqvault user deactivate alice
pqvault owner orphans
# STRIPE_KEY is now orphaned — reassign to bob
pqvault owner reassign --from alice --to bob --reason "alice offboarded"
```
