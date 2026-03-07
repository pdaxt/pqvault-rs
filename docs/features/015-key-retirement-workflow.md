# Feature 015: Key Retirement Workflow

## Status: Planned
## Phase: 2 (v2.2)
## Priority: High

## Problem

Secrets in PQVault are either active or deleted — there is no middle ground. Keys are immortal: there is no deprecation workflow, no sunset warning system, and no retirement process. When a key should be phased out (migrating providers, decommissioning services), operators must remember to delete it manually. Consumers of deprecated keys get no warning that the key is about to go away, leading to surprise outages.

## Solution

Implement a lifecycle state machine for secrets: `active -> deprecated -> disabled -> archived -> deleted`. Each transition has defined semantics — deprecated keys work but warn consumers, disabled keys are blocked from use, archived keys are read-only for audit purposes, and deleted keys are permanently removed. MCP tools and CLI commands manage transitions with configurable timelines.

## Implementation

### Files to Create/Modify

- `crates/pqvault-core/src/models.rs` — Add `lifecycle_status` field to SecretEntry, define lifecycle enum
- `crates/pqvault-mcp/src/lifecycle.rs` — MCP tools for lifecycle transitions
- `crates/pqvault-mcp/src/lib.rs` — Register lifecycle tools
- `crates/pqvault-proxy-mcp/src/proxy.rs` — Enforce lifecycle status on proxy requests
- `crates/pqvault-cli/src/main.rs` — Add lifecycle CLI commands

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum LifecycleStatus {
    /// Key is active and fully operational
    Active,
    /// Key works but consumers receive deprecation warnings
    Deprecated {
        deprecated_at: String,
        deprecated_by: String,
        reason: String,
        disable_after: Option<String>,  // Auto-disable date
        replacement_key: Option<String>, // Name of replacement key
    },
    /// Key is blocked from use — proxy rejects requests
    Disabled {
        disabled_at: String,
        disabled_by: String,
        reason: String,
        archive_after: Option<String>,
    },
    /// Key is read-only for audit — value accessible but not usable via proxy
    Archived {
        archived_at: String,
        archived_by: String,
        delete_after: Option<String>,
    },
}

impl Default for LifecycleStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Add to SecretEntry
pub struct SecretEntry {
    // ... existing fields ...
    pub lifecycle_status: LifecycleStatus,
}

/// Lifecycle transition event for audit trail
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LifecycleEvent {
    pub key_name: String,
    pub from_status: String,
    pub to_status: String,
    pub timestamp: String,
    pub actor: String,
    pub reason: String,
}
```

### MCP Tools

```rust
// Tool: vault_deprecate
{
    "name": "vault_deprecate",
    "description": "Mark a key as deprecated — it works but consumers get warnings",
    "params": {
        "key_name": "OLD_STRIPE_KEY",
        "reason": "Migrating to new Stripe account",
        "replacement_key": "NEW_STRIPE_KEY",    // optional
        "disable_after_days": 30                 // optional: auto-disable after N days
    },
    "returns": {
        "key_name": "OLD_STRIPE_KEY",
        "new_status": "deprecated",
        "disable_date": "2025-02-14T00:00:00Z",
        "replacement": "NEW_STRIPE_KEY"
    }
}

// Tool: vault_disable
{
    "name": "vault_disable",
    "description": "Disable a key — proxy will reject all requests using it",
    "params": {
        "key_name": "OLD_STRIPE_KEY",
        "reason": "Migration complete, disabling old key",
        "archive_after_days": 90     // optional
    },
    "returns": {
        "key_name": "OLD_STRIPE_KEY",
        "new_status": "disabled",
        "archive_date": "2025-05-15T00:00:00Z"
    }
}

// Tool: vault_archive
{
    "name": "vault_archive",
    "description": "Archive a key — keeps for audit, not usable",
    "params": {
        "key_name": "OLD_STRIPE_KEY",
        "delete_after_days": 365     // optional
    },
    "returns": {
        "key_name": "OLD_STRIPE_KEY",
        "new_status": "archived",
        "delete_date": "2026-01-15T00:00:00Z"
    }
}

// Tool: vault_reactivate
{
    "name": "vault_reactivate",
    "description": "Reactivate a deprecated or disabled key",
    "params": {
        "key_name": "OLD_STRIPE_KEY",
        "reason": "Migration rolled back, need old key again"
    },
    "returns": {
        "key_name": "OLD_STRIPE_KEY",
        "new_status": "active"
    }
}
```

### CLI Commands

```bash
# Deprecate a key
pqvault deprecate OLD_STRIPE_KEY --reason "Migrating" --replacement NEW_STRIPE_KEY --disable-after 30d

# Disable a key
pqvault disable OLD_STRIPE_KEY --reason "Migration complete"

# Archive a key
pqvault archive OLD_STRIPE_KEY --delete-after 365d

# Reactivate a key
pqvault reactivate OLD_STRIPE_KEY --reason "Migration rolled back"

# Show lifecycle status of all keys
pqvault lifecycle status

# Show lifecycle history for a key
pqvault lifecycle history OLD_STRIPE_KEY
```

### Web UI Changes

- Color-coded lifecycle badges: green=active, yellow=deprecated, red=disabled, gray=archived
- Lifecycle timeline visualization for each key
- Bulk lifecycle management (deprecate all keys in a category)

## Core Implementation

```rust
// crates/pqvault-mcp/src/lifecycle.rs

use anyhow::{bail, Result};
use chrono::{Utc, Duration};

pub struct LifecycleManager;

impl LifecycleManager {
    /// Transition key to deprecated status
    pub fn deprecate(
        vault: &mut Vault,
        key_name: &str,
        reason: &str,
        replacement_key: Option<String>,
        disable_after_days: Option<u32>,
        actor: &str,
    ) -> Result<()> {
        let entry = vault.get_entry_mut(key_name)?;

        // Validate transition: only Active keys can be deprecated
        match &entry.lifecycle_status {
            LifecycleStatus::Active => {}
            other => bail!(
                "Cannot deprecate key in '{}' state. Only active keys can be deprecated.",
                status_name(other)
            ),
        }

        let disable_after = disable_after_days.map(|days| {
            (Utc::now() + Duration::days(days as i64)).to_rfc3339()
        });

        entry.lifecycle_status = LifecycleStatus::Deprecated {
            deprecated_at: Utc::now().to_rfc3339(),
            deprecated_by: actor.to_string(),
            reason: reason.to_string(),
            disable_after,
            replacement_key,
        };

        vault.save()?;
        Ok(())
    }

    /// Transition key to disabled status
    pub fn disable(
        vault: &mut Vault,
        key_name: &str,
        reason: &str,
        archive_after_days: Option<u32>,
        actor: &str,
    ) -> Result<()> {
        let entry = vault.get_entry_mut(key_name)?;

        match &entry.lifecycle_status {
            LifecycleStatus::Active | LifecycleStatus::Deprecated { .. } => {}
            other => bail!(
                "Cannot disable key in '{}' state.",
                status_name(other)
            ),
        }

        let archive_after = archive_after_days.map(|days| {
            (Utc::now() + Duration::days(days as i64)).to_rfc3339()
        });

        entry.lifecycle_status = LifecycleStatus::Disabled {
            disabled_at: Utc::now().to_rfc3339(),
            disabled_by: actor.to_string(),
            reason: reason.to_string(),
            archive_after,
        };

        vault.save()?;
        Ok(())
    }

    /// Transition key to archived status
    pub fn archive(
        vault: &mut Vault,
        key_name: &str,
        delete_after_days: Option<u32>,
        actor: &str,
    ) -> Result<()> {
        let entry = vault.get_entry_mut(key_name)?;

        match &entry.lifecycle_status {
            LifecycleStatus::Disabled { .. } => {}
            other => bail!(
                "Cannot archive key in '{}' state. Disable it first.",
                status_name(other)
            ),
        }

        let delete_after = delete_after_days.map(|days| {
            (Utc::now() + Duration::days(days as i64)).to_rfc3339()
        });

        entry.lifecycle_status = LifecycleStatus::Archived {
            archived_at: Utc::now().to_rfc3339(),
            archived_by: actor.to_string(),
            delete_after,
        };

        vault.save()?;
        Ok(())
    }

    /// Reactivate a deprecated or disabled key
    pub fn reactivate(
        vault: &mut Vault,
        key_name: &str,
        reason: &str,
        actor: &str,
    ) -> Result<()> {
        let entry = vault.get_entry_mut(key_name)?;

        match &entry.lifecycle_status {
            LifecycleStatus::Deprecated { .. } | LifecycleStatus::Disabled { .. } => {}
            LifecycleStatus::Archived { .. } => bail!(
                "Cannot reactivate archived key. Create a new key instead."
            ),
            LifecycleStatus::Active => bail!("Key is already active."),
        }

        entry.lifecycle_status = LifecycleStatus::Active;
        vault.save()?;
        Ok(())
    }

    /// Process auto-transitions (disable deprecated, archive disabled, delete archived)
    pub fn process_auto_transitions(vault: &mut Vault) -> Vec<LifecycleEvent> {
        let now = Utc::now();
        let mut events = Vec::new();

        for entry in &mut vault.entries {
            let transition = match &entry.lifecycle_status {
                LifecycleStatus::Deprecated { disable_after: Some(date), .. } => {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date) {
                        if now > dt.with_timezone(&Utc) {
                            Some(("deprecated", "disabled"))
                        } else { None }
                    } else { None }
                }
                LifecycleStatus::Disabled { archive_after: Some(date), .. } => {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date) {
                        if now > dt.with_timezone(&Utc) {
                            Some(("disabled", "archived"))
                        } else { None }
                    } else { None }
                }
                _ => None,
            };

            if let Some((from, to)) = transition {
                events.push(LifecycleEvent {
                    key_name: entry.name.clone(),
                    from_status: from.to_string(),
                    to_status: to.to_string(),
                    timestamp: now.to_rfc3339(),
                    actor: "system/auto-transition".into(),
                    reason: "Scheduled auto-transition".into(),
                });
            }
        }

        events
    }
}

fn status_name(status: &LifecycleStatus) -> &'static str {
    match status {
        LifecycleStatus::Active => "active",
        LifecycleStatus::Deprecated { .. } => "deprecated",
        LifecycleStatus::Disabled { .. } => "disabled",
        LifecycleStatus::Archived { .. } => "archived",
    }
}
```

## Dependencies

- No new dependencies
- Uses existing `chrono` for timestamp management

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprecate_active_key() {
        let mut vault = create_test_vault_with_entry("KEY_1", LifecycleStatus::Active);
        LifecycleManager::deprecate(&mut vault, "KEY_1", "test", None, None, "user").unwrap();
        assert!(matches!(vault.entries[0].lifecycle_status, LifecycleStatus::Deprecated { .. }));
    }

    #[test]
    fn test_cannot_deprecate_disabled_key() {
        let mut vault = create_test_vault_with_entry("KEY_1", LifecycleStatus::Disabled {
            disabled_at: Utc::now().to_rfc3339(),
            disabled_by: "user".into(),
            reason: "test".into(),
            archive_after: None,
        });
        let result = LifecycleManager::deprecate(&mut vault, "KEY_1", "test", None, None, "user");
        assert!(result.is_err());
    }

    #[test]
    fn test_full_lifecycle() {
        let mut vault = create_test_vault_with_entry("KEY_1", LifecycleStatus::Active);

        // Active -> Deprecated
        LifecycleManager::deprecate(&mut vault, "KEY_1", "migrating", None, None, "user").unwrap();

        // Deprecated -> Disabled
        LifecycleManager::disable(&mut vault, "KEY_1", "complete", None, "user").unwrap();

        // Disabled -> Archived
        LifecycleManager::archive(&mut vault, "KEY_1", None, "user").unwrap();

        assert!(matches!(vault.entries[0].lifecycle_status, LifecycleStatus::Archived { .. }));
    }

    #[test]
    fn test_reactivate_deprecated() {
        let mut vault = create_test_vault_with_entry("KEY_1", LifecycleStatus::Active);
        LifecycleManager::deprecate(&mut vault, "KEY_1", "test", None, None, "user").unwrap();
        LifecycleManager::reactivate(&mut vault, "KEY_1", "changed mind", "user").unwrap();
        assert_eq!(vault.entries[0].lifecycle_status, LifecycleStatus::Active);
    }

    #[test]
    fn test_cannot_reactivate_archived() {
        let mut vault = create_test_vault_with_entry("KEY_1", LifecycleStatus::Archived {
            archived_at: Utc::now().to_rfc3339(),
            archived_by: "user".into(),
            delete_after: None,
        });
        let result = LifecycleManager::reactivate(&mut vault, "KEY_1", "test", "user");
        assert!(result.is_err());
    }
}
```

### Manual Verification

1. Create a key and deprecate it with a replacement
2. Access the deprecated key — verify warning is returned
3. Disable the key — verify proxy rejects requests
4. Archive the key — verify it appears in audit but not active lists
5. Set auto-transition timers and verify they fire

## Example Usage

```bash
# Deprecate a key with a replacement
$ pqvault deprecate OLD_STRIPE_KEY \
    --reason "Migrating to new Stripe account" \
    --replacement NEW_STRIPE_KEY \
    --disable-after 30d
Key OLD_STRIPE_KEY deprecated.
  Replacement: NEW_STRIPE_KEY
  Auto-disable: 2025-02-14
  Consumers will see deprecation warnings.

# Check lifecycle status
$ pqvault lifecycle status
Name                Status       Since        Auto-transition
OLD_STRIPE_KEY      DEPRECATED   15 days ago  disable in 15d
NEW_STRIPE_KEY      ACTIVE       15 days ago  -
DATABASE_URL        ACTIVE       90 days ago  -
LEGACY_API_KEY      DISABLED     30 days ago  archive in 60d

# Disable after migration is confirmed
$ pqvault disable OLD_STRIPE_KEY --reason "Migration verified" --archive-after 90d
Key OLD_STRIPE_KEY disabled. Proxy will reject all requests.

# View lifecycle history
$ pqvault lifecycle history OLD_STRIPE_KEY
2025-01-15  ACTIVE -> DEPRECATED  by user   "Migrating to new account"
2025-02-14  DEPRECATED -> DISABLED  by system "Scheduled auto-transition"
```
