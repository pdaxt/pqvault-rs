# Feature 014: Rotation Rollback

## Status: Done
## Phase: 2 (v2.2)
## Priority: High

## Problem

When a key is rotated, the old key value is immediately discarded. If the new key fails in production (wrong permissions, rate-limited, rejected by a downstream service), there is no way to revert. The operator must manually log into the provider's dashboard, regenerate a key, and update the vault — all while production is down. There is zero safety net for failed rotations.

## Solution

After rotation, retain the old key value (encrypted) for a configurable period (default: 24 hours). If the new key fails a health check during this window, automatically or manually rollback to the old key. A background health check monitors newly rotated keys at increasing intervals (1min, 5min, 15min, 1hr) during the rollback window.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/rollback.rs` — Rollback logic and health monitoring
- `crates/pqvault-core/src/models.rs` — Add `prev_value`, `prev_rotated`, `rollback_until` to SecretEntry
- `crates/pqvault-rotation-mcp/src/engine.rs` — Store old value during rotation
- `crates/pqvault-cli/src/main.rs` — Add `rollback` CLI command

### Data Model Changes

```rust
/// Extended rotation metadata on SecretEntry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationMetadata {
    pub last_rotated: Option<String>,
    pub rotation_count: u32,
    /// Encrypted previous key value (for rollback)
    pub prev_value: Option<String>,
    /// When the previous key was active
    pub prev_rotated: Option<String>,
    /// Rollback window end time — after this, prev_value is purged
    pub rollback_until: Option<String>,
    /// Whether auto-rollback is enabled for this key
    pub auto_rollback: bool,
    /// Health check results during rollback window
    pub post_rotation_checks: Vec<PostRotationCheck>,
    pub provider_config: Option<ProviderRotationConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostRotationCheck {
    pub timestamp: String,
    pub passed: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

/// Rollback result
#[derive(Serialize, Deserialize, Debug)]
pub struct RollbackResult {
    pub key_name: String,
    pub rolled_back: bool,
    pub reason: String,
    pub old_value_preview: String,
    pub restored_value_preview: String,
}
```

### MCP Tools

```rust
// Tool: vault_rollback
{
    "name": "vault_rollback",
    "description": "Rollback a recently rotated key to its previous value",
    "params": {
        "key_name": "STRIPE_SECRET_KEY"
    },
    "returns": {
        "rolled_back": true,
        "reason": "Manual rollback requested",
        "old_value_preview": "sk_l...abc (current, will be discarded)",
        "restored_value_preview": "sk_l...xyz (previous, now restored)"
    }
}

// Tool: vault_rollback_status
{
    "name": "vault_rollback_status",
    "description": "Check which keys have rollback available",
    "params": {},
    "returns": {
        "keys_with_rollback": [
            {
                "key_name": "STRIPE_SECRET_KEY",
                "rotated_at": "2025-01-15T10:00:00Z",
                "rollback_until": "2025-01-16T10:00:00Z",
                "post_rotation_checks": [
                    { "timestamp": "...", "passed": true }
                ]
            }
        ]
    }
}
```

### CLI Commands

```bash
# Rollback a key to its previous value
pqvault rollback STRIPE_SECRET_KEY

# Check rollback availability
pqvault rollback --status

# Force rollback (even if health checks pass)
pqvault rollback STRIPE_SECRET_KEY --force

# Extend rollback window
pqvault rollback STRIPE_SECRET_KEY --extend 24h

# Purge old value early (confirm rotation is good)
pqvault rollback STRIPE_SECRET_KEY --confirm
```

## Core Implementation

```rust
// crates/pqvault-rotation-mcp/src/rollback.rs

use chrono::{DateTime, Utc, Duration};
use anyhow::{bail, Context, Result};

pub struct RollbackManager;

impl RollbackManager {
    /// Store old value during rotation for later rollback
    pub fn prepare_rollback(
        entry: &mut SecretEntry,
        old_encrypted_value: &str,
        rollback_hours: u32,
    ) {
        let metadata = entry.rotation_metadata
            .get_or_insert_with(RotationMetadata::default);

        metadata.prev_value = Some(old_encrypted_value.to_string());
        metadata.prev_rotated = metadata.last_rotated.clone();
        metadata.rollback_until = Some(
            (Utc::now() + Duration::hours(rollback_hours as i64)).to_rfc3339()
        );
        metadata.post_rotation_checks = Vec::new();
    }

    /// Rollback to previous value
    pub fn rollback(
        vault: &mut Vault,
        key_name: &str,
        master_password: &str,
    ) -> Result<RollbackResult> {
        let entry = vault.entries.iter_mut()
            .find(|e| e.name == key_name)
            .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key_name))?;

        let metadata = entry.rotation_metadata.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key '{}' has no rotation metadata", key_name))?;

        let prev_value = metadata.prev_value.as_ref()
            .ok_or_else(|| anyhow::anyhow!(
                "Key '{}' has no previous value to rollback to", key_name
            ))?;

        // Check rollback window
        if let Some(until_str) = &metadata.rollback_until {
            let until = DateTime::parse_from_rfc3339(until_str)
                .context("Invalid rollback_until timestamp")?;
            if Utc::now() > until.with_timezone(&Utc) {
                bail!(
                    "Rollback window expired at {}. Previous value has been purged.",
                    until_str
                );
            }
        }

        // Swap current and previous values
        let current_value = entry.encrypted_value.clone();
        let current_preview = preview_encrypted(&current_value, master_password);
        let prev_preview = preview_encrypted(prev_value, master_password);

        entry.encrypted_value = prev_value.clone();

        // Update metadata
        let metadata = entry.rotation_metadata.as_mut().unwrap();
        metadata.prev_value = Some(current_value);
        metadata.prev_rotated = Some(Utc::now().to_rfc3339());
        metadata.last_rotated = metadata.prev_rotated.clone();
        metadata.rollback_until = Some(
            (Utc::now() + Duration::hours(24)).to_rfc3339()
        );

        vault.save()?;

        Ok(RollbackResult {
            key_name: key_name.to_string(),
            rolled_back: true,
            reason: "Manual rollback requested".to_string(),
            old_value_preview: current_preview,
            restored_value_preview: prev_preview,
        })
    }

    /// Check if a key has rollback available
    pub fn has_rollback(entry: &SecretEntry) -> bool {
        entry.rotation_metadata.as_ref()
            .and_then(|m| m.prev_value.as_ref())
            .is_some()
            && entry.rotation_metadata.as_ref()
                .and_then(|m| m.rollback_until.as_ref())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|until| Utc::now() < until.with_timezone(&Utc))
                .unwrap_or(false)
    }

    /// Record a post-rotation health check result
    pub fn record_check(
        entry: &mut SecretEntry,
        passed: bool,
        status_code: Option<u16>,
        response_time_ms: u64,
        error: Option<String>,
    ) {
        if let Some(metadata) = entry.rotation_metadata.as_mut() {
            metadata.post_rotation_checks.push(PostRotationCheck {
                timestamp: Utc::now().to_rfc3339(),
                passed,
                status_code,
                response_time_ms,
                error,
            });
        }
    }

    /// Auto-rollback if recent health checks are failing
    pub fn should_auto_rollback(entry: &SecretEntry) -> bool {
        let metadata = match &entry.rotation_metadata {
            Some(m) if m.auto_rollback => m,
            _ => return false,
        };

        let checks = &metadata.post_rotation_checks;
        if checks.len() < 3 {
            return false; // Need at least 3 checks before auto-rollback
        }

        // Auto-rollback if last 3 checks all failed
        checks.iter().rev().take(3).all(|c| !c.passed)
    }

    /// Purge expired rollback data from all entries
    pub fn purge_expired(vault: &mut Vault) -> usize {
        let now = Utc::now();
        let mut purged = 0;

        for entry in &mut vault.entries {
            if let Some(metadata) = entry.rotation_metadata.as_mut() {
                if let Some(until_str) = &metadata.rollback_until {
                    if let Ok(until) = DateTime::parse_from_rfc3339(until_str) {
                        if now > until.with_timezone(&Utc) {
                            metadata.prev_value = None;
                            metadata.prev_rotated = None;
                            metadata.rollback_until = None;
                            metadata.post_rotation_checks.clear();
                            purged += 1;
                        }
                    }
                }
            }
        }

        purged
    }
}

fn preview_encrypted(encrypted_value: &str, master_password: &str) -> String {
    // Decrypt and show first/last 4 chars
    match Vault::decrypt_value_static(encrypted_value, master_password) {
        Ok(value) if value.len() > 12 => {
            format!("{}...{}", &value[..4], &value[value.len()-4..])
        }
        Ok(value) => format!("{}...", &value[..value.len().min(4)]),
        Err(_) => "[decryption failed]".into(),
    }
}
```

## Dependencies

- No new dependencies
- Uses existing `chrono` for timestamp management
- Requires Feature 011 (Auto-Rotation Engine)
- Requires Feature 013 (Pre-Rotation Testing) for health checks

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_rollback_within_window() {
        let entry = create_entry_with_rollback(
            "KEY_1",
            Some("encrypted_prev"),
            Some((Utc::now() + Duration::hours(12)).to_rfc3339()),
        );
        assert!(RollbackManager::has_rollback(&entry));
    }

    #[test]
    fn test_has_rollback_expired() {
        let entry = create_entry_with_rollback(
            "KEY_1",
            Some("encrypted_prev"),
            Some((Utc::now() - Duration::hours(1)).to_rfc3339()),
        );
        assert!(!RollbackManager::has_rollback(&entry));
    }

    #[test]
    fn test_has_rollback_no_prev_value() {
        let entry = create_entry_with_rollback("KEY_1", None, None);
        assert!(!RollbackManager::has_rollback(&entry));
    }

    #[test]
    fn test_should_auto_rollback_after_3_failures() {
        let mut entry = create_entry_with_rollback("KEY_1", Some("prev"), Some(future_time()));
        entry.rotation_metadata.as_mut().unwrap().auto_rollback = true;

        for _ in 0..3 {
            RollbackManager::record_check(&mut entry, false, Some(500), 100, Some("Server error".into()));
        }

        assert!(RollbackManager::should_auto_rollback(&entry));
    }

    #[test]
    fn test_no_auto_rollback_with_passing_checks() {
        let mut entry = create_entry_with_rollback("KEY_1", Some("prev"), Some(future_time()));
        entry.rotation_metadata.as_mut().unwrap().auto_rollback = true;

        RollbackManager::record_check(&mut entry, false, Some(500), 100, None);
        RollbackManager::record_check(&mut entry, false, Some(500), 100, None);
        RollbackManager::record_check(&mut entry, true, Some(200), 50, None);

        assert!(!RollbackManager::should_auto_rollback(&entry));
    }

    #[test]
    fn test_purge_expired() {
        let mut vault = create_test_vault();
        // Add entry with expired rollback
        let mut entry = create_entry_with_rollback(
            "KEY_1", Some("prev"),
            Some((Utc::now() - Duration::hours(1)).to_rfc3339()),
        );
        vault.entries.push(entry);

        let purged = RollbackManager::purge_expired(&mut vault);
        assert_eq!(purged, 1);
        assert!(vault.entries[0].rotation_metadata.as_ref().unwrap().prev_value.is_none());
    }
}
```

### Manual Verification

1. Rotate a test key: `pqvault rotate TEST_KEY`
2. Verify rollback available: `pqvault rollback --status`
3. Rollback: `pqvault rollback TEST_KEY`
4. Verify old value is restored: `pqvault get TEST_KEY`
5. Wait for rollback window to expire, verify prev_value is purged

## Example Usage

```bash
# After a rotation, check rollback status
$ pqvault rollback --status
Keys with rollback available:
  STRIPE_SECRET_KEY  rotated 2h ago  rollback until: 22h from now
    Health checks: 3/3 passed
  GITHUB_TOKEN       rotated 5h ago  rollback until: 19h from now
    Health checks: 5/5 passed

# Rollback a key
$ pqvault rollback STRIPE_SECRET_KEY
Rolling back STRIPE_SECRET_KEY...
  Current value: sk_l...abc (will become rollback target)
  Previous value: sk_l...xyz (will become active)
  Confirm rollback? [y/N] y
Rolled back successfully. Old value is now active.

# Confirm rotation is good (purges old value early)
$ pqvault rollback STRIPE_SECRET_KEY --confirm
Confirming rotation of STRIPE_SECRET_KEY...
  Previous value purged. Rollback no longer available.
  Health checks: 8/8 passed over 6 hours.
Rotation confirmed.
```
