# Feature 036: Dead Key Detection

## Status: Planned
## Phase: 4 (v2.4)
## Priority: Medium

## Problem

The vault accumulates abandoned keys indefinitely. Projects get decommissioned, services get replaced, API keys for trials expire — but the keys remain in the vault, cluttering the list and potentially representing a security liability. Keys that haven't been used in months are invisible among active keys, and there is no mechanism to identify or clean them up.

## Solution

Flag keys that have not been accessed (read or proxied) for a configurable period (default: 180 days). Dead keys appear in a dedicated report with options to archive (remove from active list but keep encrypted backup) or permanently delete. An optional auto-archive policy can be configured per category or globally to automatically archive keys after their inactivity period expires.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/dead_keys.rs` — Dead key detection and archival logic
- `crates/pqvault-health-mcp/src/lib.rs` — Register dead key tools
- `crates/pqvault-core/src/archive.rs` — Key archival and restoration
- `crates/pqvault-core/src/models.rs` — Add `last_accessed` and `archived` fields

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Dead key detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadKeyReport {
    pub key_name: String,
    pub last_accessed: Option<DateTime<Utc>>,
    pub days_inactive: u64,
    pub category: Option<String>,
    pub created_at: DateTime<Utc>,
    pub total_lifetime_accesses: u64,
    pub recommendation: DeadKeyAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeadKeyAction {
    Archive,   // Safe to archive — has not been used
    Review,    // Was active once, now dormant — review before archiving
    Keep,      // Below threshold, still potentially active
}

/// Archived key record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedKey {
    pub key_name: String,
    pub encrypted_value: Vec<u8>,
    pub metadata: KeyMetadata,
    pub archived_at: DateTime<Utc>,
    pub archived_reason: String,
    pub original_created_at: DateTime<Utc>,
    pub total_accesses: u64,
}

/// Dead key policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadKeyPolicy {
    /// Days of inactivity before flagging (default: 180)
    pub inactivity_threshold_days: u64,
    /// Auto-archive after this many days (0 = disabled)
    pub auto_archive_days: u64,
    /// Categories exempt from dead key detection
    pub exempt_categories: Vec<String>,
    /// Keys exempt by name pattern
    pub exempt_patterns: Vec<String>,
}

impl Default for DeadKeyPolicy {
    fn default() -> Self {
        Self {
            inactivity_threshold_days: 180,
            auto_archive_days: 0,
            exempt_categories: vec!["infrastructure".into()],
            exempt_patterns: vec![],
        }
    }
}

/// Dead key detector
pub struct DeadKeyDetector {
    policy: DeadKeyPolicy,
}

impl DeadKeyDetector {
    pub fn detect(&self, keys: &[KeyMetadata]) -> Vec<DeadKeyReport> {
        let now = Utc::now();
        keys.iter()
            .filter(|k| !self.is_exempt(k))
            .filter_map(|k| {
                let days_inactive = k.last_accessed
                    .map(|la| (now - la).num_days() as u64)
                    .unwrap_or(
                        (now - k.created_at).num_days() as u64
                    );

                if days_inactive >= self.policy.inactivity_threshold_days {
                    let recommendation = if k.total_accesses == 0 {
                        DeadKeyAction::Archive
                    } else {
                        DeadKeyAction::Review
                    };

                    Some(DeadKeyReport {
                        key_name: k.name.clone(),
                        last_accessed: k.last_accessed,
                        days_inactive,
                        category: k.category.clone(),
                        created_at: k.created_at,
                        total_lifetime_accesses: k.total_accesses,
                        recommendation,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn is_exempt(&self, key: &KeyMetadata) -> bool {
        if let Some(ref cat) = key.category {
            if self.policy.exempt_categories.contains(cat) {
                return true;
            }
        }
        self.policy.exempt_patterns.iter().any(|p| key.name.contains(p))
    }
}
```

### MCP Tools

```rust
/// Detect dead keys in the vault
#[tool(name = "detect_dead_keys")]
async fn detect_dead_keys(
    &self,
    #[arg(description = "Inactivity threshold in days")] threshold_days: Option<u64>,
    #[arg(description = "Include exempt keys")] include_exempt: Option<bool>,
) -> Result<CallToolResult, McpError> {
    let mut policy = self.dead_key_policy.clone();
    if let Some(days) = threshold_days {
        policy.inactivity_threshold_days = days;
    }
    let detector = DeadKeyDetector { policy };
    let keys = self.vault.list_metadata().await?;
    let dead = detector.detect(&keys);

    if dead.is_empty() {
        return Ok(CallToolResult::success("No dead keys detected."));
    }

    let output = dead.iter().map(|d| {
        format!(
            "{}: {} days inactive (last: {}, total accesses: {}) → {:?}",
            d.key_name, d.days_inactive,
            d.last_accessed.map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or("never".into()),
            d.total_lifetime_accesses, d.recommendation
        )
    }).collect::<Vec<_>>().join("\n");

    Ok(CallToolResult::success(format!("{} dead keys found:\n{}", dead.len(), output)))
}

/// Archive a dead key
#[tool(name = "archive_key")]
async fn archive_key(
    &self,
    #[arg(description = "Key name to archive")] key_name: String,
    #[arg(description = "Reason for archiving")] reason: String,
) -> Result<CallToolResult, McpError> {
    // Implementation: move to archive, remove from active vault
}

/// Restore an archived key
#[tool(name = "restore_key")]
async fn restore_key(
    &self,
    #[arg(description = "Key name to restore")] key_name: String,
) -> Result<CallToolResult, McpError> {
    // Implementation: move from archive back to active vault
}

/// List archived keys
#[tool(name = "list_archived")]
async fn list_archived(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Detect dead keys
pqvault health dead-keys
# 3 dead keys found:
# OLD_TRIAL_KEY: 340 days inactive (last: never, total accesses: 0) → Archive
# DEPRECATED_API: 210 days inactive (last: 2025-08-01, total accesses: 145) → Review
# TEST_KEY_2024: 195 days inactive (last: 2025-09-15, total accesses: 3) → Review

# Custom threshold
pqvault health dead-keys --threshold 90

# Archive a key
pqvault archive OLD_TRIAL_KEY --reason "Trial expired, never used"

# List archived keys
pqvault archive list

# Restore a key
pqvault archive restore OLD_TRIAL_KEY

# Configure auto-archive
pqvault config set dead_keys.auto_archive_days 365
pqvault config set dead_keys.exempt_categories '["infrastructure", "backup"]'
```

### Web UI Changes

- "Dead Keys" tab on health dashboard with sortable list
- Archive/Restore buttons per key
- "Graveyard" view showing archived keys with restoration option
- Auto-archive countdown display for keys approaching threshold

## Dependencies

- `pqvault-core` (existing) — Key metadata and storage
- `chrono = "0.4"` (existing) — Date calculations
- `glob = "0.3"` — Pattern matching for exempt patterns (optional)

## Testing

### Unit Tests

```rust
#[test]
fn detects_never_accessed_key() {
    let detector = DeadKeyDetector { policy: DeadKeyPolicy::default() };
    let keys = vec![KeyMetadata {
        name: "OLD_KEY".into(),
        created_at: Utc::now() - chrono::Duration::days(200),
        last_accessed: None,
        total_accesses: 0,
        ..Default::default()
    }];
    let dead = detector.detect(&keys);
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].recommendation, DeadKeyAction::Archive);
}

#[test]
fn respects_exempt_categories() {
    let detector = DeadKeyDetector {
        policy: DeadKeyPolicy {
            exempt_categories: vec!["infrastructure".into()],
            ..Default::default()
        }
    };
    let keys = vec![KeyMetadata {
        name: "INFRA_KEY".into(),
        category: Some("infrastructure".into()),
        created_at: Utc::now() - chrono::Duration::days(400),
        last_accessed: None,
        total_accesses: 0,
        ..Default::default()
    }];
    let dead = detector.detect(&keys);
    assert!(dead.is_empty());
}

#[test]
fn active_key_not_flagged() {
    let detector = DeadKeyDetector { policy: DeadKeyPolicy::default() };
    let keys = vec![KeyMetadata {
        name: "ACTIVE_KEY".into(),
        last_accessed: Some(Utc::now() - chrono::Duration::days(5)),
        ..Default::default()
    }];
    let dead = detector.detect(&keys);
    assert!(dead.is_empty());
}
```

### Integration Tests

```rust
#[tokio::test]
async fn archive_and_restore_roundtrip() {
    let mcp = test_health_mcp().await;
    mcp.vault.store("KEY1", "secret_value").await.unwrap();
    mcp.archive_key("KEY1", "test archival").await.unwrap();

    // Key should not be in active list
    assert!(mcp.vault.get("KEY1").await.is_err());

    // Key should be in archive
    let archived = mcp.list_archived().await.unwrap();
    assert!(archived.contains("KEY1"));

    // Restore
    mcp.restore_key("KEY1").await.unwrap();
    let value = mcp.vault.get("KEY1").await.unwrap();
    assert_eq!(value, "secret_value");
}
```

### Manual Verification

1. Create a key and don't access it for 180+ days (or set threshold to 1 day for testing)
2. Run dead key detection and verify it appears
3. Archive the key and verify it is no longer in active list
4. Restore the key and verify the value is preserved
5. Check that archived keys remain encrypted

## Example Usage

```bash
# Weekly cleanup workflow:
pqvault health dead-keys --threshold 180
# Review list, archive confirmed dead keys:
pqvault archive OLD_TRIAL_KEY --reason "Trial expired"
pqvault archive DEPRECATED_V1_KEY --reason "V1 API decommissioned"

# Automated monthly cleanup (auto-archive after 365 days):
pqvault config set dead_keys.auto_archive_days 365
# Keys untouched for a year are automatically archived with reason "auto-archived"
```
