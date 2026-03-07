# Feature 068: pqvault history

## Status: Done
## Phase: 7 (v2.7)
## Priority: Medium

## Problem

When a secret value causes a production issue, teams need to answer: "What was the
previous value?", "Who changed it?", and "When was it changed?". Currently PQVault
stores only the current value. Without history, rollback requires manual detective
work, and there is no accountability for secret changes.

## Solution

Implement `pqvault history KEY` which displays all historical versions of a secret
with timestamps, change actors, and change reasons. This depends on Feature 017
(Secret Versioning) for the underlying storage. The CLI displays versions in reverse
chronological order and supports rollback to any previous version.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      history.rs       # History command and output formatting
    history/
      mod.rs           # History query engine
      display.rs       # Terminal-friendly history formatting
      rollback.rs      # Rollback to a previous version

pqvault-core/
  src/
    versioning.rs      # Version storage (from Feature 017, extended)
```

### Data Model Changes

```rust
/// A single version entry for a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Auto-incrementing version number
    pub version: u32,
    /// Encrypted value at this version
    pub encrypted_value: Vec<u8>,
    /// Value hash for comparison without decryption
    pub value_hash: String,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Who made the change
    pub actor: ChangeActor,
    /// Why the change was made
    pub reason: ChangeReason,
    /// Source of the change
    pub source: ChangeSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeActor {
    User(String),        // Username or email
    Cli,                 // CLI command
    Mcp(String),         // MCP tool name
    AutoRotation,        // Scheduled rotation
    Sync(String),        // Sync from platform
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeReason {
    Created,
    ManualUpdate,
    Rotation,
    BulkOperation(String),
    Sync(String),
    Rollback { from_version: u32 },
    Import,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeSource {
    Cli { command: String },
    Mcp { tool: String },
    Web,
    Api,
}

/// Query parameters for history retrieval
pub struct HistoryQuery {
    pub key: String,
    pub limit: Option<usize>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub actor: Option<String>,
}

pub struct HistoryResult {
    pub key: String,
    pub current_version: u32,
    pub versions: Vec<SecretVersion>,
    pub total_versions: usize,
}
```

### MCP Tools

No new MCP tools for history display. The `pqvault-audit-mcp` already provides
audit log access. History is a CLI convenience wrapper over versioning data.

### CLI Commands

```bash
# Show history for a key
pqvault history STRIPE_SECRET_KEY

# Show last N versions
pqvault history DATABASE_URL --limit 5

# Show changes since a date
pqvault history API_KEY --since 2025-01-01

# Show the value at a specific version
pqvault history STRIPE_SECRET_KEY --version 3 --show-value

# Compare two versions
pqvault history STRIPE_SECRET_KEY --diff 2 5

# Rollback to a previous version
pqvault history STRIPE_SECRET_KEY --rollback 3

# Output as JSON
pqvault history API_KEY --format json
```

Command definition:

```rust
#[derive(Args)]
pub struct HistoryArgs {
    /// Key name
    pub key: String,

    /// Maximum number of versions to show
    #[arg(long)]
    limit: Option<usize>,

    /// Show changes since this date
    #[arg(long)]
    since: Option<String>,

    /// Show changes until this date
    #[arg(long)]
    until: Option<String>,

    /// Show value at specific version
    #[arg(long)]
    version: Option<u32>,

    /// Show decrypted value (requires auth)
    #[arg(long, default_value_t = false)]
    show_value: bool,

    /// Compare two versions
    #[arg(long, num_args = 2)]
    diff: Option<Vec<u32>>,

    /// Rollback to version N
    #[arg(long)]
    rollback: Option<u32>,

    /// Output format
    #[arg(long, default_value = "table")]
    format: OutputFormat,
}
```

### Web UI Changes

None directly. Feature 082 (Key Detail Page) will use history data in the web UI.

## Dependencies

Requires Feature 017 (Secret Versioning) to be implemented first. No new crate
dependencies beyond what Feature 017 introduces.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_ordering() {
        let versions = vec![
            version(1, "2025-01-01T00:00:00Z"),
            version(3, "2025-03-01T00:00:00Z"),
            version(2, "2025-02-01T00:00:00Z"),
        ];
        let sorted = sort_versions_desc(versions);
        assert_eq!(sorted[0].version, 3);
        assert_eq!(sorted[1].version, 2);
        assert_eq!(sorted[2].version, 1);
    }

    #[test]
    fn test_history_query_since() {
        let versions = vec![
            version(1, "2025-01-01T00:00:00Z"),
            version(2, "2025-02-01T00:00:00Z"),
            version(3, "2025-03-01T00:00:00Z"),
        ];
        let query = HistoryQuery {
            key: "KEY".into(),
            since: Some(parse_dt("2025-02-01T00:00:00Z")),
            ..Default::default()
        };
        let filtered = apply_query_filters(&versions, &query);
        assert_eq!(filtered.len(), 2); // versions 2 and 3
    }

    #[test]
    fn test_history_limit() {
        let versions: Vec<_> = (1..=20).map(|i| version(i, &format!("2025-01-{:02}T00:00:00Z", i))).collect();
        let query = HistoryQuery { key: "KEY".into(), limit: Some(5), ..Default::default() };
        let filtered = apply_query_filters(&versions, &query);
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_version_diff() {
        let v2 = SecretVersion { version: 2, value_hash: "abc123".into(), ..mock_version() };
        let v5 = SecretVersion { version: 5, value_hash: "def456".into(), ..mock_version() };
        let diff = diff_versions(&v2, &v5);
        assert!(diff.value_changed);
        assert_eq!(diff.version_span, 3);
    }

    #[test]
    fn test_change_actor_display() {
        assert_eq!(ChangeActor::User("alice@co.com".into()).to_string(), "alice@co.com");
        assert_eq!(ChangeActor::AutoRotation.to_string(), "auto-rotation");
        assert_eq!(ChangeActor::Mcp("vault_rotate".into()).to_string(), "mcp:vault_rotate");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_history_multiple_versions() {
    let vault = empty_test_vault().await;
    vault.set("API_KEY", "v1").await.unwrap();
    vault.set("API_KEY", "v2").await.unwrap();
    vault.set("API_KEY", "v3").await.unwrap();
    let history = vault.history("API_KEY", &HistoryQuery::default()).await.unwrap();
    assert_eq!(history.versions.len(), 3);
    assert_eq!(history.current_version, 3);
}

#[tokio::test]
async fn test_rollback_to_version() {
    let vault = empty_test_vault().await;
    vault.set("KEY", "original").await.unwrap();
    vault.set("KEY", "changed").await.unwrap();
    vault.rollback("KEY", 1).await.unwrap();
    let current = vault.get("KEY").await.unwrap();
    assert_eq!(current.value, "original");
    // Rollback creates version 3, not overwrites version 2
    let history = vault.history("KEY", &HistoryQuery::default()).await.unwrap();
    assert_eq!(history.current_version, 3);
}
```

## Example Usage

```
$ pqvault history STRIPE_SECRET_KEY

  History: STRIPE_SECRET_KEY (7 versions)
  ────────────────────────────────────────────────────────

  Ver  Date                 Actor              Reason          Value
  ───  ───────────────────  ─────────────────  ──────────────  ────────
  7*   2025-03-15 14:30     auto-rotation      rotation        sk_live_██Q9
  6    2025-02-01 09:15     alice@team.com     manual update   sk_live_██K7
  5    2025-01-15 11:00     auto-rotation      rotation        sk_live_██M3
  4    2024-12-01 16:45     auto-rotation      rotation        sk_live_██P1
  3    2024-10-20 08:30     bob@team.com       manual update   sk_live_██R5
  2    2024-09-01 10:00     cli                bulk operation  sk_live_██T2
  1    2024-07-15 12:00     cli                created         sk_live_██W8

  * = current version

$ pqvault history STRIPE_SECRET_KEY --rollback 5
  Rollback STRIPE_SECRET_KEY from v7 to v5?
  Current: sk_live_██Q9 (set 2025-03-15)
  Target:  sk_live_██M3 (set 2025-01-15)
  [y/N]: y
  Rolled back to v5. New version: v8.
```
