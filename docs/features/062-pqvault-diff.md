# Feature 062: pqvault diff

## Status: Planned
## Phase: 7 (v2.7)
## Priority: High

## Problem

Teams maintain separate vaults for development, staging, and production environments.
When deploying, engineers need to verify that all required secrets exist in the target
environment and that values haven't drifted. Currently there is no way to compare two
vaults or two environments side-by-side, leading to deployment failures from missing
or stale secrets.

## Solution

Implement a `pqvault diff` command that compares secrets across environments, vaults,
or snapshots. The output uses a familiar git-diff style format showing added, removed,
and changed keys. Values are never shown in plaintext — only metadata (exists/missing,
last-rotated, provider) is compared unless `--show-values` is explicitly passed.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      diff.rs          # Core diff logic and output formatting
    diff/
      mod.rs           # Diff engine module root
      compare.rs       # Key-by-key comparison engine
      source.rs        # DiffSource trait (vault, env file, remote)
      formatter.rs     # Output formatters (table, json, patch)
```

### Data Model Changes

```rust
/// Represents one side of a diff comparison
pub enum DiffSource {
    /// Local vault at a path
    Vault(PathBuf),
    /// Environment name in multi-env vault
    Environment(String),
    /// .env file
    EnvFile(PathBuf),
    /// Remote platform (Vercel, Netlify, etc.)
    Remote { platform: String, project: String },
    /// Snapshot from a specific point in time
    Snapshot { vault: PathBuf, timestamp: DateTime<Utc> },
}

/// Result of comparing a single key across two sources
#[derive(Debug)]
pub enum KeyDiff {
    /// Key exists only in the left source
    OnlyLeft(KeyMeta),
    /// Key exists only in the right source
    OnlyRight(KeyMeta),
    /// Key exists in both but differs
    Changed {
        left: KeyMeta,
        right: KeyMeta,
        changes: Vec<FieldChange>,
    },
    /// Key is identical in both sources
    Identical(KeyMeta),
}

#[derive(Debug)]
pub struct FieldChange {
    pub field: String,       // "value", "provider", "rotated_at"
    pub left_val: String,
    pub right_val: String,
}

#[derive(Debug)]
pub struct KeyMeta {
    pub name: String,
    pub provider: Option<String>,
    pub category: Option<String>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub value_hash: String,  // SHA-256 of value for comparison without exposure
}

pub struct DiffResult {
    pub left_label: String,
    pub right_label: String,
    pub diffs: Vec<KeyDiff>,
    pub summary: DiffSummary,
}

pub struct DiffSummary {
    pub total_left: usize,
    pub total_right: usize,
    pub only_left: usize,
    pub only_right: usize,
    pub changed: usize,
    pub identical: usize,
}
```

### MCP Tools

No new MCP tools. Diff is a read-only CLI operation. If `pqvault-sync-mcp` is
available, the diff engine can use its connectors to fetch remote state for
comparison against platforms like Vercel or Netlify.

### CLI Commands

```bash
# Compare two environments in the same vault
pqvault diff prod staging

# Compare local vault with a .env file
pqvault diff --vault ./vault --env-file .env.production

# Compare current vault state with a historical snapshot
pqvault diff --snapshot 2025-01-15

# Only show differences (hide identical keys)
pqvault diff prod staging --changes-only

# Output as JSON for scripting
pqvault diff prod staging --format json

# Include value comparison (requires auth)
pqvault diff prod staging --show-values

# Exit with code 1 if differences found (for CI)
pqvault diff prod staging --exit-code
```

Command definition:

```rust
#[derive(Args)]
pub struct DiffArgs {
    /// Left side: environment name, vault path, or .env file
    pub left: String,

    /// Right side: environment name, vault path, or .env file
    pub right: Option<String>,

    /// Path to vault (if not using default)
    #[arg(long)]
    vault: Option<PathBuf>,

    /// Compare against a .env file
    #[arg(long)]
    env_file: Option<PathBuf>,

    /// Compare against a historical snapshot
    #[arg(long)]
    snapshot: Option<String>,

    /// Only show keys that differ
    #[arg(long, default_value_t = false)]
    changes_only: bool,

    /// Show actual values (requires re-authentication)
    #[arg(long, default_value_t = false)]
    show_values: bool,

    /// Output format: table, json, patch
    #[arg(long, default_value = "table")]
    format: OutputFormat,

    /// Exit with code 1 if differences exist
    #[arg(long, default_value_t = false)]
    exit_code: bool,
}
```

### Web UI Changes

None in this phase. Feature 092 (Impact Analysis) will add a web-based diff view later.

## Dependencies

No new crate dependencies. Uses existing `pqvault-core` for vault access and
standard library for comparison logic. The `similar` crate could be added later
for value-level diffing if `--show-values` needs inline highlighting.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_identical_vaults() {
        let left = mock_keys(&["API_KEY", "DB_URL"]);
        let right = mock_keys(&["API_KEY", "DB_URL"]);
        let result = compute_diff(&left, &right);
        assert_eq!(result.summary.identical, 2);
        assert_eq!(result.summary.changed, 0);
        assert_eq!(result.summary.only_left, 0);
    }

    #[test]
    fn test_diff_missing_key() {
        let left = mock_keys(&["API_KEY", "DB_URL", "REDIS_URL"]);
        let right = mock_keys(&["API_KEY", "DB_URL"]);
        let result = compute_diff(&left, &right);
        assert_eq!(result.summary.only_left, 1);
        assert!(matches!(result.diffs[2], KeyDiff::OnlyLeft(_)));
    }

    #[test]
    fn test_diff_changed_value() {
        let mut left = mock_keys(&["API_KEY"]);
        let mut right = mock_keys(&["API_KEY"]);
        right[0].value_hash = "different_hash".to_string();
        let result = compute_diff(&left, &right);
        assert_eq!(result.summary.changed, 1);
    }

    #[test]
    fn test_diff_exit_code() {
        let left = mock_keys(&["A"]);
        let right = mock_keys(&["A", "B"]);
        let result = compute_diff(&left, &right);
        assert!(result.has_differences());
    }

    #[test]
    fn test_diff_json_output() {
        let left = mock_keys(&["KEY_A"]);
        let right = mock_keys(&[]);
        let result = compute_diff(&left, &right);
        let json = format_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["summary"]["only_left"], 1);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_diff_two_vault_dirs() {
    let vault_a = create_test_vault(&[("KEY", "val1")]).await;
    let vault_b = create_test_vault(&[("KEY", "val2")]).await;
    let result = diff_vaults(&vault_a, &vault_b).await.unwrap();
    assert_eq!(result.summary.changed, 1);
}

#[tokio::test]
async fn test_diff_vault_vs_env_file() {
    let vault = create_test_vault(&[("API_KEY", "sk_live_123")]).await;
    let env_file = create_temp_env_file("API_KEY=sk_test_456\nEXTRA=foo\n");
    let result = diff_vault_envfile(&vault, &env_file).await.unwrap();
    assert_eq!(result.summary.changed, 1); // API_KEY value differs
    assert_eq!(result.summary.only_right, 1); // EXTRA only in .env
}
```

## Example Usage

```
$ pqvault diff prod staging

  PQVault Diff: prod ↔ staging
  ─────────────────────────────────────────────

  Key                     prod          staging       Status
  ──────────────────────  ────────────  ────────────  ──────
  STRIPE_SECRET_KEY       sk_live_██    sk_test_██    CHANGED
  DATABASE_URL            ████████████  ████████████  CHANGED
  AWS_ACCESS_KEY_ID       AKIA████████  AKIA████████  identical
  REDIS_URL               ████████████  (missing)     ONLY LEFT
  SENTRY_DSN              (missing)     ████████████  ONLY RIGHT

  Summary: 2 changed, 1 identical, 1 only in prod, 1 only in staging
  Total: 5 unique keys across both environments

$ echo $?
1
```
