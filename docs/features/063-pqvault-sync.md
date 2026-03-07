# Feature 063: pqvault sync

## Status: Planned
## Phase: 7 (v2.7)
## Priority: High

## Problem

Developers manage secrets in PQVault locally but must manually copy them to cloud
platforms like Vercel, Netlify, and Railway for deployment. This manual step is
error-prone, creates drift between local and deployed secrets, and means there is
no single source of truth. When a key is rotated in PQVault, engineers forget to
update the cloud platform, causing outages.

## Solution

Build a bidirectional sync engine that pushes and pulls secrets between PQVault and
cloud platforms. Each platform gets a connector implementing a common trait. The sync
is explicit (not automatic) and shows a diff before applying changes. Sync state is
tracked to detect conflicts and prevent accidental overwrites.

## Implementation

### Files to Create/Modify

```
pqvault-sync-mcp/
  src/
    lib.rs               # MCP tool registration
    sync/
      mod.rs             # Sync engine orchestration
      engine.rs          # Core sync algorithm with conflict resolution
      state.rs           # Sync state tracking (last sync timestamps)
    connectors/
      mod.rs             # Connector trait definition
      vercel.rs          # Vercel API connector (env vars)
      netlify.rs         # Netlify API connector (env vars)
      railway.rs         # Railway API connector (variables)
    tools/
      sync_push.rs       # MCP tool: push to platform
      sync_pull.rs       # MCP tool: pull from platform
      sync_status.rs     # MCP tool: show sync state

pqvault-cli/
  src/
    commands/
      sync.rs            # CLI subcommand for sync operations
```

### Data Model Changes

```rust
/// Platform connector trait — implement for each cloud platform
#[async_trait]
pub trait PlatformConnector: Send + Sync {
    /// Platform identifier
    fn platform_name(&self) -> &str;

    /// List all environment variables on the platform
    async fn list_vars(&self, project: &str, env: &str) -> Result<Vec<RemoteVar>>;

    /// Set an environment variable
    async fn set_var(&self, project: &str, env: &str, key: &str, value: &str) -> Result<()>;

    /// Delete an environment variable
    async fn delete_var(&self, project: &str, env: &str, key: &str) -> Result<()>;

    /// Validate credentials
    async fn validate_auth(&self) -> Result<()>;
}

pub struct RemoteVar {
    pub key: String,
    pub value: String,
    pub target: Vec<String>,   // ["production", "preview", "development"]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Tracks sync state between vault and platform
pub struct SyncState {
    pub platform: String,
    pub project: String,
    pub environment: String,
    pub last_sync: DateTime<Utc>,
    pub key_hashes: HashMap<String, String>,  // key -> SHA-256(value) at last sync
    pub direction: SyncDirection,
}

pub enum SyncDirection {
    Push,   // Vault → Platform
    Pull,   // Platform → Vault
    Both,   // Bidirectional
}

pub struct SyncPlan {
    pub actions: Vec<SyncAction>,
    pub conflicts: Vec<SyncConflict>,
}

pub enum SyncAction {
    PushCreate { key: String },
    PushUpdate { key: String },
    PushDelete { key: String },
    PullCreate { key: String },
    PullUpdate { key: String },
    PullDelete { key: String },
}

pub struct SyncConflict {
    pub key: String,
    pub vault_hash: String,
    pub remote_hash: String,
    pub last_sync_hash: String,
    pub resolution: Option<ConflictResolution>,
}

pub enum ConflictResolution {
    UseVault,
    UseRemote,
    Skip,
}
```

### MCP Tools

```rust
#[tool(description = "Push secrets from vault to a cloud platform")]
async fn sync_push(
    /// Platform name: vercel, netlify, railway
    platform: String,
    /// Project identifier on the platform
    project: String,
    /// Target environment: production, preview, development
    #[arg(default = "production")]
    environment: String,
    /// Only sync specific keys (comma-separated)
    keys: Option<String>,
    /// Dry run — show plan without executing
    #[arg(default = false)]
    dry_run: bool,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Pull secrets from a cloud platform into vault")]
async fn sync_pull(
    platform: String,
    project: String,
    #[arg(default = "production")]
    environment: String,
    /// Overwrite existing vault keys if they differ
    #[arg(default = false)]
    overwrite: bool,
    #[arg(default = false)]
    dry_run: bool,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Show sync status between vault and platform")]
async fn sync_status(
    platform: String,
    project: String,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Push all secrets to Vercel production
pqvault sync push vercel --project my-app --env production

# Dry run first (recommended)
pqvault sync push vercel --project my-app --env production --dry-run

# Pull from Netlify into vault
pqvault sync pull netlify --project site-xyz --env production

# Push only specific keys
pqvault sync push railway --project api --keys STRIPE_KEY,DB_URL

# Show sync status
pqvault sync status vercel --project my-app

# Configure platform credentials
pqvault sync auth vercel  # Opens browser for OAuth or prompts for token
```

### Web UI Changes

None in this phase. Future web UI could show sync status per platform.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reqwest` | 0.12 | HTTP client for platform APIs (already in workspace) |
| `serde_json` | 1 | JSON parsing for API responses (already in workspace) |

Platform API references:
- Vercel: `https://api.vercel.com/v10/projects/{id}/env`
- Netlify: `https://api.netlify.com/api/v1/accounts/{id}/env`
- Railway: GraphQL API at `https://backboard.railway.app/graphql/v2`

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_plan_push_new_keys() {
        let vault_keys = vec![kv("A", "1"), kv("B", "2")];
        let remote_keys = vec![kv("A", "1")];
        let state = SyncState::empty();
        let plan = compute_sync_plan(&vault_keys, &remote_keys, &state, SyncDirection::Push);
        assert_eq!(plan.actions.len(), 1);
        assert!(matches!(plan.actions[0], SyncAction::PushCreate { ref key } if key == "B"));
    }

    #[test]
    fn test_sync_detects_conflict() {
        let vault_keys = vec![kv("API_KEY", "vault_val")];
        let remote_keys = vec![kv("API_KEY", "remote_val")];
        let state = SyncState::with_hash("API_KEY", "old_hash");
        let plan = compute_sync_plan(&vault_keys, &remote_keys, &state, SyncDirection::Both);
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "API_KEY");
    }

    #[test]
    fn test_sync_plan_no_changes() {
        let keys = vec![kv("A", "1"), kv("B", "2")];
        let plan = compute_sync_plan(&keys, &keys, &SyncState::empty(), SyncDirection::Push);
        assert!(plan.actions.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn test_key_filter() {
        let vault_keys = vec![kv("A", "1"), kv("B", "2"), kv("C", "3")];
        let filter = KeyFilter::only(&["A", "C"]);
        let filtered = filter.apply(&vault_keys);
        assert_eq!(filtered.len(), 2);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_vercel_connector_list_vars() {
    let connector = VercelConnector::new_mock(vec![
        RemoteVar { key: "DB_URL".into(), value: "postgres://...".into(), ..Default::default() },
    ]);
    let vars = connector.list_vars("proj-123", "production").await.unwrap();
    assert_eq!(vars.len(), 1);
    assert_eq!(vars[0].key, "DB_URL");
}

#[tokio::test]
async fn test_full_push_sync() {
    let vault = test_vault_with_keys(&[("KEY_A", "val_a"), ("KEY_B", "val_b")]).await;
    let connector = MockConnector::empty();
    let result = sync_push(&vault, &connector, "proj", "production", None, false).await.unwrap();
    assert_eq!(result.pushed, 2);
    assert_eq!(connector.vars().await.len(), 2);
}
```

## Example Usage

```
$ pqvault sync push vercel --project my-saas --env production --dry-run

  Sync Plan: vault → Vercel (my-saas/production)
  ────────────────────────────────────────────────

  Action   Key                    Details
  ──────   ─────────────────────  ─────────────────
  CREATE   STRIPE_SECRET_KEY      New key (not on Vercel)
  UPDATE   DATABASE_URL           Value changed since last sync
  SKIP     AWS_ACCESS_KEY_ID      Identical
  SKIP     AWS_SECRET_KEY         Identical

  Summary: 1 create, 1 update, 2 unchanged
  Run without --dry-run to apply.

$ pqvault sync push vercel --project my-saas --env production

  Syncing vault → Vercel (my-saas/production)...
  ✓ Created STRIPE_SECRET_KEY
  ✓ Updated DATABASE_URL
  Sync complete: 2 changes applied.
```
