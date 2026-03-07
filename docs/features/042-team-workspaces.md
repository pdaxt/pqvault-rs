# Feature 042: Team Workspaces

## Status: Planned
## Phase: 5 (v2.5)
## Priority: High

## Problem

All keys exist in a single flat namespace with no separation of concerns. A startup with three products must store all keys in one vault, making it difficult to manage permissions, delegate ownership, or audit per-project usage. Teams cannot isolate their secrets from other teams, and there is no way to share a subset of keys without exposing the entire vault.

## Solution

Introduce team workspaces — separate encrypted vault partitions that can hold independent sets of keys. Each workspace has its own encryption envelope, membership list, and access policies. Keys can be shared across workspaces via explicit references. Users can belong to multiple workspaces with different roles in each. A "personal" workspace exists by default for individual secrets.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/workspace.rs` — Workspace CRUD and membership management
- `crates/pqvault-team-mcp/src/lib.rs` — Register workspace tools
- `crates/pqvault-core/src/workspace.rs` — Workspace storage and encryption isolation
- `crates/pqvault-core/src/models.rs` — Add workspace_id to key metadata

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Team workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub description: String,
    pub owner_id: String,
    pub created_at: DateTime<Utc>,
    pub members: Vec<WorkspaceMember>,
    pub settings: WorkspaceSettings,
    pub key_count: usize,
}

/// Workspace membership with role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub user_id: String,
    pub role: WorkspaceRole,
    pub joined_at: DateTime<Utc>,
    pub invited_by: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum WorkspaceRole {
    Owner,     // Full control including workspace deletion
    Admin,     // Manage members and keys
    Member,    // Read/write keys
    ReadOnly,  // View metadata only
}

/// Workspace-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    pub rotation_policy_days: Option<u32>,
    pub require_approval: bool,
    pub max_keys: Option<usize>,
    pub allowed_categories: Vec<String>,
    pub default_key_ttl_days: Option<u32>,
}

/// Cross-workspace key reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedKeyRef {
    pub source_workspace: String,
    pub source_key_name: String,
    pub target_workspace: String,
    pub alias: String,
    pub shared_by: String,
    pub shared_at: DateTime<Utc>,
    pub read_only: bool,
}

/// Workspace manager
pub struct WorkspaceManager {
    workspaces: HashMap<String, Workspace>,
    shared_refs: Vec<SharedKeyRef>,
}

impl WorkspaceManager {
    pub fn create(&mut self, name: &str, owner_id: &str) -> Workspace {
        let ws = Workspace {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            owner_id: owner_id.to_string(),
            created_at: Utc::now(),
            members: vec![WorkspaceMember {
                user_id: owner_id.to_string(),
                role: WorkspaceRole::Owner,
                joined_at: Utc::now(),
                invited_by: owner_id.to_string(),
            }],
            settings: WorkspaceSettings::default(),
            key_count: 0,
        };
        self.workspaces.insert(ws.id.clone(), ws.clone());
        ws
    }

    pub fn share_key(
        &mut self,
        source_ws: &str,
        key_name: &str,
        target_ws: &str,
        alias: &str,
        user_id: &str,
    ) -> Result<SharedKeyRef, String> {
        // Verify user has access to source workspace
        // Create cross-workspace reference
        let shared = SharedKeyRef {
            source_workspace: source_ws.to_string(),
            source_key_name: key_name.to_string(),
            target_workspace: target_ws.to_string(),
            alias: alias.to_string(),
            shared_by: user_id.to_string(),
            shared_at: Utc::now(),
            read_only: true,
        };
        self.shared_refs.push(shared.clone());
        Ok(shared)
    }
}
```

### MCP Tools

```rust
/// Create a new workspace
#[tool(name = "workspace_create")]
async fn workspace_create(
    &self,
    #[arg(description = "Workspace name")] name: String,
    #[arg(description = "Description")] description: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List workspaces the current user belongs to
#[tool(name = "workspace_list")]
async fn workspace_list(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Switch active workspace
#[tool(name = "workspace_switch")]
async fn workspace_switch(
    &self,
    #[arg(description = "Workspace name or ID")] workspace: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Add member to workspace
#[tool(name = "workspace_add_member")]
async fn workspace_add_member(
    &self,
    #[arg(description = "Workspace ID")] workspace_id: String,
    #[arg(description = "User ID to add")] user_id: String,
    #[arg(description = "Role: admin, member, readonly")] role: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Share a key to another workspace
#[tool(name = "workspace_share_key")]
async fn workspace_share_key(
    &self,
    #[arg(description = "Key name in current workspace")] key_name: String,
    #[arg(description = "Target workspace")] target_workspace: String,
    #[arg(description = "Alias in target workspace")] alias: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Create workspaces
pqvault workspace create --name "backend" --description "Backend services"
pqvault workspace create --name "frontend" --description "Frontend apps"
pqvault workspace create --name "infrastructure" --description "Infra keys"

# Switch workspace
pqvault workspace switch backend

# List workspaces
pqvault workspace list
# * backend (5 keys, 3 members) — active
#   frontend (8 keys, 2 members)
#   infrastructure (12 keys, 1 member)
#   personal (3 keys)

# Add member
pqvault workspace add-member --workspace backend --user alice --role member

# Share key across workspaces
pqvault workspace share --key DATABASE_URL --to frontend --alias SHARED_DB_URL

# Key operations are scoped to active workspace
pqvault list              # Lists keys in active workspace only
pqvault get STRIPE_KEY    # Gets from active workspace
pqvault set NEW_KEY val   # Stores in active workspace
```

### Web UI Changes

- Workspace switcher dropdown in navigation bar
- Workspace management page (create, settings, members)
- Shared keys panel showing cross-workspace references
- Per-workspace dashboard with isolated metrics

## Dependencies

- `uuid = "1"` (existing) — Workspace IDs
- `pqvault-core` (existing) — Storage partitioning
- Feature 041 (RBAC) — User management and roles

## Testing

### Unit Tests

```rust
#[test]
fn create_workspace_adds_owner() {
    let mut mgr = WorkspaceManager::new();
    let ws = mgr.create("test", "user1");
    assert_eq!(ws.members.len(), 1);
    assert_eq!(ws.members[0].role, WorkspaceRole::Owner);
}

#[test]
fn share_key_creates_reference() {
    let mut mgr = WorkspaceManager::new();
    mgr.create("ws1", "user1");
    mgr.create("ws2", "user1");
    let shared = mgr.share_key("ws1", "KEY1", "ws2", "SHARED_KEY1", "user1").unwrap();
    assert_eq!(shared.source_key_name, "KEY1");
    assert_eq!(shared.alias, "SHARED_KEY1");
    assert!(shared.read_only);
}

#[test]
fn workspace_role_hierarchy() {
    assert!(WorkspaceRole::Owner > WorkspaceRole::Admin);
    assert!(WorkspaceRole::Admin > WorkspaceRole::Member);
    assert!(WorkspaceRole::Member > WorkspaceRole::ReadOnly);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn keys_isolated_between_workspaces() {
    let mcp = test_team_mcp().await;
    mcp.workspace_create("ws1", None).await.unwrap();
    mcp.workspace_create("ws2", None).await.unwrap();

    mcp.workspace_switch("ws1").await.unwrap();
    mcp.vault_set("KEY_A", "value_a").await.unwrap();

    mcp.workspace_switch("ws2").await.unwrap();
    assert!(mcp.vault_get("KEY_A").await.is_err()); // Not visible in ws2
}

#[tokio::test]
async fn shared_key_accessible_in_target_workspace() {
    let mcp = test_team_mcp().await;
    mcp.workspace_create("ws1", None).await.unwrap();
    mcp.workspace_create("ws2", None).await.unwrap();

    mcp.workspace_switch("ws1").await.unwrap();
    mcp.vault_set("SHARED_KEY", "shared_value").await.unwrap();
    mcp.workspace_share_key("SHARED_KEY", "ws2", Some("ALIAS_KEY")).await.unwrap();

    mcp.workspace_switch("ws2").await.unwrap();
    let value = mcp.vault_get("ALIAS_KEY").await.unwrap();
    assert_eq!(value, "shared_value");
}
```

### Manual Verification

1. Create two workspaces with different members
2. Store keys in each workspace
3. Verify keys are isolated between workspaces
4. Share a key from workspace A to workspace B
5. Verify the shared key is accessible in workspace B as read-only

## Example Usage

```bash
# Team structure:
# backend team → backend workspace (DB keys, API keys)
# frontend team → frontend workspace (analytics keys, CDN keys)
# shared → database URL needed by both

pqvault workspace create --name backend
pqvault workspace create --name frontend

# Backend team adds their keys
pqvault workspace switch backend
pqvault set DATABASE_URL "postgres://..."
pqvault set REDIS_URL "redis://..."

# Share database URL with frontend
pqvault workspace share --key DATABASE_URL --to frontend --alias BACKEND_DB_URL

# Frontend can read but not modify
pqvault workspace switch frontend
pqvault get BACKEND_DB_URL  # OK (read-only)
pqvault set BACKEND_DB_URL "new" # DENIED (read-only share)
```
