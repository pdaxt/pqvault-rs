# Feature 041: Multi-User RBAC

## Status: Planned
## Phase: 5 (v2.5)
## Priority: Critical

## Problem

PQVault is currently a single-user vault with no access control. Anyone who can reach the vault endpoint has full access to all keys. This makes it unsuitable for teams where different members should have different levels of access. A junior developer should not be able to delete production keys, and a viewer should not be able to read secrets — but currently there is no way to enforce these boundaries.

## Solution

Implement Role-Based Access Control with four roles: **admin** (full access including user management), **developer** (read/write keys, no user management), **viewer** (list keys and metadata only, no secret access), and **agent** (proxy-only access via vault_proxy). Each key additionally supports per-key ACLs to override role defaults. Users are identified by unique user IDs, authenticated via local password or SSO (Feature 043).

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/rbac.rs` — Role definitions and permission checks
- `crates/pqvault-team-mcp/src/users.rs` — User management (create, update, delete)
- `crates/pqvault-core/src/acl.rs` — Per-key access control lists
- `crates/pqvault-core/src/auth.rs` — Authentication middleware
- `crates/pqvault-web/src/middleware/auth.rs` — HTTP auth middleware for axum

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// User roles with hierarchical permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Viewer = 0,    // List keys, view metadata — no secret access
    Agent = 1,     // Proxy-only access, no direct read
    Developer = 2, // Read/write keys, rotate
    Admin = 3,     // Full access including user management
}

/// Permission types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    KeyList,
    KeyRead,
    KeyCreate,
    KeyUpdate,
    KeyDelete,
    KeyRotate,
    KeyProxy,
    UserManage,
    AuditRead,
    ConfigManage,
    TeamManage,
}

impl Role {
    pub fn permissions(&self) -> HashSet<Permission> {
        let mut perms = HashSet::new();
        match self {
            Role::Viewer => {
                perms.insert(Permission::KeyList);
                perms.insert(Permission::AuditRead);
            }
            Role::Agent => {
                perms.insert(Permission::KeyList);
                perms.insert(Permission::KeyProxy);
            }
            Role::Developer => {
                perms.insert(Permission::KeyList);
                perms.insert(Permission::KeyRead);
                perms.insert(Permission::KeyCreate);
                perms.insert(Permission::KeyUpdate);
                perms.insert(Permission::KeyRotate);
                perms.insert(Permission::KeyProxy);
                perms.insert(Permission::AuditRead);
            }
            Role::Admin => {
                perms.insert(Permission::KeyList);
                perms.insert(Permission::KeyRead);
                perms.insert(Permission::KeyCreate);
                perms.insert(Permission::KeyUpdate);
                perms.insert(Permission::KeyDelete);
                perms.insert(Permission::KeyRotate);
                perms.insert(Permission::KeyProxy);
                perms.insert(Permission::UserManage);
                perms.insert(Permission::AuditRead);
                perms.insert(Permission::ConfigManage);
                perms.insert(Permission::TeamManage);
            }
        }
        perms
    }
}

/// User account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: Role,
    pub password_hash: Option<String>, // argon2id hash
    pub sso_provider: Option<String>,
    pub sso_subject: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub active: bool,
    pub mfa_enabled: bool,
}

/// Per-key access control entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAcl {
    pub key_name: String,
    pub user_id: String,
    pub permissions: HashSet<Permission>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Authorization check result
pub struct AuthzCheck;

impl AuthzCheck {
    pub fn can_access(
        user: &User,
        permission: Permission,
        key_name: &str,
        key_acls: &[KeyAcl],
    ) -> bool {
        // Check per-key ACL first (overrides role)
        let key_acl = key_acls.iter()
            .find(|a| a.key_name == key_name && a.user_id == user.id);

        if let Some(acl) = key_acl {
            if let Some(expires) = acl.expires_at {
                if Utc::now() > expires {
                    return false; // Expired ACL
                }
            }
            return acl.permissions.contains(&permission);
        }

        // Fall back to role-based check
        user.role.permissions().contains(&permission)
    }
}
```

### MCP Tools

```rust
/// Create a new user
#[tool(name = "user_create")]
async fn user_create(
    &self,
    #[arg(description = "Username")] username: String,
    #[arg(description = "Email address")] email: Option<String>,
    #[arg(description = "Role: admin, developer, viewer, agent")] role: String,
) -> Result<CallToolResult, McpError> {
    self.require_permission(Permission::UserManage).await?;
    // Implementation
}

/// List all users
#[tool(name = "user_list")]
async fn user_list(&self) -> Result<CallToolResult, McpError> {
    self.require_permission(Permission::UserManage).await?;
    // Implementation
}

/// Set per-key ACL
#[tool(name = "key_acl_set")]
async fn key_acl_set(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "User ID")] user_id: String,
    #[arg(description = "Permissions: read,write,rotate,proxy")] permissions: String,
    #[arg(description = "Expiry in hours (optional)")] expires_hours: Option<u64>,
) -> Result<CallToolResult, McpError> {
    self.require_permission(Permission::TeamManage).await?;
    // Implementation
}

/// Check current user's permissions on a key
#[tool(name = "check_permission")]
async fn check_permission(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Permission to check")] permission: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Create admin user (first user setup)
pqvault user create --username admin --role admin --email admin@company.com

# Create developer
pqvault user create --username alice --role developer

# Create viewer
pqvault user create --username bob --role viewer

# List users
pqvault user list

# Set per-key ACL (give viewer access to one key)
pqvault acl set --key STAGING_DB_URL --user bob --permissions read --expires 24h

# Login
pqvault login --username alice

# Check permissions
pqvault acl check --key PROD_DB_URL --permission read
```

### Web UI Changes

- Login page with username/password form
- User management panel (admin only)
- Role badges on user list
- Per-key ACL editor in key detail view
- Permission denied error pages with clear messaging

## Dependencies

- `argon2 = "0.5"` — Password hashing (new dependency)
- `jsonwebtoken = "9"` — Session tokens (new dependency)
- `pqvault-core` (existing) — ACL storage
- Feature 043 (SSO) — Optional SSO authentication

## Testing

### Unit Tests

```rust
#[test]
fn role_permission_hierarchy() {
    assert!(Role::Admin.permissions().contains(&Permission::UserManage));
    assert!(!Role::Developer.permissions().contains(&Permission::UserManage));
    assert!(!Role::Viewer.permissions().contains(&Permission::KeyRead));
    assert!(Role::Agent.permissions().contains(&Permission::KeyProxy));
}

#[test]
fn key_acl_overrides_role() {
    let user = User { role: Role::Viewer, id: "u1".into(), ..Default::default() };
    let acls = vec![KeyAcl {
        key_name: "SPECIAL_KEY".into(),
        user_id: "u1".into(),
        permissions: [Permission::KeyRead].into(),
        granted_by: "admin".into(),
        granted_at: Utc::now(),
        expires_at: None,
    }];
    assert!(AuthzCheck::can_access(&user, Permission::KeyRead, "SPECIAL_KEY", &acls));
    assert!(!AuthzCheck::can_access(&user, Permission::KeyRead, "OTHER_KEY", &acls));
}

#[test]
fn expired_acl_denied() {
    let user = User { role: Role::Viewer, id: "u1".into(), ..Default::default() };
    let acls = vec![KeyAcl {
        key_name: "KEY".into(),
        user_id: "u1".into(),
        permissions: [Permission::KeyRead].into(),
        expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        ..Default::default()
    }];
    assert!(!AuthzCheck::can_access(&user, Permission::KeyRead, "KEY", &acls));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn viewer_cannot_read_secrets() {
    let mcp = test_team_mcp().await;
    mcp.login_as("viewer_user", Role::Viewer).await;
    let result = mcp.vault_get("SECRET_KEY").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("permission denied"));
}

#[tokio::test]
async fn developer_can_read_and_write() {
    let mcp = test_team_mcp().await;
    mcp.login_as("dev_user", Role::Developer).await;
    assert!(mcp.vault_get("KEY").await.is_ok());
    assert!(mcp.vault_set("NEW_KEY", "value").await.is_ok());
    assert!(mcp.vault_delete("KEY").await.is_err()); // No delete permission
}
```

### Manual Verification

1. Create users with different roles
2. Login as each role, attempt various operations
3. Verify viewer cannot read secrets
4. Verify developer cannot delete or manage users
5. Verify admin has full access
6. Set per-key ACL, verify override works

## Example Usage

```bash
# Team setup:
pqvault user create --username admin --role admin
pqvault user create --username alice --role developer
pqvault user create --username bob --role viewer
pqvault user create --username deploy-bot --role agent

# Alice (developer) can:
pqvault login --username alice
pqvault get STRIPE_KEY        # OK
pqvault set NEW_KEY value     # OK
pqvault rotate STRIPE_KEY     # OK
pqvault user list             # DENIED

# Bob (viewer) can:
pqvault login --username bob
pqvault list                  # OK (sees names only)
pqvault get STRIPE_KEY        # DENIED
```
