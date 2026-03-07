# Feature 045: Break-Glass Access

## Status: Planned
## Phase: 5 (v2.5)
## Priority: Medium

## Problem

When a production incident occurs at 3 AM and the designated approver is asleep, the approval workflow (Feature 044) blocks access to critical keys. There is no emergency override mechanism. The only option is to bypass the vault entirely, which means losing audit trail and using potentially stale credentials. Organizations need a "break glass" mechanism that provides immediate access with full accountability.

## Solution

Implement an emergency override that bypasses the approval workflow but requires a mandatory written justification. Break-glass access is immediately granted but generates a high-severity audit event that is pushed to all admins. The justification is permanently recorded and cannot be edited. Break-glass events trigger a mandatory post-incident review. Access duration is limited (default: 4 hours, configurable), and the number of break-glass uses per user is tracked.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/break_glass.rs` — Emergency access override logic
- `crates/pqvault-team-mcp/src/lib.rs` — Register break-glass tools
- `crates/pqvault-audit-mcp/src/lib.rs` — High-severity audit events for break-glass
- `crates/pqvault-core/src/models.rs` — Add break_glass_count to user profile

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Break-glass access record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassEvent {
    pub id: String,
    pub user_id: String,
    pub key_name: String,
    pub justification: String,
    pub permission: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub duration_hours: u32,
    pub reviewed: bool,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_notes: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Break-glass policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassPolicy {
    /// Roles allowed to use break-glass
    pub allowed_roles: Vec<String>,
    /// Maximum duration of break-glass access
    pub max_duration_hours: u32,
    /// Minimum justification length (characters)
    pub min_justification_length: usize,
    /// Maximum break-glass uses per user per week
    pub max_uses_per_week: u32,
    /// Require review within this many hours
    pub review_deadline_hours: u32,
    /// Notify these user IDs on break-glass
    pub notify_users: Vec<String>,
    /// Keys that can never be accessed via break-glass
    pub excluded_keys: Vec<String>,
}

impl Default for BreakGlassPolicy {
    fn default() -> Self {
        Self {
            allowed_roles: vec!["admin".into(), "developer".into()],
            max_duration_hours: 4,
            min_justification_length: 20,
            max_uses_per_week: 3,
            review_deadline_hours: 48,
            notify_users: vec![],
            excluded_keys: vec![],
        }
    }
}

/// Break-glass manager
pub struct BreakGlassManager {
    policy: BreakGlassPolicy,
    events: Vec<BreakGlassEvent>,
}

impl BreakGlassManager {
    pub fn invoke(
        &mut self,
        user_id: &str,
        user_role: &str,
        key_name: &str,
        justification: &str,
    ) -> Result<BreakGlassEvent, String> {
        // Validate role
        if !self.policy.allowed_roles.contains(&user_role.to_string()) {
            return Err("Your role is not authorized for break-glass access".into());
        }

        // Check excluded keys
        if self.policy.excluded_keys.contains(&key_name.to_string()) {
            return Err(format!("Key '{}' is excluded from break-glass access", key_name));
        }

        // Validate justification length
        if justification.len() < self.policy.min_justification_length {
            return Err(format!(
                "Justification must be at least {} characters (got {})",
                self.policy.min_justification_length, justification.len()
            ));
        }

        // Check weekly limit
        let week_ago = Utc::now() - chrono::Duration::days(7);
        let recent_count = self.events.iter()
            .filter(|e| e.user_id == user_id && e.granted_at > week_ago)
            .count() as u32;
        if recent_count >= self.policy.max_uses_per_week {
            return Err(format!(
                "Weekly break-glass limit reached ({}/{})",
                recent_count, self.policy.max_uses_per_week
            ));
        }

        let event = BreakGlassEvent {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            key_name: key_name.to_string(),
            justification: justification.to_string(),
            permission: "read".into(),
            granted_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(self.policy.max_duration_hours as i64),
            duration_hours: self.policy.max_duration_hours,
            reviewed: false,
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            ip_address: None,
            user_agent: None,
        };

        self.events.push(event.clone());
        Ok(event)
    }

    pub fn pending_reviews(&self) -> Vec<&BreakGlassEvent> {
        self.events.iter().filter(|e| !e.reviewed).collect()
    }
}
```

### MCP Tools

```rust
/// Invoke break-glass emergency access
#[tool(name = "break_glass")]
async fn break_glass(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Mandatory justification (min 20 chars)")] justification: String,
    #[arg(description = "Duration in hours (max: policy limit)")] duration_hours: Option<u32>,
) -> Result<CallToolResult, McpError> {
    let user = self.current_user().await?;
    let event = self.break_glass_mgr.invoke(
        &user.id, &user.role.to_string(), &key_name, &justification
    )?;

    // Publish high-severity audit event
    self.audit.log_critical("break_glass", &event).await;

    // Notify admins
    self.notify_break_glass(&event).await;

    Ok(CallToolResult::success(format!(
        "BREAK-GLASS ACCESS GRANTED\n  Key: {}\n  Expires: {}\n  Review required within {}h\n  Event ID: {}",
        key_name, event.expires_at, self.policy.review_deadline_hours, event.id
    )))
}

/// Review a break-glass event
#[tool(name = "review_break_glass")]
async fn review_break_glass(
    &self,
    #[arg(description = "Break-glass event ID")] event_id: String,
    #[arg(description = "Review notes")] notes: String,
    #[arg(description = "Approved: was the use justified?")] approved: bool,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List pending break-glass reviews
#[tool(name = "list_break_glass")]
async fn list_break_glass(
    &self,
    #[arg(description = "Only unreviewed")] pending_only: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Emergency access
pqvault break-glass --key PROD_DATABASE_URL \
  --justification "Production database connection failing, incident INC-789. Need to verify credentials."
# !! BREAK-GLASS ACCESS GRANTED !!
#   Key: PROD_DATABASE_URL
#   Expires: 2026-03-07T18:30:00Z (4 hours)
#   Review required within 48h
#   Event ID: bg-abc123
#   All admins have been notified.

# List pending reviews (admin)
pqvault break-glass list --pending
# bg-abc123 | alice | PROD_DATABASE_URL | 2h ago | Unreviewed

# Review
pqvault break-glass review bg-abc123 \
  --notes "Justified — production incident confirmed" \
  --approved

# View break-glass history
pqvault break-glass history --user alice
```

### Web UI Changes

- "Emergency Access" button with warning styling (red)
- Justification form with minimum length requirement
- Break-glass events dashboard with review queue
- Admin notification banner for pending reviews
- Break-glass usage count per user on user management page

## Dependencies

- `uuid = "1"` (existing) — Event IDs
- `chrono = "0.4"` (existing) — Expiry management
- Feature 041 (RBAC) — Role-based authorization
- Feature 044 (Approval Workflows) — Break-glass bypasses approval

## Testing

### Unit Tests

```rust
#[test]
fn break_glass_requires_justification() {
    let mut mgr = BreakGlassManager::new(BreakGlassPolicy::default());
    let result = mgr.invoke("user1", "developer", "KEY", "too short");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("at least"));
}

#[test]
fn break_glass_respects_weekly_limit() {
    let mut mgr = BreakGlassManager::new(BreakGlassPolicy { max_uses_per_week: 1, ..Default::default() });
    mgr.invoke("user1", "developer", "K1", "First emergency access justified").unwrap();
    let result = mgr.invoke("user1", "developer", "K2", "Second emergency access justified");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("limit reached"));
}

#[test]
fn break_glass_excluded_keys() {
    let mut mgr = BreakGlassManager::new(BreakGlassPolicy {
        excluded_keys: vec!["ROOT_KEY".into()],
        ..Default::default()
    });
    let result = mgr.invoke("user1", "admin", "ROOT_KEY", "Emergency need for root key access");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("excluded"));
}

#[test]
fn break_glass_unauthorized_role() {
    let mut mgr = BreakGlassManager::new(BreakGlassPolicy::default());
    let result = mgr.invoke("user1", "viewer", "KEY", "Emergency viewer needs access now");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not authorized"));
}

#[test]
fn pending_reviews_lists_unreviewed() {
    let mut mgr = BreakGlassManager::new(BreakGlassPolicy::default());
    mgr.invoke("user1", "developer", "KEY", "Production incident needs immediate key access").unwrap();
    assert_eq!(mgr.pending_reviews().len(), 1);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn break_glass_grants_immediate_access() {
    let mcp = test_team_mcp().await;
    // Set approval policy (normally blocks access)
    mcp.set_approval_policy("PROD_KEY", "admin1", Some(8)).await.unwrap();

    // Regular access is blocked
    mcp.login_as("dev1").await;
    assert!(mcp.vault_get("PROD_KEY").await.is_err());

    // Break-glass grants immediate access
    mcp.break_glass("PROD_KEY", "Incident INC-123: prod database down, need credentials").await.unwrap();
    assert!(mcp.vault_get("PROD_KEY").await.is_ok());
}
```

### Manual Verification

1. Set approval policy on a key
2. Attempt regular access — verify it is blocked
3. Use break-glass with justification — verify immediate access
4. Verify admins receive notification
5. Review the break-glass event as admin
6. Wait for expiry, verify access is revoked
7. Check audit log for complete trail

## Example Usage

```bash
# 3 AM incident scenario:
# 1. On-call engineer gets paged
# 2. Needs production database credentials
# 3. Approval workflow would require team lead (who is asleep)

pqvault break-glass --key PROD_DATABASE_URL \
  --justification "Pager alert PD-12345: database connection pool exhaustion.
  Need to verify credentials and check connection limits.
  Team lead bob@company.com notified via Slack."

# Access granted immediately
# All admins notified
# Review required within 48 hours
# Full audit trail preserved
```
