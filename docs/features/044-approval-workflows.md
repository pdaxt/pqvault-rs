# Feature 044: Approval Workflows

## Status: Planned
## Phase: 5 (v2.5)
## Priority: High

## Problem

Key access is entirely self-serve with no oversight. Any user with the right role can access any key at any time. There is no audit trail of why someone accessed a key, no manager approval for sensitive operations, and no time-limited access grants. For SOC2 and SOX compliance, organizations need approval workflows before granting access to production secrets.

## Solution

Implement a request-approve-grant workflow for key access. Users submit an access request with justification, which enters a "pending" state. Designated approvers review and approve or deny the request. Approved access is automatically time-limited (default: 8 hours). All requests, approvals, and denials are logged to the audit trail. Emergency "break-glass" access (Feature 045) bypasses the workflow but with mandatory justification.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/approval.rs` — Approval workflow engine
- `crates/pqvault-team-mcp/src/lib.rs` — Register approval tools
- `crates/pqvault-team-mcp/src/policy.rs` — Approval policy configuration per key/category
- `crates/pqvault-core/src/models.rs` — Add `requires_approval` field to key metadata

### Data Model Changes

```rust
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: String,
    pub requester_id: String,
    pub key_name: String,
    pub workspace_id: Option<String>,
    pub justification: String,
    pub requested_permission: RequestedPermission,
    pub requested_duration_hours: u32,
    pub status: RequestStatus,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub denial_reason: Option<String>,
    pub grant_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RequestedPermission {
    Read,
    Proxy,
    Rotate,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,    // Request expired without decision
    Revoked,    // Approved but access revoked early
}

/// Approval policy for a key or category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub target: PolicyTarget,
    pub require_approval: bool,
    pub approvers: Vec<String>,     // User IDs who can approve
    pub max_duration_hours: u32,    // Maximum grant duration
    pub auto_approve_roles: Vec<String>, // Roles that skip approval
    pub request_expiry_hours: u32,  // Pending request timeout
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyTarget {
    Key(String),
    Category(String),
    Workspace(String),
    Global,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            target: PolicyTarget::Global,
            require_approval: false,
            approvers: vec![],
            max_duration_hours: 8,
            auto_approve_roles: vec!["admin".into()],
            request_expiry_hours: 24,
        }
    }
}

/// Approval workflow manager
pub struct ApprovalManager {
    requests: Vec<AccessRequest>,
    policies: Vec<ApprovalPolicy>,
}

impl ApprovalManager {
    pub fn submit_request(
        &mut self,
        requester_id: &str,
        key_name: &str,
        justification: &str,
        permission: RequestedPermission,
        duration_hours: u32,
    ) -> Result<AccessRequest, String> {
        let policy = self.get_policy(key_name);

        if !policy.require_approval {
            // Auto-approve
            let mut request = AccessRequest::new(requester_id, key_name, justification, permission, duration_hours);
            request.status = RequestStatus::Approved;
            request.decided_at = Some(Utc::now());
            request.decided_by = Some("auto".into());
            request.grant_expires_at = Some(Utc::now() + Duration::hours(duration_hours as i64));
            self.requests.push(request.clone());
            return Ok(request);
        }

        let max_hours = policy.max_duration_hours;
        let request = AccessRequest::new(
            requester_id, key_name, justification, permission,
            duration_hours.min(max_hours),
        );
        self.requests.push(request.clone());
        Ok(request)
    }

    pub fn approve(&mut self, request_id: &str, approver_id: &str) -> Result<(), String> {
        let request = self.requests.iter_mut()
            .find(|r| r.id == request_id && r.status == RequestStatus::Pending)
            .ok_or("Request not found or not pending")?;

        let policy = self.get_policy(&request.key_name);
        if !policy.approvers.contains(&approver_id.to_string()) {
            return Err("Not an authorized approver".into());
        }

        request.status = RequestStatus::Approved;
        request.decided_at = Some(Utc::now());
        request.decided_by = Some(approver_id.to_string());
        request.grant_expires_at = Some(
            Utc::now() + Duration::hours(request.requested_duration_hours as i64)
        );
        Ok(())
    }

    pub fn deny(&mut self, request_id: &str, approver_id: &str, reason: &str) -> Result<(), String> {
        let request = self.requests.iter_mut()
            .find(|r| r.id == request_id && r.status == RequestStatus::Pending)
            .ok_or("Request not found or not pending")?;

        request.status = RequestStatus::Denied;
        request.decided_at = Some(Utc::now());
        request.decided_by = Some(approver_id.to_string());
        request.denial_reason = Some(reason.to_string());
        Ok(())
    }
}
```

### MCP Tools

```rust
/// Submit an access request
#[tool(name = "request_access")]
async fn request_access(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Why you need access")] justification: String,
    #[arg(description = "Permission: read, proxy, rotate, admin")] permission: String,
    #[arg(description = "Duration in hours")] duration_hours: Option<u32>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List pending requests (for approvers)
#[tool(name = "list_requests")]
async fn list_requests(
    &self,
    #[arg(description = "Filter: pending, approved, denied, all")] status: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Approve a request
#[tool(name = "approve_request")]
async fn approve_request(
    &self,
    #[arg(description = "Request ID")] request_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Deny a request
#[tool(name = "deny_request")]
async fn deny_request(
    &self,
    #[arg(description = "Request ID")] request_id: String,
    #[arg(description = "Reason for denial")] reason: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Set approval policy
#[tool(name = "set_approval_policy")]
async fn set_approval_policy(
    &self,
    #[arg(description = "Key name or category")] target: String,
    #[arg(description = "Approver user IDs (comma-separated)")] approvers: String,
    #[arg(description = "Max grant duration in hours")] max_hours: Option<u32>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Request access to a key
pqvault request --key PROD_DATABASE_URL \
  --justification "Need to debug production issue #1234" \
  --permission read --duration 4h
# Request #req-abc123 submitted. Awaiting approval from: alice, bob

# List pending requests (as approver)
pqvault requests --status pending
# #req-abc123 | charlie | PROD_DATABASE_URL | read | 4h | "debug issue #1234"

# Approve
pqvault approve req-abc123

# Deny
pqvault deny req-abc123 --reason "Use staging environment instead"

# Set approval policy
pqvault policy set --key PROD_DATABASE_URL \
  --approvers alice,bob \
  --max-duration 8h

# Set category-wide policy
pqvault policy set --category production \
  --approvers alice,bob \
  --max-duration 4h
```

### Web UI Changes

- "Request Access" button on keys requiring approval
- Pending requests queue for approvers with approve/deny buttons
- Request history timeline per key
- Policy configuration panel in admin settings
- Notification badges for pending requests

## Dependencies

- `uuid = "1"` (existing) — Request IDs
- `chrono = "0.4"` (existing) — Expiry management
- Feature 041 (RBAC) — User roles for approver authorization
- Feature 042 (Workspaces) — Workspace-scoped policies

## Testing

### Unit Tests

```rust
#[test]
fn request_auto_approved_when_no_policy() {
    let mut mgr = ApprovalManager::new(vec![]);
    let req = mgr.submit_request("user1", "KEY", "testing", RequestedPermission::Read, 4).unwrap();
    assert_eq!(req.status, RequestStatus::Approved);
}

#[test]
fn request_pending_with_policy() {
    let policy = ApprovalPolicy {
        target: PolicyTarget::Key("PROD_KEY".into()),
        require_approval: true,
        approvers: vec!["admin1".into()],
        ..Default::default()
    };
    let mut mgr = ApprovalManager::new(vec![policy]);
    let req = mgr.submit_request("user1", "PROD_KEY", "need it", RequestedPermission::Read, 4).unwrap();
    assert_eq!(req.status, RequestStatus::Pending);
}

#[test]
fn only_designated_approver_can_approve() {
    let policy = ApprovalPolicy {
        target: PolicyTarget::Key("KEY".into()),
        require_approval: true,
        approvers: vec!["admin1".into()],
        ..Default::default()
    };
    let mut mgr = ApprovalManager::new(vec![policy]);
    let req = mgr.submit_request("user1", "KEY", "reason", RequestedPermission::Read, 4).unwrap();
    assert!(mgr.approve(&req.id, "random_user").is_err());
    assert!(mgr.approve(&req.id, "admin1").is_ok());
}

#[test]
fn duration_capped_by_policy() {
    let policy = ApprovalPolicy {
        target: PolicyTarget::Key("KEY".into()),
        require_approval: true,
        max_duration_hours: 4,
        approvers: vec!["admin1".into()],
        ..Default::default()
    };
    let mut mgr = ApprovalManager::new(vec![policy]);
    let req = mgr.submit_request("user1", "KEY", "reason", RequestedPermission::Read, 24).unwrap();
    assert_eq!(req.requested_duration_hours, 4); // Capped
}
```

### Integration Tests

```rust
#[tokio::test]
async fn full_approval_workflow() {
    let mcp = test_team_mcp().await;
    mcp.set_approval_policy("PROD_KEY", "admin1", Some(8)).await.unwrap();

    // User requests
    mcp.login_as("user1").await;
    let result = mcp.request_access("PROD_KEY", "debugging", "read", Some(4)).await.unwrap();
    assert!(result.contains("Pending"));

    // Admin approves
    mcp.login_as("admin1").await;
    mcp.approve_request("req-id").await.unwrap();

    // User can now access
    mcp.login_as("user1").await;
    assert!(mcp.vault_get("PROD_KEY").await.is_ok());
}
```

### Manual Verification

1. Set approval policy on a production key
2. Request access as a regular user
3. Verify request appears in approver's queue
4. Approve the request
5. Verify time-limited access works
6. Wait for expiry, verify access is revoked

## Example Usage

```bash
# Production key workflow:
# 1. Developer needs prod database access:
pqvault request --key PROD_DB_URL --justification "Incident INC-456" --duration 2h

# 2. Team lead gets notification, reviews:
pqvault requests --pending
pqvault approve req-xyz789

# 3. Developer has 2-hour access:
pqvault get PROD_DB_URL  # Works for 2 hours

# 4. After 2 hours:
pqvault get PROD_DB_URL  # "Access expired. Submit new request."
```
