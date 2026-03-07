# Feature 047: Access Reviews

## Status: Planned
## Phase: 5 (v2.5)
## Priority: Medium

## Problem

Permissions accumulate over time and never get cleaned up. A developer who was granted temporary access to production keys six months ago still has that access. A contractor who finished their project still has read access to all client secrets. Without periodic access reviews, the vault's permission surface grows monotonically, violating the principle of least privilege and creating compliance risk for SOC2 and ISO 27001.

## Solution

Implement quarterly access recertification campaigns. The system generates a review for each user listing all their current key access. Reviewers (managers or key owners) must confirm or revoke each access grant. Unreviewed access is automatically revoked after the review deadline. Review history is preserved for compliance audits. The review cadence, scope, and deadlines are configurable.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/review.rs` — Access review campaign management
- `crates/pqvault-team-mcp/src/lib.rs` — Register review tools
- `crates/pqvault-team-mcp/src/review_report.rs` — Compliance report generation

### Data Model Changes

```rust
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Access review campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCampaign {
    pub id: String,
    pub name: String,
    pub started_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub status: CampaignStatus,
    pub reviews: Vec<UserReview>,
    pub completed_count: usize,
    pub total_count: usize,
    pub created_by: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CampaignStatus {
    Active,
    Completed,
    Expired, // Deadline passed with incomplete reviews
}

/// Per-user access review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReview {
    pub user_id: String,
    pub username: String,
    pub reviewer_id: String,
    pub reviewer_name: String,
    pub items: Vec<ReviewItem>,
    pub status: ReviewStatus,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ReviewStatus {
    Pending,
    InProgress,
    Completed,
    Expired,
}

/// Individual key access review item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewItem {
    pub key_name: String,
    pub permission: String,
    pub granted_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count_90d: u64,
    pub decision: Option<ReviewDecision>,
    pub justification: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ReviewDecision {
    Confirm,  // Keep access
    Revoke,   // Remove access
    Downgrade, // Reduce permission level
}

/// Review campaign manager
pub struct ReviewManager {
    campaigns: Vec<ReviewCampaign>,
}

impl ReviewManager {
    pub fn start_campaign(
        &mut self,
        name: &str,
        deadline_days: u32,
        created_by: &str,
        users: Vec<UserAccessSummary>,
    ) -> ReviewCampaign {
        let reviews: Vec<UserReview> = users.into_iter().map(|u| {
            UserReview {
                user_id: u.user_id.clone(),
                username: u.username.clone(),
                reviewer_id: u.manager_id.unwrap_or_else(|| created_by.to_string()),
                reviewer_name: String::new(),
                items: u.key_accesses.into_iter().map(|ka| ReviewItem {
                    key_name: ka.key_name,
                    permission: ka.permission,
                    granted_at: ka.granted_at,
                    last_used: ka.last_used,
                    usage_count_90d: ka.usage_count_90d,
                    decision: None,
                    justification: None,
                }).collect(),
                status: ReviewStatus::Pending,
                completed_at: None,
            }
        }).collect();

        let total = reviews.len();
        let campaign = ReviewCampaign {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            started_at: Utc::now(),
            deadline: Utc::now() + chrono::Duration::days(deadline_days as i64),
            status: CampaignStatus::Active,
            reviews,
            completed_count: 0,
            total_count: total,
            created_by: created_by.to_string(),
        };
        self.campaigns.push(campaign.clone());
        campaign
    }

    pub fn submit_review(
        &mut self,
        campaign_id: &str,
        user_id: &str,
        reviewer_id: &str,
        decisions: Vec<(String, ReviewDecision, Option<String>)>,
    ) -> Result<(), String> {
        let campaign = self.campaigns.iter_mut()
            .find(|c| c.id == campaign_id)
            .ok_or("Campaign not found")?;

        let review = campaign.reviews.iter_mut()
            .find(|r| r.user_id == user_id && r.reviewer_id == reviewer_id)
            .ok_or("Review not found")?;

        for (key_name, decision, justification) in decisions {
            if let Some(item) = review.items.iter_mut().find(|i| i.key_name == key_name) {
                item.decision = Some(decision);
                item.justification = justification;
            }
        }

        if review.items.iter().all(|i| i.decision.is_some()) {
            review.status = ReviewStatus::Completed;
            review.completed_at = Some(Utc::now());
            campaign.completed_count += 1;
        } else {
            review.status = ReviewStatus::InProgress;
        }

        if campaign.completed_count == campaign.total_count {
            campaign.status = CampaignStatus::Completed;
        }

        Ok(())
    }
}
```

### MCP Tools

```rust
/// Start an access review campaign
#[tool(name = "start_review")]
async fn start_review(
    &self,
    #[arg(description = "Campaign name")] name: String,
    #[arg(description = "Deadline in days")] deadline_days: Option<u32>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Get review items for a user
#[tool(name = "get_review")]
async fn get_review(
    &self,
    #[arg(description = "Campaign ID")] campaign_id: String,
    #[arg(description = "User ID to review")] user_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Submit review decisions
#[tool(name = "submit_review")]
async fn submit_review(
    &self,
    #[arg(description = "Campaign ID")] campaign_id: String,
    #[arg(description = "User ID")] user_id: String,
    #[arg(description = "Decisions as JSON")] decisions_json: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Get campaign status
#[tool(name = "review_status")]
async fn review_status(
    &self,
    #[arg(description = "Campaign ID")] campaign_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Start quarterly review
pqvault review start --name "Q1 2026 Access Review" --deadline 14

# View pending review (as reviewer)
pqvault review pending
# Campaign: Q1 2026 Access Review (due in 12 days)
#   alice — 5 keys to review
#   bob — 3 keys to review

# Review a user's access
pqvault review show --campaign rv-123 --user alice
# alice has access to:
#   STRIPE_KEY (read) — granted 2025-10-01, used 234 times in 90d → ?
#   PROD_DB (read) — granted 2025-06-15, used 0 times in 90d → ?
#   TEST_KEY (admin) — granted 2025-11-20, used 12 times in 90d → ?

# Submit decisions
pqvault review decide --campaign rv-123 --user alice \
  --confirm STRIPE_KEY \
  --revoke PROD_DB --reason "No longer needs prod access" \
  --downgrade TEST_KEY --to read

# Check campaign progress
pqvault review status rv-123
# Q1 2026 Access Review: 8/12 reviews completed (67%)
```

### Web UI Changes

- Review campaign management page (admin)
- Reviewer inbox with pending reviews
- Decision interface with usage context (last used, count)
- Campaign progress dashboard with completion metrics
- Compliance report export

## Dependencies

- `uuid = "1"` (existing) — Campaign and review IDs
- `chrono = "0.4"` (existing) — Deadlines and dates
- Feature 041 (RBAC) — User and permission data
- Feature 042 (Workspaces) — Workspace-scoped reviews

## Testing

### Unit Tests

```rust
#[test]
fn campaign_tracks_completion() {
    let mut mgr = ReviewManager::new();
    let campaign = mgr.start_campaign("test", 14, "admin", vec![
        UserAccessSummary::new("user1", vec![("KEY1", "read")]),
    ]);
    assert_eq!(campaign.completed_count, 0);
    assert_eq!(campaign.total_count, 1);

    mgr.submit_review(&campaign.id, "user1", "admin", vec![
        ("KEY1".into(), ReviewDecision::Confirm, None),
    ]).unwrap();

    let updated = mgr.get_campaign(&campaign.id).unwrap();
    assert_eq!(updated.completed_count, 1);
    assert_eq!(updated.status, CampaignStatus::Completed);
}

#[test]
fn partial_review_is_in_progress() {
    let mut mgr = ReviewManager::new();
    let campaign = mgr.start_campaign("test", 14, "admin", vec![
        UserAccessSummary::new("user1", vec![("K1", "read"), ("K2", "read")]),
    ]);
    mgr.submit_review(&campaign.id, "user1", "admin", vec![
        ("K1".into(), ReviewDecision::Confirm, None),
    ]).unwrap();

    let review = mgr.get_user_review(&campaign.id, "user1").unwrap();
    assert_eq!(review.status, ReviewStatus::InProgress);
}

#[test]
fn revoke_decision_records_reason() {
    let mut mgr = ReviewManager::new();
    let campaign = mgr.start_campaign("test", 14, "admin", vec![
        UserAccessSummary::new("user1", vec![("KEY1", "read")]),
    ]);
    mgr.submit_review(&campaign.id, "user1", "admin", vec![
        ("KEY1".into(), ReviewDecision::Revoke, Some("No longer needed".into())),
    ]).unwrap();

    let review = mgr.get_user_review(&campaign.id, "user1").unwrap();
    assert_eq!(review.items[0].justification, Some("No longer needed".to_string()));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn revoked_access_is_enforced() {
    let mcp = test_team_mcp().await;
    // Grant access
    mcp.grant_access("user1", "KEY1", "read").await.unwrap();
    assert!(mcp.vault_get_as("user1", "KEY1").await.is_ok());

    // Review and revoke
    let campaign = mcp.start_review("test", Some(14)).await.unwrap();
    mcp.submit_review(&campaign.id, "user1", vec![("KEY1", "revoke", "unused")]).await.unwrap();

    // Access should be revoked
    assert!(mcp.vault_get_as("user1", "KEY1").await.is_err());
}
```

### Manual Verification

1. Start a review campaign
2. Log in as reviewer, review each user's access
3. Revoke access for unused keys
4. Verify revoked access is enforced immediately
5. Generate compliance report
6. Test deadline expiry auto-revocation

## Example Usage

```bash
# Quarterly compliance workflow:
# 1. Admin starts campaign
pqvault review start --name "Q1 2026" --deadline 14

# 2. Reviewers get notified, complete reviews
# 3. Unused access gets revoked
# 4. Generate compliance report
pqvault review report rv-123 --format pdf > q1-2026-access-review.pdf
# Report shows: 45 grants reviewed, 12 revoked, 3 downgraded, 30 confirmed
```
