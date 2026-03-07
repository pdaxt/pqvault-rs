# Feature 050: Activity Feed

## Status: Done
## Phase: 5 (v2.5)
## Priority: Low

## Problem

There is no team-wide visibility into vault operations. Team members operate in isolation — Alice does not know that Bob just rotated the shared database key, and nobody notices when an agent exceeds its budget. The audit log exists but is a compliance tool, not a collaboration tool. Teams need a human-readable, real-time activity stream to maintain situational awareness.

## Solution

Implement a real-time activity feed that shows vault operations in a human-readable format: "Alice rotated STRIPE_KEY," "Bob's agent exceeded budget on OPENAI_KEY," "Charlie was granted temporary access to PROD_DB." The feed combines audit events, health alerts, and system notifications into a unified timeline. Users can filter by workspace, user, key, or event type. The feed integrates with the WebSocket dashboard (Feature 031) for live updates.

## Implementation

### Files to Create/Modify

- `crates/pqvault-team-mcp/src/activity.rs` — Activity feed aggregation and formatting
- `crates/pqvault-team-mcp/src/lib.rs` — Register activity feed tools
- `crates/pqvault-web/src/activity_handler.rs` — HTTP/WebSocket handler for activity feed
- `crates/pqvault-web/src/routes.rs` — Add `/api/activity` and `/ws/activity` routes

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Activity feed event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: Actor,
    pub action: ActivityAction,
    pub target: ActivityTarget,
    pub workspace_id: Option<String>,
    pub details: Option<String>,
    pub severity: EventSeverity,
}

/// Who performed the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub user_id: String,
    pub display_name: String,
    pub actor_type: ActorType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActorType {
    User,
    Agent,
    System,
}

/// What action was performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityAction {
    KeyCreated,
    KeyRotated,
    KeyDeleted,
    KeyAccessed,
    KeyProxied,
    GrantCreated,
    GrantRevoked,
    GrantExpired,
    UserAdded,
    UserRemoved,
    BreakGlassUsed,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    AnomalyDetected,
    BudgetExceeded,
    HealthAlert,
    WorkspaceCreated,
    InviteCreated,
    InviteRedeemed,
}

/// What was the action's target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityTarget {
    pub target_type: String, // "key", "user", "workspace", "grant"
    pub target_id: String,
    pub target_name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

impl ActivityEvent {
    /// Human-readable summary
    pub fn summary(&self) -> String {
        let actor = &self.actor.display_name;
        let target = &self.target.target_name;
        match &self.action {
            ActivityAction::KeyCreated => format!("{} created key {}", actor, target),
            ActivityAction::KeyRotated => format!("{} rotated key {}", actor, target),
            ActivityAction::KeyDeleted => format!("{} deleted key {}", actor, target),
            ActivityAction::KeyAccessed => format!("{} accessed key {}", actor, target),
            ActivityAction::KeyProxied => format!("{} used key {} via proxy", actor, target),
            ActivityAction::GrantCreated => format!("{} granted access to {}", actor, target),
            ActivityAction::GrantExpired => format!("Access to {} expired for {}", target, actor),
            ActivityAction::BreakGlassUsed => format!("{} used break-glass for {}", actor, target),
            ActivityAction::AnomalyDetected => format!("Anomaly detected on {}", target),
            ActivityAction::BudgetExceeded => format!("{} exceeded budget on {}", actor, target),
            _ => format!("{} performed {:?} on {}", actor, self.action, target),
        }
    }
}

/// Activity feed query options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityQuery {
    pub workspace_id: Option<String>,
    pub user_id: Option<String>,
    pub key_name: Option<String>,
    pub action_types: Option<Vec<ActivityAction>>,
    pub severity: Option<EventSeverity>,
    pub since: Option<DateTime<Utc>>,
    pub limit: usize,
    pub offset: usize,
}

/// Activity feed store
pub struct ActivityFeed {
    events: Vec<ActivityEvent>,
    max_events: usize,
}

impl ActivityFeed {
    pub fn record(&mut self, event: ActivityEvent) {
        self.events.push(event);
        if self.events.len() > self.max_events {
            self.events.remove(0);
        }
    }

    pub fn query(&self, q: &ActivityQuery) -> Vec<&ActivityEvent> {
        self.events.iter()
            .filter(|e| {
                if let Some(ref ws) = q.workspace_id {
                    if e.workspace_id.as_ref() != Some(ws) { return false; }
                }
                if let Some(ref uid) = q.user_id {
                    if &e.actor.user_id != uid { return false; }
                }
                if let Some(ref key) = q.key_name {
                    if &e.target.target_name != key { return false; }
                }
                if let Some(ref since) = q.since {
                    if &e.timestamp < since { return false; }
                }
                true
            })
            .rev()
            .skip(q.offset)
            .take(q.limit)
            .collect()
    }
}
```

### MCP Tools

```rust
/// Get activity feed
#[tool(name = "activity_feed")]
async fn activity_feed(
    &self,
    #[arg(description = "Filter by workspace")] workspace: Option<String>,
    #[arg(description = "Filter by user")] user: Option<String>,
    #[arg(description = "Filter by key")] key: Option<String>,
    #[arg(description = "Number of events")] limit: Option<usize>,
    #[arg(description = "Only warnings and above")] warnings_only: Option<bool>,
) -> Result<CallToolResult, McpError> {
    let query = ActivityQuery {
        workspace_id: workspace,
        user_id: user,
        key_name: key,
        limit: limit.unwrap_or(20),
        ..Default::default()
    };

    let events = self.feed.query(&query);
    let output = events.iter().map(|e| {
        format!("[{}] {} {:?} — {}",
            e.timestamp.format("%H:%M"),
            severity_icon(e.severity),
            e.severity,
            e.summary()
        )
    }).collect::<Vec<_>>().join("\n");

    Ok(CallToolResult::success(output))
}
```

### CLI Commands

```bash
# View recent activity
pqvault activity
# [14:30] alice rotated STRIPE_KEY
# [14:25] bob's agent used OPENAI_KEY via proxy
# [14:20] system: Anomaly detected on ANTHROPIC_KEY
# [14:15] charlie was granted temporary access to PROD_DB_URL
# [14:10] alice created key NEW_SERVICE_KEY
# [14:05] system: Access to STAGING_KEY expired for contractor1

# Filter by key
pqvault activity --key STRIPE_KEY

# Filter by user
pqvault activity --user alice

# Warnings only
pqvault activity --warnings-only

# Stream live activity
pqvault activity --stream
# [14:31] bob rotated OPENAI_KEY
# [14:32] deploy-bot accessed AWS_KEY via proxy
# ^C
```

### Web UI Changes

- Activity feed sidebar or dedicated page
- Real-time updates via WebSocket (Feature 031)
- Filter dropdowns for workspace, user, key, event type
- Color-coded severity (gray=info, yellow=warning, red=critical)
- Click-to-expand event details
- "Mark as read" for personal feed items

## Dependencies

- `chrono = "0.4"` (existing) — Timestamps
- `serde_json = "1"` (existing) — Serialization
- Feature 031 (Real-Time Dashboard) — WebSocket infrastructure for live feed
- Feature 041 (RBAC) — User identity for activity actors

## Testing

### Unit Tests

```rust
#[test]
fn activity_summary_readable() {
    let event = ActivityEvent {
        actor: Actor { display_name: "alice".into(), ..Default::default() },
        action: ActivityAction::KeyRotated,
        target: ActivityTarget { target_name: "STRIPE_KEY".into(), ..Default::default() },
        ..Default::default()
    };
    assert_eq!(event.summary(), "alice rotated key STRIPE_KEY");
}

#[test]
fn query_filters_by_user() {
    let mut feed = ActivityFeed::new(1000);
    feed.record(ActivityEvent::test("alice", ActivityAction::KeyCreated, "KEY1"));
    feed.record(ActivityEvent::test("bob", ActivityAction::KeyCreated, "KEY2"));

    let results = feed.query(&ActivityQuery { user_id: Some("alice".into()), ..Default::default() });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].actor.user_id, "alice");
}

#[test]
fn query_limits_results() {
    let mut feed = ActivityFeed::new(1000);
    for i in 0..50 {
        feed.record(ActivityEvent::test("alice", ActivityAction::KeyAccessed, &format!("KEY{i}")));
    }
    let results = feed.query(&ActivityQuery { limit: 10, ..Default::default() });
    assert_eq!(results.len(), 10);
}

#[test]
fn feed_evicts_old_events() {
    let mut feed = ActivityFeed::new(5);
    for i in 0..10 {
        feed.record(ActivityEvent::test("alice", ActivityAction::KeyAccessed, &format!("KEY{i}")));
    }
    assert_eq!(feed.events.len(), 5);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn vault_operations_appear_in_feed() {
    let mcp = test_team_mcp().await;
    mcp.vault_set("KEY1", "value").await.unwrap();
    mcp.vault_get("KEY1").await.unwrap();
    mcp.vault_rotate("KEY1").await.unwrap();

    let feed = mcp.activity_feed(None, None, Some("KEY1"), Some(10), None).await.unwrap();
    assert!(feed.contains("created"));
    assert!(feed.contains("accessed"));
    assert!(feed.contains("rotated"));
}

#[tokio::test]
async fn websocket_streams_activity() {
    let app = test_app().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(
        format!("ws://{}/ws/activity", app.addr)
    ).await.unwrap();

    app.vault.set("KEY1", "val").await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
    assert!(msg.is_ok());
    let text = msg.unwrap().unwrap().unwrap().into_text().unwrap();
    assert!(text.contains("created"));
}
```

### Manual Verification

1. Perform various vault operations (create, read, rotate, delete)
2. Check activity feed shows all operations in order
3. Filter by different dimensions (user, key, workspace)
4. Open two browser tabs, verify real-time updates on both
5. Verify critical events (break-glass, anomalies) are highlighted

## Example Usage

```bash
# Morning check — what happened overnight:
pqvault activity --since 12h
# [02:15] deploy-bot rotated AWS_PROD_KEY (scheduled rotation)
# [03:30] on-call-dev used break-glass for PROD_DB_URL
# [03:45] system: Budget exceeded on ANTHROPIC_KEY ($120 daily)
# [06:00] system: Access to STAGING_KEY expired for contractor1

# Agent monitoring — what is my agent doing:
pqvault activity --user deploy-bot --limit 50
```
