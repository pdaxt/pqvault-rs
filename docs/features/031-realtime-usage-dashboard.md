# Feature 031: Real-Time Usage Dashboard

## Status: Planned
## Phase: 4 (v2.4)
## Priority: Critical

## Problem

The dashboard shows static data that requires manual page refresh to see updates. There are no live usage counts, no real-time cost tracking, and no streaming trend visualization. When multiple agents are actively using keys, the dashboard is stale the moment it renders. Operators have no situational awareness of what is happening in the vault right now.

## Solution

Add a WebSocket endpoint at `/ws/dashboard` that pushes real-time usage updates to connected clients. The server maintains an in-memory event bus that aggregates key usage events and broadcasts them every second. Clients receive incremental updates including live request counts, cost deltas, active agent sessions, and anomaly alerts. The web UI subscribes on load and renders a real-time dashboard with animated counters and sparkline charts.

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/src/ws.rs` — WebSocket handler and event broadcasting
- `crates/pqvault-web/src/dashboard.rs` — Dashboard data aggregation and snapshot generation
- `crates/pqvault-web/src/routes.rs` — Register `/ws/dashboard` route
- `crates/pqvault-web/src/event_bus.rs` — In-memory pub/sub for vault events
- `crates/pqvault-web/static/js/dashboard.js` — Client-side WebSocket consumer and chart rendering

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Real-time dashboard event pushed via WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DashboardEvent {
    /// Key was accessed (read or proxy)
    KeyAccess {
        key_name: String,
        agent_id: Option<String>,
        access_type: String, // "read", "proxy", "rotate"
        timestamp: DateTime<Utc>,
    },
    /// Cost update for a key
    CostDelta {
        key_name: String,
        cost_usd: f64,
        daily_total: f64,
        monthly_total: f64,
        timestamp: DateTime<Utc>,
    },
    /// Agent session state change
    AgentStatus {
        agent_id: String,
        pane_id: String,
        status: String, // "connected", "disconnected", "idle"
        timestamp: DateTime<Utc>,
    },
    /// Anomaly detected
    AnomalyAlert {
        key_name: String,
        metric: String,
        expected: f64,
        actual: f64,
        severity: String,
        timestamp: DateTime<Utc>,
    },
    /// Periodic snapshot (sent every 5 seconds)
    Snapshot {
        total_keys: usize,
        active_agents: usize,
        requests_per_minute: f64,
        daily_cost_usd: f64,
        top_keys: Vec<KeyUsageSummary>,
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsageSummary {
    pub key_name: String,
    pub requests_1h: u64,
    pub cost_today: f64,
    pub last_used: DateTime<Utc>,
    pub trend: Vec<f64>, // Last 60 data points (1 per minute)
}

/// Event bus for broadcasting dashboard events
pub struct EventBus {
    sender: broadcast::Sender<DashboardEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: DashboardEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DashboardEvent> {
        self.sender.subscribe()
    }
}
```

### WebSocket Handler

```rust
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};

pub async fn ws_dashboard(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.event_bus.subscribe();

    // Send initial snapshot
    let snapshot = state.dashboard.snapshot().await;
    let msg = serde_json::to_string(&snapshot).unwrap();
    let _ = sender.send(Message::Text(msg)).await;

    // Forward events to client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let msg = serde_json::to_string(&event).unwrap();
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Handle client messages (ping/pong, filters)
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(data) => { /* pong handled by axum */ },
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}
```

### MCP Tools

No new MCP tools — the dashboard is a web-only feature. However, the event bus is fed by existing MCP tool calls:

```rust
// In vault_get handler:
self.event_bus.publish(DashboardEvent::KeyAccess {
    key_name: key_name.clone(),
    agent_id: session.map(|s| s.agent_id.clone()),
    access_type: "read".to_string(),
    timestamp: Utc::now(),
});
```

### CLI Commands

```bash
# Open dashboard in browser
pqvault dashboard

# Stream dashboard events to terminal (for headless use)
pqvault dashboard --stream
# [14:30:01] KeyAccess: ANTHROPIC_KEY by claude-agent-1 (proxy)
# [14:30:02] CostDelta: ANTHROPIC_KEY +$0.003 (daily: $1.23)
# [14:30:05] Snapshot: 42 keys, 3 agents, 12.4 req/min, $4.56 today

# Export dashboard snapshot as JSON
pqvault dashboard --snapshot > dashboard.json
```

### Web UI Changes

- Live request counter with animation (requests/minute)
- Real-time cost ticker (daily and monthly running totals)
- Sparkline charts per key showing last 60 minutes of usage
- Active agents panel with status indicators (green/yellow/red)
- Anomaly alert banner that appears in real-time
- Auto-reconnecting WebSocket connection with exponential backoff

## Dependencies

- `tokio-tungstenite = "0.24"` — WebSocket support for axum (new dependency)
- `axum = "0.8"` (existing) — HTTP/WebSocket routing
- `tokio = { version = "1", features = ["sync"] }` (existing) — broadcast channels
- `serde_json = "1"` (existing) — Event serialization
- Feature 031 requires audit logging infrastructure from Phase 2

## Testing

### Unit Tests

```rust
#[test]
fn event_bus_delivers_to_subscribers() {
    let bus = EventBus::new(100);
    let mut rx = bus.subscribe();
    bus.publish(DashboardEvent::KeyAccess {
        key_name: "TEST".into(),
        agent_id: None,
        access_type: "read".into(),
        timestamp: Utc::now(),
    });
    let event = rx.try_recv().unwrap();
    assert!(matches!(event, DashboardEvent::KeyAccess { .. }));
}

#[test]
fn snapshot_includes_top_keys() {
    let dashboard = Dashboard::new();
    dashboard.record_access("KEY_A", 100);
    dashboard.record_access("KEY_B", 50);
    let snap = dashboard.snapshot_sync();
    assert_eq!(snap.top_keys[0].key_name, "KEY_A");
}

#[test]
fn event_serialization_roundtrip() {
    let event = DashboardEvent::CostDelta {
        key_name: "OPENAI_KEY".into(),
        cost_usd: 0.003,
        daily_total: 1.23,
        monthly_total: 34.56,
        timestamp: Utc::now(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: DashboardEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, DashboardEvent::CostDelta { .. }));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn websocket_receives_events() {
    let app = test_app().await;
    let addr = app.listen_addr();

    let (mut ws, _) = tokio_tungstenite::connect_async(
        format!("ws://{addr}/ws/dashboard")
    ).await.unwrap();

    // Trigger a vault access
    app.vault.get("TEST_KEY").await.unwrap();

    // Should receive the event
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
    assert!(msg.is_ok());
    let text = msg.unwrap().unwrap().unwrap().into_text().unwrap();
    assert!(text.contains("KeyAccess"));
}

#[tokio::test]
async fn websocket_sends_initial_snapshot() {
    let app = test_app().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(
        format!("ws://{}/ws/dashboard", app.listen_addr())
    ).await.unwrap();

    let msg = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let event: DashboardEvent = serde_json::from_str(&msg).unwrap();
    assert!(matches!(event, DashboardEvent::Snapshot { .. }));
}
```

### Manual Verification

1. Start web server, open dashboard in browser
2. Make vault_proxy calls from a Claude Code agent
3. Verify counters update in real-time without page refresh
4. Disconnect network briefly, verify WebSocket reconnects
5. Open multiple dashboard tabs, verify all receive updates

## Example Usage

```javascript
// Client-side WebSocket consumer
const ws = new WebSocket('ws://localhost:3001/ws/dashboard');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    switch (data.type) {
        case 'Snapshot':
            updateCounters(data.total_keys, data.active_agents, data.requests_per_minute);
            updateCostTicker(data.daily_cost_usd);
            updateTopKeys(data.top_keys);
            break;
        case 'KeyAccess':
            flashAccessIndicator(data.key_name);
            incrementCounter();
            break;
        case 'AnomalyAlert':
            showAlertBanner(data);
            break;
    }
};

// Auto-reconnect with exponential backoff
ws.onclose = () => setTimeout(() => connect(), backoff());
```
