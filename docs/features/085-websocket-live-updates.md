# Feature 085: WebSocket Live Updates

## Status: Planned
## Phase: 9 (v2.9)
## Priority: Medium

## Problem

The web dashboard shows stale data until the user manually refreshes. When a key is
rotated via CLI or MCP, the dashboard still shows the old status. In team environments,
one user's changes are invisible to others viewing the dashboard. This creates a
disconnect between actual vault state and displayed state.

## Solution

Implement WebSocket-based live updates using axum's built-in WebSocket support
(leveraging Feature 031's WebSocket infrastructure). The dashboard establishes a
persistent connection and receives real-time events when vault state changes. Updates
are granular — only affected rows are re-rendered, avoiding full page reloads.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    ws/
      mod.rs           # WebSocket module root
      handler.rs       # WebSocket upgrade handler
      broadcaster.rs   # Event broadcaster to connected clients
      events.rs        # Event types and serialization
    routes/
      ws.rs            # GET /ws - WebSocket endpoint
  static/
    js/
      live.js          # Client-side WebSocket handler
  templates/
    components/
      live_indicator.html  # Connection status indicator
```

### Data Model Changes

```rust
use axum::extract::ws::{WebSocket, Message};
use tokio::sync::broadcast;

/// Events sent to connected dashboard clients
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum VaultEvent {
    /// A key was created
    KeyCreated {
        key: String,
        category: Option<String>,
        timestamp: String,
    },
    /// A key was updated or rotated
    KeyUpdated {
        key: String,
        change: String,  // "rotated", "value_changed", "metadata_updated"
        timestamp: String,
    },
    /// A key was deleted
    KeyDeleted {
        key: String,
        timestamp: String,
    },
    /// Health status changed
    HealthChanged {
        key: String,
        old_status: String,
        new_status: String,
        timestamp: String,
    },
    /// Vault was locked/unlocked
    VaultStateChanged {
        state: String,    // "locked", "unlocked"
        timestamp: String,
    },
    /// Connection heartbeat
    Ping {
        timestamp: String,
    },
}

/// Manages WebSocket connections and broadcasts events
pub struct EventBroadcaster {
    sender: broadcast::Sender<VaultEvent>,
}

impl EventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Broadcast an event to all connected clients
    pub fn broadcast(&self, event: VaultEvent) {
        let _ = self.sender.send(event);
    }

    /// Get a new receiver for a connecting client
    pub fn subscribe(&self) -> broadcast::Receiver<VaultEvent> {
        self.sender.subscribe()
    }

    /// Number of currently connected clients
    pub fn client_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// WebSocket connection handler
pub async fn handle_ws(
    ws: WebSocket,
    broadcaster: Arc<EventBroadcaster>,
) {
    let mut rx = broadcaster.subscribe();
    let (mut ws_sender, mut ws_receiver) = ws.split();

    // Send events to client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let json = serde_json::to_string(&event).unwrap();
            if ws_sender.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    });

    // Receive pings/commands from client
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(data) => {
                    // Auto-responded by axum
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}
```

WebSocket route registration:

```rust
pub fn ws_routes() -> Router<AppState> {
    Router::new()
        .route("/ws", get(ws_upgrade))
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        handle_ws(socket, state.broadcaster.clone())
    })
}
```

### MCP Tools

No new MCP tools. Events are emitted internally when vault operations occur.

### CLI Commands

No new CLI commands.

### Web UI Changes

```javascript
// live.js - Client-side WebSocket handler
class LiveUpdater {
    constructor() {
        this.ws = null;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.connect();
    }

    connect() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${protocol}//${location.host}/ws`);

        this.ws.onopen = () => {
            this.reconnectDelay = 1000;
            this.setIndicator('connected');
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleEvent(data);
        };

        this.ws.onclose = () => {
            this.setIndicator('disconnected');
            setTimeout(() => this.connect(), this.reconnectDelay);
            this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
        };

        this.ws.onerror = () => {
            this.setIndicator('error');
        };
    }

    handleEvent(event) {
        switch (event.type) {
            case 'KeyCreated':
                this.addKeyRow(event.key, event.category);
                this.showToast(`Key created: ${event.key}`);
                break;
            case 'KeyUpdated':
                this.updateKeyRow(event.key, event.change);
                this.showToast(`Key ${event.change}: ${event.key}`);
                break;
            case 'KeyDeleted':
                this.removeKeyRow(event.key);
                this.showToast(`Key deleted: ${event.key}`);
                break;
            case 'HealthChanged':
                this.updateHealthBadge(event.key, event.new_status);
                break;
            case 'Ping':
                // Heartbeat, no action needed
                break;
        }
    }

    updateKeyRow(keyName, change) {
        const row = document.querySelector(`[data-key="${keyName}"]`);
        if (row) {
            row.classList.add('updated');
            setTimeout(() => row.classList.remove('updated'), 2000);
            // Fetch fresh data for this row
            this.refreshRow(keyName);
        }
    }

    setIndicator(status) {
        const indicator = document.getElementById('live-indicator');
        if (indicator) {
            indicator.className = `live-indicator ${status}`;
            indicator.title = status === 'connected'
                ? 'Live updates active'
                : 'Reconnecting...';
        }
    }
}

const liveUpdater = new LiveUpdater();
```

## Dependencies

No new dependencies. Uses axum's built-in WebSocket support and tokio broadcast channels.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = VaultEvent::KeyUpdated {
            key: "API_KEY".into(),
            change: "rotated".into(),
            timestamp: "2025-03-15T10:00:00Z".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("KeyUpdated"));
        assert!(json.contains("API_KEY"));
    }

    #[test]
    fn test_broadcaster_subscribe() {
        let broadcaster = EventBroadcaster::new(100);
        let mut rx = broadcaster.subscribe();
        broadcaster.broadcast(VaultEvent::Ping { timestamp: "now".into() });
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, VaultEvent::Ping { .. }));
    }

    #[test]
    fn test_broadcaster_client_count() {
        let broadcaster = EventBroadcaster::new(100);
        assert_eq!(broadcaster.client_count(), 0);
        let _rx1 = broadcaster.subscribe();
        assert_eq!(broadcaster.client_count(), 1);
        let _rx2 = broadcaster.subscribe();
        assert_eq!(broadcaster.client_count(), 2);
    }

    #[test]
    fn test_event_types_complete() {
        let events = vec![
            VaultEvent::KeyCreated { key: "K".into(), category: None, timestamp: "t".into() },
            VaultEvent::KeyUpdated { key: "K".into(), change: "rotated".into(), timestamp: "t".into() },
            VaultEvent::KeyDeleted { key: "K".into(), timestamp: "t".into() },
            VaultEvent::HealthChanged { key: "K".into(), old_status: "healthy".into(), new_status: "warning".into(), timestamp: "t".into() },
            VaultEvent::VaultStateChanged { state: "locked".into(), timestamp: "t".into() },
            VaultEvent::Ping { timestamp: "t".into() },
        ];
        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.len() > 10);
        }
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_ws_connection() {
    let app = test_app().await;
    let (mut ws, _) = tokio_tungstenite::connect_async("ws://localhost:3001/ws")
        .await.unwrap();
    // Connection should succeed
    ws.close(None).await.unwrap();
}

#[tokio::test]
async fn test_ws_receives_events() {
    let app = test_app().await;
    let (mut ws, _) = tokio_tungstenite::connect_async("ws://localhost:3001/ws")
        .await.unwrap();

    // Trigger a vault change
    app.post("/api/keys").json(&json!({"key": "NEW", "value": "v"})).await;

    // Should receive KeyCreated event
    let msg = ws.next().await.unwrap().unwrap();
    let event: VaultEvent = serde_json::from_str(&msg.to_text().unwrap()).unwrap();
    assert!(matches!(event, VaultEvent::KeyCreated { .. }));
}
```

## Example Usage

```
Dashboard with live indicator:

┌─────────────────────────────────────────────────────────┐
│  PQVault Dashboard           [Live] [Dark] [Settings]  │
│                                 ^                       │
│                            green dot = connected        │
├─────────────────────────────────────────────────────────┤

When another user rotates a key via CLI:

┌─────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────┐            │
│  │  Key rotated: STRIPE_SECRET_KEY         │  <- toast  │
│  └─────────────────────────────────────────┘            │
│                                                         │
│  STRIPE_SECRET_KEY  payment  healthy  [just now]  ← highlighted
│  AWS_ACCESS_KEY     cloud    healthy  15d ago           │
│  DATABASE_URL       db       warning  90d ago           │
└─────────────────────────────────────────────────────────┘
```
