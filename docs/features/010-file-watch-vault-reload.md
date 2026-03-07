# Feature 010: File-Watch Vault Reload

## Status: Planned
## Phase: 1 (v2.1)
## Priority: High

## Problem

The web server loads the vault file once at startup and holds it in memory. When the CLI or MCP tools modify the vault (add, delete, rotate), the web dashboard becomes stale — showing outdated data, potentially overwriting newer changes when the user interacts with the dashboard. This causes data loss and confusion. Users must manually restart the web server after every CLI operation.

## Solution

The web server watches `~/.pqvault/vault.enc` for filesystem changes using the `notify` crate. When the file changes, the server automatically reloads the vault from disk into memory. A debounce mechanism (500ms) prevents rapid reloads during multi-step operations. WebSocket notifications push updates to connected browsers for real-time UI refresh.

## Implementation

### Files to Create/Modify

- `crates/pqvault-web/src/watcher.rs` — File watcher setup and reload logic
- `crates/pqvault-web/src/lib.rs` — Integrate watcher into server startup
- `crates/pqvault-web/src/web.rs` — Add WebSocket endpoint for live-reload notifications
- `crates/pqvault-web/static/app.js` — Add WebSocket client for auto-refresh
- `crates/pqvault-core/src/vault.rs` — Add `reload()` method to Vault

### Data Model Changes

Add reload capability to Vault:

```rust
impl Vault {
    /// Reload vault from disk, replacing in-memory state
    pub fn reload(&mut self, master_password: &str) -> Result<()> {
        let new_vault = Vault::load(&self.path, master_password)?;
        self.entries = new_vault.entries;
        self.metadata = new_vault.metadata;
        self.last_loaded = chrono::Utc::now();
        Ok(())
    }
}
```

Shared state wrapper:

```rust
/// Thread-safe vault state shared between web handlers and watcher
pub struct VaultState {
    vault: RwLock<Vault>,
    master_password: String,
    last_reload: AtomicU64,
    reload_count: AtomicU64,
}

impl VaultState {
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, Vault> {
        self.vault.read().await
    }

    pub async fn reload(&self) -> Result<()> {
        let mut vault = self.vault.write().await;
        vault.reload(&self.master_password)?;
        self.last_reload.store(
            chrono::Utc::now().timestamp() as u64,
            Ordering::Relaxed,
        );
        self.reload_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
```

### MCP Tools

No new MCP tools. The file watcher is internal to the web server.

### CLI Commands

```bash
# Web server with file watching enabled (default)
pqvault web

# Web server with file watching disabled
pqvault web --no-watch

# Web server with custom debounce interval
pqvault web --watch-debounce 1000  # 1 second debounce
```

### Web UI Changes

- Real-time notification bar when vault is reloaded: "Vault updated — showing latest data"
- Automatic table refresh when vault changes
- WebSocket connection indicator in footer

## Core Implementation

### File Watcher

```rust
// crates/pqvault-web/src/watcher.rs

use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use anyhow::Result;

pub struct VaultWatcher {
    _watcher: RecommendedWatcher,
    reload_tx: broadcast::Sender<VaultReloadEvent>,
}

#[derive(Debug, Clone)]
pub struct VaultReloadEvent {
    pub timestamp: String,
    pub entry_count: usize,
}

impl VaultWatcher {
    pub fn new(
        vault_path: PathBuf,
        vault_state: Arc<VaultState>,
        debounce_ms: u64,
    ) -> Result<(Self, broadcast::Receiver<VaultReloadEvent>)> {
        let (reload_tx, reload_rx) = broadcast::channel(16);
        let tx = reload_tx.clone();

        // Channel for raw file events
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(100);

        // Create filesystem watcher
        let watcher_event_tx = event_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            let _ = watcher_event_tx.blocking_send(event);
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        )?;

        // Watch the vault file's parent directory
        // (watching the file directly can miss atomic rename writes)
        let watch_dir = vault_path.parent()
            .ok_or_else(|| anyhow::anyhow!("Vault path has no parent directory"))?;
        watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;

        let vault_filename = vault_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Spawn debounced reload task
        let state = vault_state.clone();
        tokio::spawn(async move {
            let mut pending_reload = false;

            loop {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        // Check if the event is for our vault file
                        let is_vault_file = event.paths.iter().any(|p| {
                            p.file_name()
                                .map(|f| f.to_string_lossy().to_string())
                                .unwrap_or_default()
                                == vault_filename
                        });

                        if is_vault_file {
                            pending_reload = true;
                        }
                    }
                    _ = sleep(Duration::from_millis(debounce_ms)), if pending_reload => {
                        pending_reload = false;
                        match state.reload().await {
                            Ok(()) => {
                                let vault = state.read().await;
                                let event = VaultReloadEvent {
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    entry_count: vault.entries.len(),
                                };
                                eprintln!(
                                    "[watcher] Vault reloaded: {} entries",
                                    event.entry_count
                                );
                                let _ = tx.send(event);
                            }
                            Err(e) => {
                                eprintln!("[watcher] Failed to reload vault: {}", e);
                            }
                        }
                    }
                    else => {
                        // No events and no pending reload, wait for next event
                        if let Some(event) = event_rx.recv().await {
                            let is_vault_file = event.paths.iter().any(|p| {
                                p.file_name()
                                    .map(|f| f.to_string_lossy().to_string())
                                    .unwrap_or_default()
                                    == vault_filename
                            });
                            if is_vault_file {
                                pending_reload = true;
                            }
                        } else {
                            break; // Channel closed
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                reload_tx,
            },
            reload_rx,
        ))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<VaultReloadEvent> {
        self.reload_tx.subscribe()
    }
}
```

### WebSocket Endpoint

```rust
// In crates/pqvault-web/src/web.rs

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.reload_rx.resubscribe();

    loop {
        tokio::select! {
            Ok(event) = rx.recv() => {
                let msg = serde_json::json!({
                    "type": "vault_reload",
                    "timestamp": event.timestamp,
                    "entry_count": event.entry_count,
                });
                if socket.send(Message::Text(msg.to_string())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

// Add to router:
// .route("/ws", get(ws_handler))
```

### Client-Side WebSocket (app.js addition)

```javascript
// Add to crates/pqvault-web/static/app.js

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
        console.log('[pqvault] WebSocket connected');
        updateConnectionIndicator(true);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'vault_reload') {
            console.log('[pqvault] Vault reloaded:', data.entry_count, 'entries');
            showNotification('Vault updated — refreshing...');
            loadSecrets();
            loadStatus();
        }
    };

    ws.onclose = () => {
        console.log('[pqvault] WebSocket disconnected, reconnecting in 5s...');
        updateConnectionIndicator(false);
        setTimeout(connectWebSocket, 5000);
    };

    ws.onerror = () => {
        ws.close();
    };
}

function updateConnectionIndicator(connected) {
    const indicator = document.getElementById('ws-indicator');
    if (indicator) {
        indicator.className = connected ? 'connected' : 'disconnected';
        indicator.title = connected ? 'Live updates active' : 'Reconnecting...';
    }
}

// Connect on page load
connectWebSocket();
```

## Dependencies

- `notify = "6"` — Cross-platform filesystem event watching
- `tokio = { version = "1", features = ["sync", "time"] }` — Already a dependency
- No new JavaScript dependencies

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_vault_reload_on_file_change() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");

        // Create initial vault
        let mut vault = Vault::new(&vault_path, "password");
        vault.add_entry("KEY_1", "value1", "api", None, "password").unwrap();
        vault.save().unwrap();

        let state = Arc::new(VaultState::new(vault, "password".into()));
        let (watcher, mut rx) = VaultWatcher::new(
            vault_path.clone(),
            state.clone(),
            100, // 100ms debounce for testing
        ).unwrap();

        // Modify vault via a separate "CLI" operation
        {
            let mut vault2 = Vault::load(&vault_path, "password").unwrap();
            vault2.add_entry("KEY_2", "value2", "api", None, "password").unwrap();
            vault2.save().unwrap();
        }

        // Wait for watcher to detect and reload
        let event = tokio::time::timeout(
            Duration::from_secs(5),
            rx.recv(),
        ).await.unwrap().unwrap();

        assert_eq!(event.entry_count, 2);

        // Verify in-memory state updated
        let vault = state.read().await;
        assert_eq!(vault.entries.len(), 2);
    }

    #[tokio::test]
    async fn test_debounce_prevents_rapid_reloads() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");

        let mut vault = Vault::new(&vault_path, "password");
        vault.save().unwrap();

        let state = Arc::new(VaultState::new(vault, "password".into()));
        let (watcher, mut rx) = VaultWatcher::new(
            vault_path.clone(),
            state.clone(),
            500, // 500ms debounce
        ).unwrap();

        // Rapidly modify vault 5 times
        for i in 0..5 {
            let mut v = Vault::load(&vault_path, "password").unwrap();
            v.add_entry(&format!("KEY_{}", i), "val", "api", None, "password").unwrap();
            v.save().unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Should only get 1 reload event (debounced)
        let event = tokio::time::timeout(
            Duration::from_secs(5),
            rx.recv(),
        ).await.unwrap().unwrap();

        // After debounce, should have all 5 entries
        assert_eq!(event.entry_count, 5);

        // Verify no more events within a short window
        let no_event = tokio::time::timeout(
            Duration::from_millis(200),
            rx.recv(),
        ).await;
        assert!(no_event.is_err()); // Timeout = no extra events
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_web_server_reflects_cli_changes() {
    let (server, vault_path) = start_test_web_server().await;
    let client = reqwest::Client::new();

    // Initial state
    let resp = client.get(&format!("{}/api/secrets", server.url())).send().await.unwrap();
    let data: serde_json::Value = resp.json().await.unwrap();
    let initial_count = data["secrets"].as_array().unwrap().len();

    // Modify vault externally (simulating CLI)
    let mut vault = Vault::load(&vault_path, "password").unwrap();
    vault.add_entry("NEW_KEY", "new_value", "api", None, "password").unwrap();
    vault.save().unwrap();

    // Wait for watcher to reload
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Web server should now show the new key
    let resp = client.get(&format!("{}/api/secrets", server.url())).send().await.unwrap();
    let data: serde_json::Value = resp.json().await.unwrap();
    let new_count = data["secrets"].as_array().unwrap().len();

    assert_eq!(new_count, initial_count + 1);
}
```

### Manual Verification

1. Start `pqvault web` and open dashboard in browser
2. In another terminal, run `pqvault add --name TEST_KEY --value test123`
3. Dashboard should auto-refresh and show the new key within 1 second
4. Delete a key via CLI — dashboard should reflect the deletion
5. Check the notification bar shows "Vault updated" messages

## Example Usage

```bash
# Terminal 1: Start web server with watching
$ pqvault web
PQVault dashboard: http://localhost:3000
File watcher: active (debounce: 500ms)
WebSocket: listening for browser connections

# Terminal 2: Make changes via CLI
$ pqvault add --name NEW_API_KEY --value sk_test_123 --category api
Added: NEW_API_KEY [api]

# Terminal 1 output:
[watcher] Vault reloaded: 16 entries

# Browser: Automatically shows updated table with NEW_API_KEY
# Notification: "Vault updated — showing latest data"
```
