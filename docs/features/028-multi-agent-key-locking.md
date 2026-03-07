# Feature 028: Multi-Agent Key Locking

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Medium

## Problem

When two or more agents attempt to use the same key simultaneously, they can hit provider rate limits by both making API calls at the same time. There is no coordination mechanism — agents are unaware of each other's key usage. This leads to wasted API credits, failed requests, and unpredictable behavior when multiple Claude Code panes operate on the same project.

## Solution

Implement a distributed lock per key so that only one agent can actively use a key at any given time. The lock uses a file-based mutex with advisory locking (flock) for single-machine scenarios, with a configurable timeout and automatic release. Agents that cannot acquire the lock receive a `LockBusy` response with estimated wait time. Locks have a maximum TTL to prevent deadlocks from crashed agents.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/locking.rs` — Distributed lock manager with flock-based locking
- `crates/pqvault-agent-mcp/src/lib.rs` — Wrap vault_proxy and vault_get calls with lock acquisition
- `crates/pqvault-core/src/lock.rs` — Lock state persistence and TTL management
- `crates/pqvault-agent-mcp/src/queue.rs` — Fair queuing for lock waiters

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// State of a key lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLock {
    pub key_name: String,
    pub holder_agent_id: String,
    pub holder_pane_id: String,
    pub acquired_at: DateTime<Utc>,
    pub max_ttl: Duration,
    pub use_count: u32,
}

/// Result of a lock acquisition attempt
#[derive(Debug)]
pub enum LockResult {
    Acquired(KeyLock),
    Busy {
        holder: String,
        estimated_wait: Duration,
        queue_position: usize,
    },
    Timeout,
}

/// Lock manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockConfig {
    /// Maximum time a lock can be held (default: 30s)
    pub max_ttl_secs: u64,
    /// Time to wait for lock acquisition (default: 10s)
    pub acquire_timeout_secs: u64,
    /// Directory for lock files
    pub lock_dir: PathBuf,
    /// Enable fair queuing (FIFO order for waiters)
    pub fair_queue: bool,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            max_ttl_secs: 30,
            acquire_timeout_secs: 10,
            lock_dir: dirs::data_local_dir()
                .unwrap_or_default()
                .join("pqvault")
                .join("locks"),
            fair_queue: true,
        }
    }
}

/// Lock manager
pub struct KeyLockManager {
    config: LockConfig,
    active_locks: tokio::sync::RwLock<HashMap<String, KeyLock>>,
    wait_queues: tokio::sync::RwLock<HashMap<String, VecDeque<String>>>,
}

impl KeyLockManager {
    pub async fn acquire(
        &self,
        key_name: &str,
        agent_id: &str,
        pane_id: &str,
    ) -> LockResult {
        let timeout = Duration::from_secs(self.config.acquire_timeout_secs);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Check for expired locks first
            self.reap_expired().await;

            let locks = self.active_locks.read().await;
            if let Some(existing) = locks.get(key_name) {
                if existing.holder_agent_id == agent_id {
                    // Re-entrant lock for same agent
                    return LockResult::Acquired(existing.clone());
                }
                let queue = self.wait_queues.read().await;
                let position = queue.get(key_name)
                    .map(|q| q.iter().position(|id| id == agent_id).unwrap_or(q.len()))
                    .unwrap_or(0);

                if tokio::time::Instant::now() >= deadline {
                    return LockResult::Timeout;
                }
                drop(locks);
                drop(queue);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            drop(locks);

            // Acquire lock
            let lock = KeyLock {
                key_name: key_name.to_string(),
                holder_agent_id: agent_id.to_string(),
                holder_pane_id: pane_id.to_string(),
                acquired_at: Utc::now(),
                max_ttl: Duration::from_secs(self.config.max_ttl_secs),
                use_count: 0,
            };
            self.active_locks.write().await.insert(key_name.to_string(), lock.clone());
            return LockResult::Acquired(lock);
        }
    }

    pub async fn release(&self, key_name: &str, agent_id: &str) -> bool {
        let mut locks = self.active_locks.write().await;
        if let Some(lock) = locks.get(key_name) {
            if lock.holder_agent_id == agent_id {
                locks.remove(key_name);
                return true;
            }
        }
        false
    }
}
```

### MCP Tools

```rust
/// Acquire a lock on a key before using it
#[tool(name = "key_lock")]
async fn key_lock(
    &self,
    #[arg(description = "Key name to lock")] key_name: String,
    #[arg(description = "Agent ID requesting the lock")] agent_id: String,
    #[arg(description = "Maximum hold time in seconds")] max_ttl: Option<u64>,
) -> Result<CallToolResult, McpError> {
    match self.lock_manager.acquire(&key_name, &agent_id, "").await {
        LockResult::Acquired(lock) => Ok(CallToolResult::success(
            format!("Lock acquired on {} by {} (TTL: {}s)", key_name, agent_id, lock.max_ttl.as_secs())
        )),
        LockResult::Busy { holder, estimated_wait, queue_position } => Ok(CallToolResult::success(
            format!("Lock busy — held by {holder}, position #{queue_position}, est. wait {estimated_wait:?}")
        )),
        LockResult::Timeout => Err(McpError::internal("Lock acquisition timed out")),
    }
}

/// Release a held lock
#[tool(name = "key_unlock")]
async fn key_unlock(
    &self,
    #[arg(description = "Key name to unlock")] key_name: String,
    #[arg(description = "Agent ID releasing the lock")] agent_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List all currently held locks
#[tool(name = "lock_status")]
async fn lock_status(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Acquire a lock manually
pqvault lock acquire --key STRIPE_KEY --agent deploy-bot --ttl 60

# Release a lock
pqvault lock release --key STRIPE_KEY --agent deploy-bot

# List active locks
pqvault lock list

# Force-release a stale lock (admin only)
pqvault lock force-release --key STRIPE_KEY

# Configure lock defaults
pqvault config set lock.max_ttl_secs 30
pqvault config set lock.acquire_timeout_secs 10
pqvault config set lock.fair_queue true
```

### Web UI Changes

- Lock status indicator on each key in the key list
- Real-time lock holder display with remaining TTL countdown
- Lock history in key detail view
- "Force Release" button for admin users

## Dependencies

- `tokio = "1"` (existing) — Async mutex and timing
- `chrono = "0.4"` (existing) — Timestamps
- `fs2 = "0.4"` — File-based advisory locking (flock)
- Feature 027 (Agent Sandboxing) — Lock acquisition respects sandbox levels

## Testing

### Unit Tests

```rust
#[tokio::test]
async fn acquire_and_release_lock() {
    let mgr = KeyLockManager::new(LockConfig::default());
    let result = mgr.acquire("KEY1", "agent-1", "pane-1").await;
    assert!(matches!(result, LockResult::Acquired(_)));
    assert!(mgr.release("KEY1", "agent-1").await);
}

#[tokio::test]
async fn second_agent_gets_busy() {
    let mgr = KeyLockManager::new(LockConfig {
        acquire_timeout_secs: 1,
        ..Default::default()
    });
    mgr.acquire("KEY1", "agent-1", "pane-1").await;
    let result = mgr.acquire("KEY1", "agent-2", "pane-2").await;
    assert!(matches!(result, LockResult::Timeout));
}

#[tokio::test]
async fn expired_lock_is_reaped() {
    let mgr = KeyLockManager::new(LockConfig {
        max_ttl_secs: 0, // Expire immediately
        acquire_timeout_secs: 2,
        ..Default::default()
    });
    mgr.acquire("KEY1", "agent-1", "pane-1").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let result = mgr.acquire("KEY1", "agent-2", "pane-2").await;
    assert!(matches!(result, LockResult::Acquired(_)));
}

#[tokio::test]
async fn reentrant_lock_succeeds() {
    let mgr = KeyLockManager::new(LockConfig::default());
    mgr.acquire("KEY1", "agent-1", "pane-1").await;
    let result = mgr.acquire("KEY1", "agent-1", "pane-1").await;
    assert!(matches!(result, LockResult::Acquired(_)));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn concurrent_agents_serialize_access() {
    let vault = test_vault().await;
    let results = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..5).map(|i| {
        let vault = vault.clone();
        let results = results.clone();
        tokio::spawn(async move {
            let lock = vault.lock_manager.acquire("SHARED_KEY", &format!("agent-{i}"), "").await;
            if let LockResult::Acquired(_) = lock {
                results.lock().await.push(i);
                tokio::time::sleep(Duration::from_millis(50)).await;
                vault.lock_manager.release("SHARED_KEY", &format!("agent-{i}")).await;
            }
        })
    }).collect();

    futures::future::join_all(handles).await;
    // All agents should have eventually gotten access
}
```

### Manual Verification

1. Open two Claude Code panes on the same project
2. Both agents attempt to use the same key simultaneously
3. Verify one gets lock, other gets `LockBusy` with queue position
4. After first agent finishes, second agent proceeds
5. Check audit log for lock acquisition/release events

## Example Usage

```bash
# Agent 1 (pane claude6:0.0):
# Calls vault_proxy for ANTHROPIC_KEY → lock acquired automatically
# Makes API call → lock released automatically

# Agent 2 (pane claude6:0.1):
# Calls vault_proxy for ANTHROPIC_KEY → gets "LockBusy, position #1, est. wait 2s"
# Retries after 2s → lock acquired → makes API call → lock released

# Manual lock for batch operations:
pqvault lock acquire --key STRIPE_KEY --agent batch-job --ttl 300
# ... run batch of 50 API calls ...
pqvault lock release --key STRIPE_KEY --agent batch-job
```
