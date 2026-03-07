# Feature 024: Session-Based Access

## Status: Planned
## Phase: 3 (v2.3)
## Priority: High

## Problem

Agent tokens persist indefinitely — or until they expire or are manually revoked. If an agent crashes, gets killed, or its session ends, the token remains active. A stale token from a terminated agent process can be picked up by malware or reused in an unintended context. There is no concept of "this agent is currently running" vs "this agent finished hours ago." Keys stay accessible long after they are needed.

## Solution

Tie agent tokens to sessions with configurable TTL (Time To Live). When an agent starts, it creates a session. The session must be kept alive with periodic heartbeats. If heartbeats stop (agent crashed), the session expires and the token is automatically suspended. Sessions can be explicitly ended when work is complete. This ensures secrets are only accessible while the agent is actively running.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/sessions.rs` — Session lifecycle management
- `crates/pqvault-agent-mcp/src/lib.rs` — Register session MCP tools
- `crates/pqvault-core/src/models.rs` — AgentSession struct
- `crates/pqvault-agent-mcp/src/tokens.rs` — Link tokens to sessions

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentSession {
    /// Unique session identifier
    pub session_id: String,
    /// Agent token ID this session belongs to
    pub agent_token_id: String,
    /// Session creation time
    pub created_at: String,
    /// Last heartbeat received
    pub last_heartbeat: String,
    /// Session TTL in seconds (how long after last heartbeat before expiry)
    pub ttl_seconds: u64,
    /// Session status
    pub status: SessionStatus,
    /// What the agent is doing (optional context)
    pub context: Option<String>,
    /// Process ID of the agent (for correlation)
    pub pid: Option<u32>,
    /// Hostname where the agent is running
    pub hostname: Option<String>,
    /// Number of requests made in this session
    pub request_count: u64,
    /// Total cost in this session
    pub session_cost_usd: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SessionStatus {
    /// Session is active and receiving heartbeats
    Active,
    /// Session has not received a heartbeat within TTL
    Expired,
    /// Session was explicitly ended by the agent
    Ended,
    /// Session was forcefully terminated by an admin
    Terminated,
}

/// Add session_id to AgentToken for session-bound tokens
pub struct AgentToken {
    // ... existing fields ...
    /// If set, this token is only valid within this session
    pub bound_session_id: Option<String>,
}
```

### MCP Tools

```rust
// Tool: agent_session_start
{
    "name": "agent_session_start",
    "description": "Start a new agent session with TTL",
    "params": {
        "agent_token": "pqv_agt_...",
        "ttl_seconds": 3600,           // 1 hour
        "context": "Processing customer data",
        "pid": 12345,
        "hostname": "dev-machine"
    },
    "returns": {
        "session_id": "ses_abc123",
        "expires_at": "2025-01-15T11:00:00Z",
        "heartbeat_interval_seconds": 60
    }
}

// Tool: agent_session_heartbeat
{
    "name": "agent_session_heartbeat",
    "description": "Keep session alive with a heartbeat",
    "params": {
        "session_id": "ses_abc123"
    },
    "returns": {
        "alive": true,
        "next_heartbeat_by": "2025-01-15T10:01:00Z",
        "session_uptime_seconds": 1800,
        "request_count": 42,
        "session_cost_usd": 3.50
    }
}

// Tool: agent_session_end
{
    "name": "agent_session_end",
    "description": "Explicitly end an agent session",
    "params": {
        "session_id": "ses_abc123"
    },
    "returns": {
        "ended": true,
        "duration_seconds": 3600,
        "total_requests": 142,
        "total_cost_usd": 8.50
    }
}

// Tool: agent_session_list
{
    "name": "agent_session_list",
    "params": {},
    "returns": {
        "sessions": [
            {
                "session_id": "ses_abc123",
                "agent_name": "code-gen-agent",
                "status": "active",
                "uptime": "30m",
                "last_heartbeat": "15s ago",
                "requests": 42
            }
        ]
    }
}

// Tool: agent_session_terminate
{
    "name": "agent_session_terminate",
    "description": "Admin: forcefully terminate an agent session",
    "params": {
        "session_id": "ses_abc123",
        "reason": "Suspicious activity"
    },
    "returns": { "terminated": true }
}
```

### CLI Commands

```bash
# List active sessions
pqvault session list

# Show session details
pqvault session show ses_abc123

# Terminate a session
pqvault session terminate ses_abc123 --reason "Unauthorized access"

# Cleanup expired sessions
pqvault session cleanup

# View session history
pqvault session history --agent agt_abc123

# Set default session TTL
pqvault session config --default-ttl 3600
```

## Core Implementation

```rust
// crates/pqvault-agent-mcp/src/sessions.rs

use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use anyhow::{bail, Result};

pub struct SessionManager {
    sessions: HashMap<String, AgentSession>,
    default_ttl: u64,
}

impl SessionManager {
    pub fn new(default_ttl: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            default_ttl,
        }
    }

    /// Start a new agent session
    pub fn start_session(
        &mut self,
        agent_token_id: &str,
        ttl_seconds: Option<u64>,
        context: Option<String>,
        pid: Option<u32>,
        hostname: Option<String>,
    ) -> Result<AgentSession> {
        // Check if agent already has an active session
        let existing = self.sessions.values()
            .find(|s| s.agent_token_id == agent_token_id && s.status == SessionStatus::Active);

        if let Some(existing) = existing {
            bail!(
                "Agent already has active session '{}'. End it first or use heartbeat.",
                existing.session_id
            );
        }

        let session_id = format!("ses_{}", &uuid::Uuid::new_v4().to_string()[..12]);
        let now = Utc::now().to_rfc3339();
        let ttl = ttl_seconds.unwrap_or(self.default_ttl);

        let session = AgentSession {
            session_id: session_id.clone(),
            agent_token_id: agent_token_id.to_string(),
            created_at: now.clone(),
            last_heartbeat: now,
            ttl_seconds: ttl,
            status: SessionStatus::Active,
            context,
            pid,
            hostname,
            request_count: 0,
            session_cost_usd: 0.0,
        };

        self.sessions.insert(session_id, session.clone());
        Ok(session)
    }

    /// Process a heartbeat
    pub fn heartbeat(&mut self, session_id: &str) -> Result<HeartbeatResponse> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", session_id))?;

        if session.status != SessionStatus::Active {
            bail!("Session '{}' is not active (status: {:?})", session_id, session.status);
        }

        session.last_heartbeat = Utc::now().to_rfc3339();

        let uptime = Utc::now() - DateTime::parse_from_rfc3339(&session.created_at)
            .unwrap().with_timezone(&Utc);

        Ok(HeartbeatResponse {
            alive: true,
            next_heartbeat_by: (Utc::now() + Duration::seconds(session.ttl_seconds as i64 / 2)).to_rfc3339(),
            session_uptime_seconds: uptime.num_seconds() as u64,
            request_count: session.request_count,
            session_cost_usd: session.session_cost_usd,
        })
    }

    /// End a session gracefully
    pub fn end_session(&mut self, session_id: &str) -> Result<SessionEndResult> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", session_id))?;

        session.status = SessionStatus::Ended;

        let duration = Utc::now() - DateTime::parse_from_rfc3339(&session.created_at)
            .unwrap().with_timezone(&Utc);

        Ok(SessionEndResult {
            session_id: session_id.to_string(),
            duration_seconds: duration.num_seconds() as u64,
            total_requests: session.request_count,
            total_cost_usd: session.session_cost_usd,
        })
    }

    /// Check if a session is valid for use
    pub fn validate_session(&self, session_id: &str) -> Result<&AgentSession> {
        let session = self.sessions.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", session_id))?;

        if session.status != SessionStatus::Active {
            bail!("Session '{}' is {:?}", session_id, session.status);
        }

        // Check if heartbeat has expired
        let last_hb = DateTime::parse_from_rfc3339(&session.last_heartbeat)
            .map_err(|_| anyhow::anyhow!("Invalid heartbeat timestamp"))?
            .with_timezone(&Utc);

        let ttl = Duration::seconds(session.ttl_seconds as i64);
        if Utc::now() > last_hb + ttl {
            // Session expired due to missed heartbeat
            // Note: actual status update happens in expire_stale_sessions()
            bail!(
                "Session '{}' expired: last heartbeat was {} ago, TTL is {}s",
                session_id,
                (Utc::now() - last_hb).num_seconds(),
                session.ttl_seconds,
            );
        }

        Ok(session)
    }

    /// Expire all sessions that have missed their heartbeat TTL
    pub fn expire_stale_sessions(&mut self) -> Vec<String> {
        let now = Utc::now();
        let mut expired = Vec::new();

        for session in self.sessions.values_mut() {
            if session.status != SessionStatus::Active {
                continue;
            }

            let last_hb = match DateTime::parse_from_rfc3339(&session.last_heartbeat) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(_) => continue,
            };

            let ttl = Duration::seconds(session.ttl_seconds as i64);
            if now > last_hb + ttl {
                session.status = SessionStatus::Expired;
                expired.push(session.session_id.clone());
            }
        }

        expired
    }

    /// Terminate a session forcefully (admin action)
    pub fn terminate_session(&mut self, session_id: &str, reason: &str) -> Result<()> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", session_id))?;

        session.status = SessionStatus::Terminated;
        session.context = Some(format!("Terminated: {}", reason));
        Ok(())
    }

    /// Record a request in a session
    pub fn record_request(&mut self, session_id: &str, cost_usd: f64) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.request_count += 1;
            session.session_cost_usd += cost_usd;
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub alive: bool,
    pub next_heartbeat_by: String,
    pub session_uptime_seconds: u64,
    pub request_count: u64,
    pub session_cost_usd: f64,
}

#[derive(Debug, Serialize)]
pub struct SessionEndResult {
    pub session_id: String,
    pub duration_seconds: u64,
    pub total_requests: u64,
    pub total_cost_usd: f64,
}
```

## Dependencies

- `uuid = { version = "1", features = ["v4"] }` — Session ID generation
- Uses existing `chrono`
- Requires Feature 021 (Agent-Scoped Tokens) for token-session binding

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_session() {
        let mut manager = SessionManager::new(3600);
        let session = manager.start_session("agt_1", Some(300), None, None, None).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.ttl_seconds, 300);
    }

    #[test]
    fn test_heartbeat_keeps_alive() {
        let mut manager = SessionManager::new(3600);
        let session = manager.start_session("agt_1", Some(300), None, None, None).unwrap();
        let resp = manager.heartbeat(&session.session_id).unwrap();
        assert!(resp.alive);
    }

    #[test]
    fn test_expired_session_fails_validation() {
        let mut manager = SessionManager::new(3600);
        let session = manager.start_session("agt_1", Some(1), None, None, None).unwrap();

        // Manually set last heartbeat to the past
        manager.sessions.get_mut(&session.session_id).unwrap().last_heartbeat =
            (Utc::now() - Duration::seconds(10)).to_rfc3339();

        let result = manager.validate_session(&session.session_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_session() {
        let mut manager = SessionManager::new(3600);
        let session = manager.start_session("agt_1", None, None, None, None).unwrap();

        manager.record_request(&session.session_id, 1.5);
        manager.record_request(&session.session_id, 2.0);

        let result = manager.end_session(&session.session_id).unwrap();
        assert_eq!(result.total_requests, 2);
        assert!((result.total_cost_usd - 3.5).abs() < 0.01);
    }

    #[test]
    fn test_duplicate_session_rejected() {
        let mut manager = SessionManager::new(3600);
        manager.start_session("agt_1", None, None, None, None).unwrap();
        let result = manager.start_session("agt_1", None, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_stale_sessions() {
        let mut manager = SessionManager::new(3600);
        let s1 = manager.start_session("agt_1", Some(1), None, None, None).unwrap();
        let s2 = manager.start_session("agt_2", Some(86400), None, None, None).unwrap();

        // Set s1's heartbeat to the past
        manager.sessions.get_mut(&s1.session_id).unwrap().last_heartbeat =
            (Utc::now() - Duration::seconds(10)).to_rfc3339();

        let expired = manager.expire_stale_sessions();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], s1.session_id);

        // s2 should still be active
        assert_eq!(manager.sessions[&s2.session_id].status, SessionStatus::Active);
    }

    #[test]
    fn test_terminate_session() {
        let mut manager = SessionManager::new(3600);
        let session = manager.start_session("agt_1", None, None, None, None).unwrap();

        manager.terminate_session(&session.session_id, "Suspicious").unwrap();

        let s = &manager.sessions[&session.session_id];
        assert_eq!(s.status, SessionStatus::Terminated);
    }
}
```

### Manual Verification

1. Start a session with 60s TTL
2. Send heartbeats every 30s — session stays active
3. Stop heartbeats — session should expire after 60s
4. Verify requests are rejected after session expires
5. Start new session — verify it works normally

## Example Usage

```bash
# Agent starts a session
$ pqvault session start --agent agt_abc123 --ttl 3600 --context "Processing batch job"
Session started: ses_abc123def456
  TTL: 1 hour
  Heartbeat interval: every 30s
  Expires at: 2025-01-15T11:00:00Z

# List active sessions
$ pqvault session list
Session         Agent            Status    Uptime    Last HB    Requests    Cost
ses_abc123      code-gen-agent   ACTIVE    30m       15s ago    42          $3.50
ses_def456      ci-pipeline      ACTIVE    2h        5s ago     180         $0.90

# Terminate a suspicious session
$ pqvault session terminate ses_abc123 --reason "Unusual API access pattern"
Session 'ses_abc123' terminated. Agent token suspended.

# Agent session expired (no heartbeat)
$ pqvault session list
Session         Agent            Status     Uptime    Last HB      Requests
ses_abc123      code-gen-agent   EXPIRED    45m       16m ago      42
  Expired: no heartbeat for 960s (TTL: 60s)
```
