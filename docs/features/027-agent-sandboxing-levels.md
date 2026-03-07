# Feature 027: Agent Sandboxing Levels

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Medium

## Problem

The `vault_proxy` tool exists as a binary gate — either an agent can use a key through the proxy, or it cannot. There is no middle ground. Some agents need full read access to keys (e.g., deployment scripts), while others should never see the plaintext at all (e.g., a chat agent that just needs to call an API). Without tiered access levels, we either over-privilege or under-serve every agent.

## Solution

Implement three sandboxing levels for agent access: **proxy-only** (agent never sees the key value, can only make proxied requests), **read** (agent can retrieve the decrypted value), and **admin** (agent can rotate, delete, and manage keys). Each agent session is assigned a level at registration time, and each key can restrict which levels are allowed. This provides defense-in-depth — even a compromised agent at proxy-only level cannot exfiltrate key material.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/sandbox.rs` — Sandbox level definitions and enforcement
- `crates/pqvault-agent-mcp/src/lib.rs` — Integrate sandbox checks into all tool handlers
- `crates/pqvault-agent-mcp/src/session.rs` — Add sandbox level to agent session registration
- `crates/pqvault-core/src/models.rs` — Add `allowed_levels` field to key metadata

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};

/// Agent sandbox access levels, ordered by privilege
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SandboxLevel {
    /// Can only use keys through vault_proxy — never sees plaintext
    ProxyOnly = 0,
    /// Can read key values directly
    Read = 1,
    /// Can rotate, delete, create, and manage keys
    Admin = 2,
}

/// Per-key access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAccessPolicy {
    /// Minimum sandbox level required to use this key
    pub min_level: SandboxLevel,
    /// Maximum sandbox level allowed (can restrict admin on sensitive keys)
    pub max_level: SandboxLevel,
    /// Explicit agent allowlist (empty = all agents at appropriate level)
    pub allowed_agents: Vec<String>,
    /// Explicit agent denylist
    pub denied_agents: Vec<String>,
}

/// Agent session with sandbox level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub agent_id: String,
    pub pane_id: String,
    pub sandbox_level: SandboxLevel,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub last_active: chrono::DateTime<chrono::Utc>,
    pub request_count: u64,
}

impl KeyAccessPolicy {
    pub fn allows(&self, agent_id: &str, level: SandboxLevel) -> bool {
        if !self.denied_agents.is_empty() && self.denied_agents.contains(&agent_id.to_string()) {
            return false;
        }
        if !self.allowed_agents.is_empty() && !self.allowed_agents.contains(&agent_id.to_string()) {
            return false;
        }
        level >= self.min_level && level <= self.max_level
    }
}
```

### MCP Tools

```rust
/// Register agent session with a specific sandbox level
#[tool(name = "agent_register")]
async fn agent_register(
    &self,
    #[arg(description = "Agent identifier")] agent_id: String,
    #[arg(description = "Tmux pane ID")] pane_id: String,
    #[arg(description = "Sandbox level: proxy_only, read, or admin")] level: String,
) -> Result<CallToolResult, McpError> {
    let sandbox_level = SandboxLevel::from_str(&level)?;
    let session = AgentSession::new(agent_id, pane_id, sandbox_level);
    self.sessions.write().await.insert(session.agent_id.clone(), session);
    Ok(CallToolResult::success(format!("Agent registered at {level} level")))
}

/// Set access policy on a key
#[tool(name = "key_set_policy")]
async fn key_set_policy(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Minimum sandbox level")] min_level: String,
    #[arg(description = "Maximum sandbox level")] max_level: Option<String>,
    #[arg(description = "Allowed agent IDs (comma-separated)")] allowed_agents: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Check what level the current agent has for a key
#[tool(name = "check_access")]
async fn check_access(
    &self,
    #[arg(description = "Key name to check")] key_name: String,
    #[arg(description = "Agent ID")] agent_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Register an agent with a specific level
pqvault agent register --id claude-agent-1 --level proxy_only

# Set key access policy
pqvault key policy set STRIPE_SECRET_KEY --min-level read --max-level admin

# Set key to proxy-only (most restrictive)
pqvault key policy set ANTHROPIC_KEY --min-level proxy_only --max-level proxy_only

# List agent sessions and their levels
pqvault agent list

# Check access for an agent on a key
pqvault agent check-access --id claude-agent-1 --key STRIPE_SECRET_KEY
```

### Web UI Changes

- Agent sessions table showing sandbox level per agent with color coding
- Per-key access policy editor in key detail view
- Access denied events highlighted in audit log
- Sandbox level selector in agent registration dialog

## Dependencies

- `pqvault-core` — Key metadata model changes
- `pqvault-audit-mcp` — Log access denials
- `serde = "1"` (existing)
- `chrono = "0.4"` (existing)
- Feature 001 (vault_proxy) must be implemented

## Testing

### Unit Tests

```rust
#[test]
fn sandbox_level_ordering() {
    assert!(SandboxLevel::ProxyOnly < SandboxLevel::Read);
    assert!(SandboxLevel::Read < SandboxLevel::Admin);
}

#[test]
fn key_policy_allows_correct_levels() {
    let policy = KeyAccessPolicy {
        min_level: SandboxLevel::Read,
        max_level: SandboxLevel::Admin,
        allowed_agents: vec![],
        denied_agents: vec![],
    };
    assert!(!policy.allows("any", SandboxLevel::ProxyOnly));
    assert!(policy.allows("any", SandboxLevel::Read));
    assert!(policy.allows("any", SandboxLevel::Admin));
}

#[test]
fn key_policy_denylists_agent() {
    let policy = KeyAccessPolicy {
        min_level: SandboxLevel::ProxyOnly,
        max_level: SandboxLevel::Admin,
        allowed_agents: vec![],
        denied_agents: vec!["bad-agent".to_string()],
    };
    assert!(!policy.allows("bad-agent", SandboxLevel::Admin));
    assert!(policy.allows("good-agent", SandboxLevel::Admin));
}

#[test]
fn key_policy_allowlist_restricts() {
    let policy = KeyAccessPolicy {
        min_level: SandboxLevel::ProxyOnly,
        max_level: SandboxLevel::Admin,
        allowed_agents: vec!["trusted-agent".to_string()],
        denied_agents: vec![],
    };
    assert!(policy.allows("trusted-agent", SandboxLevel::Read));
    assert!(!policy.allows("other-agent", SandboxLevel::Read));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn proxy_only_agent_cannot_read_key() {
    let mcp = test_agent_mcp().await;
    mcp.agent_register("test-agent", "pane1", "proxy_only").await.unwrap();
    let result = mcp.vault_get("test-agent", "SECRET_KEY").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("insufficient sandbox level"));
}

#[tokio::test]
async fn admin_agent_can_rotate_key() {
    let mcp = test_agent_mcp().await;
    mcp.agent_register("admin-agent", "pane2", "admin").await.unwrap();
    let result = mcp.vault_rotate("admin-agent", "SECRET_KEY").await;
    assert!(result.is_ok());
}
```

### Manual Verification

1. Register agent at proxy_only level
2. Attempt vault_get — verify access denied
3. Attempt vault_proxy — verify access granted
4. Check audit log for denial entry
5. Escalate agent to read level, verify vault_get now works

## Example Usage

```bash
# Scenario: Chat agent that calls APIs but should never see keys
pqvault agent register --id chat-bot --level proxy_only
pqvault key policy set OPENAI_KEY --min-level proxy_only
# chat-bot can use vault_proxy to call OpenAI, but vault_get returns "access denied"

# Scenario: Deploy script that needs to read database URLs
pqvault agent register --id deploy-script --level read
pqvault key policy set DATABASE_URL --min-level read
# deploy-script can read DATABASE_URL value directly

# Scenario: Ops agent that manages key rotation
pqvault agent register --id ops-bot --level admin
# ops-bot can rotate, delete, and create keys
```
