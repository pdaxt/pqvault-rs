# Feature 021: Agent-Scoped Tokens

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Critical

## Problem

All AI agents that connect to PQVault via MCP have unrestricted access to every secret in the vault. A code-generation agent can read production database passwords. A content agent can access payment keys. There is no access control, no principle of least privilege, and no way to limit what an agent can see or do. If any single agent is compromised, all secrets are exposed.

## Solution

Each AI agent gets a scoped token that defines exactly which keys it can access and what operations it can perform. Tokens are stored encrypted in the vault metadata. The MCP layer validates tokens before serving requests. Tokens support allow-lists for specific keys, wildcard patterns, category restrictions, and operation limits (read-only vs read-write).

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/tokens.rs` — Token creation, validation, storage, and revocation
- `crates/pqvault-core/src/models.rs` — AgentToken struct, add agent_tokens to VaultMetadata
- `crates/pqvault-agent-mcp/src/lib.rs` — MCP tool registration and token enforcement middleware
- `crates/pqvault-agent-mcp/src/middleware.rs` — Request validation middleware
- `crates/pqvault-cli/src/main.rs` — Agent token management CLI commands

### Data Model Changes

```rust
/// An access token scoping an agent's vault access
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentToken {
    /// Unique token identifier
    pub id: String,
    /// Human-readable agent name
    pub name: String,
    /// Description of what this agent does
    pub description: Option<String>,
    /// The actual token value (securely random, 32 bytes hex)
    pub token_hash: String,  // SHA256 hash of token — never store plaintext
    /// Which keys this agent can access
    pub allowed_keys: KeyAccess,
    /// Which operations this agent can perform
    pub allowed_operations: Vec<AgentOperation>,
    /// Maximum requests per minute (rate limiting)
    pub rate_limit_rpm: Option<u32>,
    /// Token creation time
    pub created: String,
    /// Token expiry (None = no expiry)
    pub expires: Option<String>,
    /// Whether token is currently active
    pub active: bool,
    /// Who created this token
    pub created_by: String,
    /// Last used timestamp
    pub last_used: Option<String>,
    /// Total usage count
    pub usage_count: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyAccess {
    /// Access to specific key names
    AllowList(Vec<String>),
    /// Access to keys matching glob patterns (e.g., "STRIPE_*")
    Patterns(Vec<String>),
    /// Access to keys in specific categories
    Categories(Vec<String>),
    /// Access to keys in specific projects
    Projects(Vec<String>),
    /// Access to all keys (dangerous, should be rare)
    All,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AgentOperation {
    /// Read secret values (vault_get)
    Get,
    /// List secret names and metadata (vault_list, vault_search)
    List,
    /// Add new secrets (vault_add)
    Add,
    /// Delete secrets (vault_delete)
    Delete,
    /// Update secret values
    Update,
    /// Proxy requests through vault_proxy
    Proxy,
    /// Read health/usage data
    Health,
}

/// Add to VaultMetadata
pub struct VaultMetadata {
    // ... existing fields ...
    pub agent_tokens: Vec<AgentToken>,
}
```

### MCP Tools

```rust
// Tool: agent_create_token
{
    "name": "agent_create_token",
    "description": "Create a scoped access token for an AI agent",
    "params": {
        "name": "code-gen-agent",
        "description": "Code generation agent for webapp project",
        "allowed_keys": { "Categories": ["database", "api"] },
        "allowed_operations": ["Get", "List"],
        "rate_limit_rpm": 60,
        "expires_in_days": 30
    },
    "returns": {
        "token_id": "agt_abc123",
        "token": "pqv_agt_a1b2c3d4e5f6...",  // Only returned once!
        "name": "code-gen-agent",
        "expires": "2025-02-14T00:00:00Z",
        "warning": "Save this token — it will not be shown again"
    }
}

// Tool: agent_list_tokens
{
    "name": "agent_list_tokens",
    "params": {},
    "returns": {
        "tokens": [
            {
                "id": "agt_abc123",
                "name": "code-gen-agent",
                "active": true,
                "allowed_keys": { "Categories": ["database", "api"] },
                "allowed_operations": ["Get", "List"],
                "last_used": "2025-01-15T10:00:00Z",
                "usage_count": 142
            }
        ]
    }
}

// Tool: agent_revoke_token
{
    "name": "agent_revoke_token",
    "params": { "token_id": "agt_abc123" },
    "returns": { "revoked": true, "name": "code-gen-agent" }
}
```

### CLI Commands

```bash
# Create a token for an agent
pqvault agent create-token \
    --name "code-gen-agent" \
    --keys-category database,api \
    --operations get,list \
    --rate-limit 60 \
    --expires 30d

# List all tokens
pqvault agent list-tokens

# Revoke a token
pqvault agent revoke agt_abc123

# Show token details
pqvault agent show agt_abc123

# Rotate a token (new value, same permissions)
pqvault agent rotate-token agt_abc123

# Audit token usage
pqvault agent usage agt_abc123
```

## Core Implementation

### Token Manager

```rust
// crates/pqvault-agent-mcp/src/tokens.rs

use rand::RngCore;
use sha2::{Sha256, Digest};
use anyhow::{bail, Result};

const TOKEN_PREFIX: &str = "pqv_agt_";

pub struct TokenManager;

impl TokenManager {
    /// Create a new agent token
    pub fn create_token(
        vault: &mut Vault,
        name: &str,
        description: Option<&str>,
        allowed_keys: KeyAccess,
        allowed_operations: Vec<AgentOperation>,
        rate_limit_rpm: Option<u32>,
        expires_in_days: Option<u32>,
        created_by: &str,
    ) -> Result<(String, AgentToken)> {
        // Check for duplicate names
        if vault.metadata.agent_tokens.iter().any(|t| t.name == name) {
            bail!("Agent token with name '{}' already exists", name);
        }

        // Generate secure random token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token_value = format!("{}{}", TOKEN_PREFIX, hex::encode(token_bytes));

        // Hash token for storage (never store plaintext)
        let token_hash = hash_token(&token_value);

        let token_id = format!("agt_{}", &hex::encode(&token_bytes[..6]));

        let expires = expires_in_days.map(|days| {
            (chrono::Utc::now() + chrono::Duration::days(days as i64)).to_rfc3339()
        });

        let agent_token = AgentToken {
            id: token_id,
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            token_hash,
            allowed_keys,
            allowed_operations,
            rate_limit_rpm,
            created: chrono::Utc::now().to_rfc3339(),
            expires,
            active: true,
            created_by: created_by.to_string(),
            last_used: None,
            usage_count: 0,
        };

        vault.metadata.agent_tokens.push(agent_token.clone());
        vault.save()?;

        Ok((token_value, agent_token))
    }

    /// Validate a token and return the agent's permissions
    pub fn validate_token(
        vault: &Vault,
        token_value: &str,
    ) -> Result<&AgentToken> {
        let hash = hash_token(token_value);

        let token = vault.metadata.agent_tokens.iter()
            .find(|t| t.token_hash == hash)
            .ok_or_else(|| anyhow::anyhow!("Invalid agent token"))?;

        if !token.active {
            bail!("Agent token '{}' has been revoked", token.name);
        }

        if let Some(expires) = &token.expires {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if chrono::Utc::now() > exp.with_timezone(&chrono::Utc) {
                    bail!("Agent token '{}' has expired", token.name);
                }
            }
        }

        Ok(token)
    }

    /// Check if a token has access to a specific key
    pub fn check_key_access(token: &AgentToken, key_name: &str, entry: &SecretEntry) -> bool {
        match &token.allowed_keys {
            KeyAccess::All => true,
            KeyAccess::AllowList(keys) => keys.contains(&key_name.to_string()),
            KeyAccess::Patterns(patterns) => {
                patterns.iter().any(|p| glob_match(p, key_name))
            }
            KeyAccess::Categories(cats) => cats.contains(&entry.category),
            KeyAccess::Projects(projs) => {
                entry.project.as_ref().map(|p| projs.contains(p)).unwrap_or(false)
            }
        }
    }

    /// Check if a token allows a specific operation
    pub fn check_operation(token: &AgentToken, operation: &AgentOperation) -> bool {
        token.allowed_operations.contains(operation)
    }

    /// Revoke a token
    pub fn revoke_token(vault: &mut Vault, token_id: &str) -> Result<String> {
        let token = vault.metadata.agent_tokens.iter_mut()
            .find(|t| t.id == token_id)
            .ok_or_else(|| anyhow::anyhow!("Token '{}' not found", token_id))?;

        token.active = false;
        let name = token.name.clone();
        vault.save()?;
        Ok(name)
    }

    /// Record token usage
    pub fn record_usage(vault: &mut Vault, token_hash: &str) {
        if let Some(token) = vault.metadata.agent_tokens.iter_mut()
            .find(|t| t.token_hash == token_hash)
        {
            token.last_used = Some(chrono::Utc::now().to_rfc3339());
            token.usage_count += 1;
        }
    }
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple glob: * matches any sequence of characters
    let regex_pattern = pattern
        .replace('.', "\\.")
        .replace('*', ".*")
        .replace('?', ".");
    regex::Regex::new(&format!("^{}$", regex_pattern))
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}
```

### MCP Middleware

```rust
// crates/pqvault-agent-mcp/src/middleware.rs

/// Validate agent token before processing any MCP request
pub fn enforce_token(
    vault: &Vault,
    token_value: &str,
    key_name: Option<&str>,
    operation: &AgentOperation,
) -> Result<()> {
    let token = TokenManager::validate_token(vault, token_value)?;

    // Check operation permission
    if !TokenManager::check_operation(token, operation) {
        bail!(
            "Agent '{}' is not authorized for {:?} operations",
            token.name, operation
        );
    }

    // Check key access (if a specific key is being accessed)
    if let Some(key) = key_name {
        if let Some(entry) = vault.entries.iter().find(|e| e.name == key) {
            if !TokenManager::check_key_access(token, key, entry) {
                bail!(
                    "Agent '{}' does not have access to key '{}'",
                    token.name, key
                );
            }
        }
    }

    Ok(())
}
```

## Dependencies

- `sha2 = "0.10"` — Already a dependency, for token hashing
- `hex = "0.4"` — Already a dependency, for token encoding
- `rand = "0.8"` — Already a dependency, for secure token generation
- `regex = "1"` — For glob pattern matching on key names

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_token() {
        let mut vault = create_test_vault();
        let (token_value, token) = TokenManager::create_token(
            &mut vault, "test-agent", None,
            KeyAccess::All,
            vec![AgentOperation::Get, AgentOperation::List],
            None, None, "test",
        ).unwrap();

        assert!(token_value.starts_with("pqv_agt_"));
        assert!(token.active);

        let validated = TokenManager::validate_token(&vault, &token_value).unwrap();
        assert_eq!(validated.name, "test-agent");
    }

    #[test]
    fn test_invalid_token_rejected() {
        let vault = create_test_vault();
        let result = TokenManager::validate_token(&vault, "pqv_agt_invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_revoked_token_rejected() {
        let mut vault = create_test_vault();
        let (token_value, token) = TokenManager::create_token(
            &mut vault, "test-agent", None,
            KeyAccess::All, vec![AgentOperation::Get],
            None, None, "test",
        ).unwrap();

        TokenManager::revoke_token(&mut vault, &token.id).unwrap();

        let result = TokenManager::validate_token(&vault, &token_value);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[test]
    fn test_expired_token_rejected() {
        let mut vault = create_test_vault();
        let (token_value, _) = TokenManager::create_token(
            &mut vault, "test-agent", None,
            KeyAccess::All, vec![AgentOperation::Get],
            None, Some(0),  // Expires immediately (0 days)
            "test",
        ).unwrap();

        // Manually set expiry to the past
        vault.metadata.agent_tokens[0].expires =
            Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());

        let result = TokenManager::validate_token(&vault, &token_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_access_by_category() {
        let token = AgentToken {
            allowed_keys: KeyAccess::Categories(vec!["database".into()]),
            ..test_token()
        };
        let db_entry = make_entry("DB_URL", "database");
        let api_entry = make_entry("API_KEY", "api");

        assert!(TokenManager::check_key_access(&token, "DB_URL", &db_entry));
        assert!(!TokenManager::check_key_access(&token, "API_KEY", &api_entry));
    }

    #[test]
    fn test_key_access_by_pattern() {
        let token = AgentToken {
            allowed_keys: KeyAccess::Patterns(vec!["STRIPE_*".into()]),
            ..test_token()
        };
        let stripe_entry = make_entry("STRIPE_SECRET_KEY", "payment");
        let other_entry = make_entry("GITHUB_TOKEN", "api");

        assert!(TokenManager::check_key_access(&token, "STRIPE_SECRET_KEY", &stripe_entry));
        assert!(!TokenManager::check_key_access(&token, "GITHUB_TOKEN", &other_entry));
    }

    #[test]
    fn test_operation_check() {
        let token = AgentToken {
            allowed_operations: vec![AgentOperation::Get, AgentOperation::List],
            ..test_token()
        };

        assert!(TokenManager::check_operation(&token, &AgentOperation::Get));
        assert!(TokenManager::check_operation(&token, &AgentOperation::List));
        assert!(!TokenManager::check_operation(&token, &AgentOperation::Delete));
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut vault = create_test_vault();
        TokenManager::create_token(&mut vault, "agent-1", None, KeyAccess::All, vec![], None, None, "test").unwrap();
        let result = TokenManager::create_token(&mut vault, "agent-1", None, KeyAccess::All, vec![], None, None, "test");
        assert!(result.is_err());
    }
}
```

### Manual Verification

1. Create a token: `pqvault agent create-token --name test-agent --keys-category api --operations get,list`
2. Use the token to access an API key — should succeed
3. Try to access a database key — should be rejected
4. Try to delete a key — should be rejected (only get,list allowed)
5. Revoke the token — all further requests should fail

## Example Usage

```bash
# Create a scoped token for a code generation agent
$ pqvault agent create-token \
    --name "cursor-agent" \
    --description "Cursor IDE AI assistant" \
    --keys-category database,api \
    --operations get,list \
    --rate-limit 60 \
    --expires 30d

Agent Token Created
  ID: agt_a1b2c3
  Name: cursor-agent
  Token: pqv_agt_7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a
  Access: database, api categories
  Operations: get, list
  Rate limit: 60 req/min
  Expires: 2025-02-14

  WARNING: Save this token now. It will not be shown again.

# List tokens
$ pqvault agent list-tokens
ID            Name            Active  Access              Last Used    Usage
agt_a1b2c3    cursor-agent    yes     database,api cats   2m ago       142
agt_d4e5f6    ci-pipeline     yes     STRIPE_* pattern    1h ago       38
agt_g7h8i9    admin-agent     yes     ALL KEYS            5m ago       503

# Revoke a token
$ pqvault agent revoke agt_a1b2c3
Revoked token 'cursor-agent'. All future requests will be denied.
```
