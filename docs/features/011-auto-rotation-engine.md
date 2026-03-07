# Feature 011: Auto-Rotation Engine

## Status: Done
## Phase: 2 (v2.2)
## Priority: Critical

## Problem

API keys and secrets never get rotated. A Stripe key created in 2022 is still running production in 2025. Compromised keys go undetected for months because there is no rotation infrastructure. Manual rotation is error-prone: developers must log into each provider's dashboard, generate a new key, update the vault, and update all consumers. This process is so tedious that it simply doesn't happen.

## Solution

Build a trait-based auto-rotation engine where each API provider implements a `RotationProvider` trait. The engine handles the workflow: generate new key via provider API, verify it works, update the vault, and optionally notify consumers. Ships with built-in providers for Stripe, GitHub, Resend, and generic HTTP-based rotation. Third-party providers can be added by implementing the trait.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/engine.rs` — Core rotation engine and RotationProvider trait
- `crates/pqvault-rotation-mcp/src/providers/mod.rs` — Provider module
- `crates/pqvault-rotation-mcp/src/providers/stripe.rs` — Stripe key rotation
- `crates/pqvault-rotation-mcp/src/providers/github.rs` — GitHub PAT rotation
- `crates/pqvault-rotation-mcp/src/providers/resend.rs` — Resend API key rotation
- `crates/pqvault-rotation-mcp/src/providers/generic.rs` — Generic HTTP rotation
- `crates/pqvault-rotation-mcp/src/lib.rs` — MCP tool registration
- `crates/pqvault-core/src/models.rs` — Add rotation metadata to SecretEntry

### Data Model Changes

```rust
/// Trait that each provider must implement for auto-rotation
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// Provider name (e.g., "stripe", "github")
    fn name(&self) -> &str;

    /// Whether this provider supports auto-rotation
    fn supports_auto_rotate(&self) -> bool;

    /// Generate a new key, returning the new value
    /// The old key is provided for providers that need it to authenticate
    async fn rotate(&self, old_key: &str, config: &ProviderRotationConfig) -> Result<RotationResult>;

    /// Verify a key works by making a test API call
    async fn verify(&self, key: &str, config: &ProviderRotationConfig) -> Result<bool>;

    /// Revoke an old key (optional — some providers auto-revoke on rotation)
    async fn revoke(&self, key: &str, config: &ProviderRotationConfig) -> Result<()> {
        Ok(()) // Default: no-op
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRotationConfig {
    /// API base URL for the provider
    pub api_base: Option<String>,
    /// Additional auth headers or parameters
    pub auth_headers: HashMap<String, String>,
    /// Custom rotation endpoint
    pub rotation_endpoint: Option<String>,
    /// Custom verification endpoint
    pub verify_endpoint: Option<String>,
}

#[derive(Debug)]
pub struct RotationResult {
    /// The new key value
    pub new_key: String,
    /// The old key that was replaced
    pub old_key: String,
    /// Provider-specific metadata about the rotation
    pub metadata: HashMap<String, String>,
    /// Whether the old key was revoked
    pub old_key_revoked: bool,
}

/// Added to SecretEntry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationMetadata {
    /// When the key was last rotated
    pub last_rotated: Option<String>,
    /// Number of times this key has been rotated
    pub rotation_count: u32,
    /// Previous key value (for rollback, encrypted)
    pub prev_value: Option<String>,
    /// When the previous value expires (for dual-write)
    pub prev_expires: Option<String>,
    /// Custom provider rotation config
    pub provider_config: Option<ProviderRotationConfig>,
}
```

### MCP Tools

```rust
// Tool: vault_rotate
{
    "name": "vault_rotate",
    "description": "Rotate a secret key using its provider's API",
    "params": {
        "key_name": "STRIPE_SECRET_KEY",
        "verify_before_commit": true,    // default true
        "keep_old_for_hours": 1          // default 1 hour
    },
    "returns": {
        "success": true,
        "old_key_preview": "sk_l...xyz",
        "new_key_preview": "sk_l...abc",
        "provider": "stripe",
        "verified": true,
        "rollback_until": "2025-01-15T11:30:00Z"
    }
}

// Tool: vault_auto_rotate
{
    "name": "vault_auto_rotate",
    "description": "Check and rotate all keys due for rotation",
    "params": {},
    "returns": {
        "rotated": ["STRIPE_KEY", "GITHUB_TOKEN"],
        "failed": [{"key": "RESEND_KEY", "error": "API error 403"}],
        "skipped": ["DATABASE_URL"],
        "next_due": {"AWS_KEY": "2025-01-20"}
    }
}
```

### CLI Commands

```bash
# Rotate a specific key
pqvault rotate STRIPE_SECRET_KEY

# Rotate with dry-run (shows what would happen)
pqvault rotate STRIPE_SECRET_KEY --dry-run

# Auto-rotate all keys due for rotation
pqvault rotate --auto

# Rotate all keys for a specific provider
pqvault rotate --provider stripe

# Force rotation (skip "not due" check)
pqvault rotate STRIPE_SECRET_KEY --force

# Rotate without verification (dangerous)
pqvault rotate STRIPE_SECRET_KEY --skip-verify
```

### Web UI Changes

- "Rotate" button on each key's row in the secrets table
- Rotation status indicator (green: recent, yellow: due soon, red: overdue)
- Rotation history modal showing past rotations with timestamps

## Core Implementation

### Rotation Engine

```rust
// crates/pqvault-rotation-mcp/src/engine.rs

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Context, Result};

pub struct RotationEngine {
    providers: HashMap<String, Arc<dyn RotationProvider>>,
}

impl RotationEngine {
    pub fn new() -> Self {
        let mut providers: HashMap<String, Arc<dyn RotationProvider>> = HashMap::new();
        providers.insert("stripe".into(), Arc::new(StripeProvider));
        providers.insert("github".into(), Arc::new(GitHubProvider));
        providers.insert("resend".into(), Arc::new(ResendProvider));
        providers.insert("generic".into(), Arc::new(GenericHttpProvider));

        Self { providers }
    }

    pub async fn rotate_key(
        &self,
        entry: &SecretEntry,
        old_value: &str,
        options: &RotationOptions,
    ) -> Result<RotationResult> {
        let provider_name = entry.provider.as_deref()
            .ok_or_else(|| anyhow::anyhow!(
                "Key '{}' has no provider configured. Cannot auto-rotate.", entry.name
            ))?;

        let provider = self.providers.get(provider_name)
            .ok_or_else(|| anyhow::anyhow!(
                "No rotation provider registered for '{}'", provider_name
            ))?;

        if !provider.supports_auto_rotate() {
            anyhow::bail!(
                "Provider '{}' does not support auto-rotation", provider_name
            );
        }

        let config = entry.rotation_metadata
            .as_ref()
            .and_then(|m| m.provider_config.clone())
            .unwrap_or_default();

        // Step 1: Generate new key
        eprintln!("[rotate] Generating new key for {} via {}", entry.name, provider_name);
        let result = provider.rotate(old_value, &config).await
            .context(format!("Failed to rotate {} via {}", entry.name, provider_name))?;

        // Step 2: Verify new key works (unless skipped)
        if options.verify_before_commit {
            eprintln!("[rotate] Verifying new key for {}", entry.name);
            let verified = provider.verify(&result.new_key, &config).await
                .context("Verification API call failed")?;

            if !verified {
                anyhow::bail!(
                    "New key for {} failed verification. Rotation aborted. Old key is still active.",
                    entry.name
                );
            }
            eprintln!("[rotate] Verification passed for {}", entry.name);
        }

        Ok(result)
    }

    pub fn get_provider(&self, name: &str) -> Option<Arc<dyn RotationProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn register_provider(&mut self, name: String, provider: Arc<dyn RotationProvider>) {
        self.providers.insert(name, provider);
    }
}

#[derive(Debug, Clone)]
pub struct RotationOptions {
    pub verify_before_commit: bool,
    pub keep_old_for_hours: u32,
    pub force: bool,
    pub dry_run: bool,
}

impl Default for RotationOptions {
    fn default() -> Self {
        Self {
            verify_before_commit: true,
            keep_old_for_hours: 1,
            force: false,
            dry_run: false,
        }
    }
}
```

### Stripe Provider

```rust
// crates/pqvault-rotation-mcp/src/providers/stripe.rs

use reqwest::Client;
use async_trait::async_trait;

pub struct StripeProvider;

#[async_trait]
impl RotationProvider for StripeProvider {
    fn name(&self) -> &str { "stripe" }

    fn supports_auto_rotate(&self) -> bool { true }

    async fn rotate(&self, old_key: &str, _config: &ProviderRotationConfig) -> Result<RotationResult> {
        let client = Client::new();

        // Stripe API: Roll API key
        // POST https://api.stripe.com/v1/api_keys/roll
        let response = client
            .post("https://api.stripe.com/v1/api_keys")
            .bearer_auth(old_key)
            .form(&[("type", "secret")])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("Stripe API error: {}", error_body);
        }

        let body: serde_json::Value = response.json().await?;
        let new_key = body["secret"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No 'secret' field in Stripe response"))?
            .to_string();

        Ok(RotationResult {
            new_key,
            old_key: old_key.to_string(),
            metadata: HashMap::from([
                ("stripe_key_id".into(), body["id"].as_str().unwrap_or("").into()),
            ]),
            old_key_revoked: true, // Stripe auto-revokes old key after rolling
        })
    }

    async fn verify(&self, key: &str, _config: &ProviderRotationConfig) -> Result<bool> {
        let client = Client::new();
        let response = client
            .get("https://api.stripe.com/v1/balance")
            .bearer_auth(key)
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}
```

### GitHub Provider

```rust
// crates/pqvault-rotation-mcp/src/providers/github.rs

pub struct GitHubProvider;

#[async_trait]
impl RotationProvider for GitHubProvider {
    fn name(&self) -> &str { "github" }

    fn supports_auto_rotate(&self) -> bool { true }

    async fn rotate(&self, old_key: &str, config: &ProviderRotationConfig) -> Result<RotationResult> {
        let client = Client::new();

        // GitHub API: Regenerate a token
        // POST https://api.github.com/user/token
        let response = client
            .post("https://api.github.com/authorizations")
            .header("Authorization", format!("token {}", old_key))
            .header("User-Agent", "pqvault-rotation")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("GitHub API error: {}", response.status());
        }

        let body: serde_json::Value = response.json().await?;
        let new_token = body["token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No token in GitHub response"))?
            .to_string();

        Ok(RotationResult {
            new_key: new_token,
            old_key: old_key.to_string(),
            metadata: HashMap::new(),
            old_key_revoked: true,
        })
    }

    async fn verify(&self, key: &str, _config: &ProviderRotationConfig) -> Result<bool> {
        let client = Client::new();
        let response = client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {}", key))
            .header("User-Agent", "pqvault-rotation")
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}
```

## Dependencies

- `reqwest = { version = "0.12", features = ["json"] }` — Already a dependency, used for provider API calls
- `async-trait = "0.1"` — For async trait methods
- Uses existing `serde`, `serde_json`, `chrono`

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        should_fail: bool,
        verify_result: bool,
    }

    #[async_trait]
    impl RotationProvider for MockProvider {
        fn name(&self) -> &str { "mock" }
        fn supports_auto_rotate(&self) -> bool { true }

        async fn rotate(&self, old_key: &str, _config: &ProviderRotationConfig) -> Result<RotationResult> {
            if self.should_fail {
                anyhow::bail!("Mock rotation failure");
            }
            Ok(RotationResult {
                new_key: format!("{}_rotated", old_key),
                old_key: old_key.to_string(),
                metadata: HashMap::new(),
                old_key_revoked: false,
            })
        }

        async fn verify(&self, _key: &str, _config: &ProviderRotationConfig) -> Result<bool> {
            Ok(self.verify_result)
        }
    }

    #[tokio::test]
    async fn test_successful_rotation() {
        let mut engine = RotationEngine::new();
        engine.register_provider("mock".into(), Arc::new(MockProvider {
            should_fail: false,
            verify_result: true,
        }));

        let entry = create_test_entry("TEST_KEY", "mock");
        let result = engine.rotate_key(&entry, "old_value", &RotationOptions::default()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().new_key, "old_value_rotated");
    }

    #[tokio::test]
    async fn test_rotation_aborted_on_verify_failure() {
        let mut engine = RotationEngine::new();
        engine.register_provider("mock".into(), Arc::new(MockProvider {
            should_fail: false,
            verify_result: false,
        }));

        let entry = create_test_entry("TEST_KEY", "mock");
        let result = engine.rotate_key(&entry, "old_value", &RotationOptions::default()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed verification"));
    }

    #[tokio::test]
    async fn test_unknown_provider_fails() {
        let engine = RotationEngine::new();
        let entry = create_test_entry("TEST_KEY", "unknown_provider");
        let result = engine.rotate_key(&entry, "old_value", &RotationOptions::default()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No rotation provider"));
    }

    #[tokio::test]
    async fn test_no_provider_on_entry_fails() {
        let engine = RotationEngine::new();
        let mut entry = create_test_entry("TEST_KEY", "stripe");
        entry.provider = None;
        let result = engine.rotate_key(&entry, "old_value", &RotationOptions::default()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no provider configured"));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
#[ignore] // Requires real Stripe test key
async fn test_stripe_rotation_live() {
    let engine = RotationEngine::new();
    let entry = create_test_entry("STRIPE_KEY", "stripe");
    let old_key = std::env::var("STRIPE_TEST_KEY").expect("STRIPE_TEST_KEY required");

    let result = engine.rotate_key(&entry, &old_key, &RotationOptions::default()).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.new_key.starts_with("sk_test_"));
    assert_ne!(result.new_key, old_key);
}
```

### Manual Verification

1. Configure a test Stripe key: `pqvault add --name STRIPE_TEST --value sk_test_... --provider stripe`
2. Run `pqvault rotate STRIPE_TEST --dry-run` — verify it shows the rotation plan
3. Run `pqvault rotate STRIPE_TEST` — verify new key is generated and verified
4. Test old key no longer works (if provider revokes)
5. Test new key works in your application

## Example Usage

```bash
# Rotate a Stripe key
$ pqvault rotate STRIPE_SECRET_KEY
Rotating STRIPE_SECRET_KEY via stripe...
  Generating new key... done
  Verifying new key... passed
  Updating vault... done
  Old key: sk_l...xyz (will expire in 1h)
  New key: sk_l...abc (active)
Rotation complete.

# Auto-rotate all due keys
$ pqvault rotate --auto
Checking rotation policies...
  STRIPE_SECRET_KEY: due (last rotated 95 days ago, policy: 90 days)
  GITHUB_TOKEN: due (last rotated 35 days ago, policy: 30 days)
  DATABASE_URL: skipped (no rotation provider)
  RESEND_KEY: not due (last rotated 5 days ago, policy: 90 days)

Rotating 2 keys...
  STRIPE_SECRET_KEY: rotated successfully
  GITHUB_TOKEN: rotated successfully

Summary: 2 rotated, 0 failed, 2 skipped
```
