# Feature 013: Pre-Rotation Testing

## Status: Planned
## Phase: 2 (v2.2)
## Priority: High

## Problem

When a key is rotated, the new key might be invalid, lack required permissions, or be configured incorrectly. Without verification, a bad rotation takes down production instantly. The existing `ProviderConfig.verify_path` field is defined in the data model but is never actually used — no verification step exists in the rotation workflow.

## Solution

After generating a new key, automatically verify it works before committing the rotation. Each provider defines a verification endpoint and expected response. The verification makes a lightweight API call with the new key and checks for a successful response (e.g., HTTP 200). Only if verification passes is the new key committed to the vault. If verification fails, the rotation is aborted and the old key remains active.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/verify.rs` — Verification engine and test suite
- `crates/pqvault-rotation-mcp/src/engine.rs` — Integrate verification into rotation flow
- `crates/pqvault-core/src/providers.rs` — Add verify_path to all ProviderConfig entries

### Data Model Changes

```rust
/// Verification configuration per provider
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerificationConfig {
    /// HTTP method to use (GET or POST)
    pub method: HttpMethod,
    /// URL to call for verification
    pub url: String,
    /// How to pass the key (header, query, bearer)
    pub auth_method: AuthMethod,
    /// Header name if auth_method is Header
    pub header_name: Option<String>,
    /// Expected HTTP status codes (e.g., [200, 201])
    pub expected_status: Vec<u16>,
    /// Optional: expected response body substring
    pub expected_body_contains: Option<String>,
    /// Timeout in seconds
    pub timeout_seconds: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HttpMethod {
    Get,
    Post,
    Head,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthMethod {
    /// Authorization: Bearer <key>
    Bearer,
    /// Custom header: <header_name>: <key>
    Header,
    /// Query parameter: ?key=<key>
    QueryParam,
    /// Basic auth with key as password
    BasicAuth,
}

/// Result of a verification attempt
#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationResult {
    pub passed: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub error: Option<String>,
    pub details: String,
}
```

### MCP Tools

```rust
// Tool: vault_verify_key
{
    "name": "vault_verify_key",
    "description": "Test if a key is valid by calling its provider's verification endpoint",
    "params": {
        "key_name": "STRIPE_SECRET_KEY"
    },
    "returns": {
        "passed": true,
        "status_code": 200,
        "response_time_ms": 145,
        "provider": "stripe",
        "verification_url": "https://api.stripe.com/v1/balance"
    }
}
```

### CLI Commands

```bash
# Verify a specific key
pqvault verify STRIPE_SECRET_KEY

# Verify all keys that have verification configured
pqvault verify --all

# Test a key value directly (without storing)
pqvault verify --provider stripe --value sk_live_abc123
```

## Core Implementation

### Verification Engine

```rust
// crates/pqvault-rotation-mcp/src/verify.rs

use reqwest::{Client, StatusCode};
use std::time::Instant;
use anyhow::Result;

/// Default verification configs for known providers
pub fn default_verification_config(provider: &str) -> Option<VerificationConfig> {
    match provider {
        "stripe" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.stripe.com/v1/balance".into(),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        "github" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.github.com/user".into(),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        "openai" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.openai.com/v1/models".into(),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        "resend" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.resend.com/domains".into(),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        "sendgrid" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.sendgrid.com/v3/user/profile".into(),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        "anthropic" => Some(VerificationConfig {
            method: HttpMethod::Get,
            url: "https://api.anthropic.com/v1/models".into(),
            auth_method: AuthMethod::Header,
            header_name: Some("x-api-key".into()),
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 10,
        }),
        _ => None,
    }
}

pub async fn verify_key(
    key_value: &str,
    config: &VerificationConfig,
) -> VerificationResult {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_seconds as u64))
        .build()
        .unwrap();

    let start = Instant::now();

    let request = match config.method {
        HttpMethod::Get => client.get(&config.url),
        HttpMethod::Post => client.post(&config.url),
        HttpMethod::Head => client.head(&config.url),
    };

    let request = match &config.auth_method {
        AuthMethod::Bearer => request.bearer_auth(key_value),
        AuthMethod::Header => {
            let header = config.header_name.as_deref().unwrap_or("Authorization");
            request.header(header, key_value)
        }
        AuthMethod::QueryParam => request.query(&[("key", key_value)]),
        AuthMethod::BasicAuth => request.basic_auth("", Some(key_value)),
    };

    let request = request.header("User-Agent", "pqvault-verification/1.0");

    match request.send().await {
        Ok(response) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();

            let status_ok = config.expected_status.contains(&status);
            let body_ok = config.expected_body_contains
                .as_ref()
                .map(|expected| body.contains(expected))
                .unwrap_or(true);

            let passed = status_ok && body_ok;

            let details = if passed {
                format!("HTTP {} in {}ms", status, elapsed)
            } else if !status_ok {
                format!(
                    "Expected status {:?}, got {}",
                    config.expected_status, status
                )
            } else {
                format!("Response body missing expected content")
            };

            VerificationResult {
                passed,
                status_code: Some(status),
                response_time_ms: elapsed,
                error: None,
                details,
            }
        }
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            VerificationResult {
                passed: false,
                status_code: None,
                response_time_ms: elapsed,
                error: Some(e.to_string()),
                details: format!("Request failed: {}", e),
            }
        }
    }
}

/// Verify all keys in the vault that have verification configs
pub async fn verify_all_keys(
    vault: &Vault,
    master_password: &str,
) -> Vec<(String, VerificationResult)> {
    let mut results = Vec::new();

    for entry in &vault.entries {
        let config = entry.provider.as_deref()
            .and_then(default_verification_config)
            .or_else(|| entry.rotation_metadata
                .as_ref()
                .and_then(|m| m.provider_config.as_ref())
                .map(|pc| VerificationConfig {
                    method: HttpMethod::Get,
                    url: pc.verify_endpoint.clone().unwrap_or_default(),
                    auth_method: AuthMethod::Bearer,
                    header_name: None,
                    expected_status: vec![200],
                    expected_body_contains: None,
                    timeout_seconds: 10,
                })
            );

        if let Some(config) = config {
            let value = match vault.decrypt_value(&entry.encrypted_value, master_password) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let result = verify_key(&value, &config).await;
            results.push((entry.name.clone(), result));
        }
    }

    results
}
```

## Dependencies

- `reqwest = { version = "0.12", features = ["json"] }` — Already a dependency
- No new dependencies required
- Requires Feature 011 (Auto-Rotation Engine) for integration

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, matchers, ResponseTemplate};

    #[tokio::test]
    async fn test_verify_bearer_auth_success() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::header("Authorization", "Bearer valid_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let config = VerificationConfig {
            method: HttpMethod::Get,
            url: format!("{}/verify", mock_server.uri()),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 5,
        };

        let result = verify_key("valid_key", &config).await;
        assert!(result.passed);
        assert_eq!(result.status_code, Some(200));
    }

    #[tokio::test]
    async fn test_verify_invalid_key_returns_401() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let config = VerificationConfig {
            method: HttpMethod::Get,
            url: format!("{}/verify", mock_server.uri()),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 5,
        };

        let result = verify_key("invalid_key", &config).await;
        assert!(!result.passed);
        assert_eq!(result.status_code, Some(401));
    }

    #[tokio::test]
    async fn test_verify_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_delay(std::time::Duration::from_secs(30)))
            .mount(&mock_server)
            .await;

        let config = VerificationConfig {
            method: HttpMethod::Get,
            url: format!("{}/verify", mock_server.uri()),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: None,
            timeout_seconds: 1,
        };

        let result = verify_key("key", &config).await;
        assert!(!result.passed);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_verify_body_contains() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("user: admin"))
            .mount(&mock_server)
            .await;

        let config = VerificationConfig {
            method: HttpMethod::Get,
            url: format!("{}/verify", mock_server.uri()),
            auth_method: AuthMethod::Bearer,
            header_name: None,
            expected_status: vec![200],
            expected_body_contains: Some("admin".into()),
            timeout_seconds: 5,
        };

        let result = verify_key("key", &config).await;
        assert!(result.passed);
    }

    #[test]
    fn test_default_configs_exist() {
        assert!(default_verification_config("stripe").is_some());
        assert!(default_verification_config("github").is_some());
        assert!(default_verification_config("openai").is_some());
        assert!(default_verification_config("unknown_provider").is_none());
    }
}
```

### Manual Verification

1. Add a valid Stripe test key and run `pqvault verify STRIPE_KEY` — should pass
2. Add an invalid key and run verify — should fail with 401
3. Run `pqvault verify --all` — verify all keys with providers are tested
4. During rotation, verify the new key is tested before being committed

## Example Usage

```bash
# Verify a single key
$ pqvault verify STRIPE_SECRET_KEY
Verifying STRIPE_SECRET_KEY via stripe...
  Endpoint: https://api.stripe.com/v1/balance
  Auth: Bearer token
  Status: 200 OK (145ms)
  Result: PASSED

# Verify all keys
$ pqvault verify --all
Verifying 8 keys with provider endpoints...

  STRIPE_SECRET_KEY     stripe    200 OK    145ms  PASSED
  GITHUB_TOKEN          github    200 OK    230ms  PASSED
  OPENAI_API_KEY        openai    200 OK    310ms  PASSED
  RESEND_KEY            resend    200 OK    180ms  PASSED
  INVALID_KEY           stripe    401 ERR   90ms   FAILED
  AWS_ACCESS_KEY        -         skipped   -      NO VERIFY CONFIG

Summary: 4 passed, 1 failed, 1 skipped
```
