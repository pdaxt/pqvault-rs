# Feature 034: Provider Health Monitoring

## Status: Planned
## Phase: 4 (v2.4)
## Priority: High

## Problem

When a key-backed API call fails, there is no way to know whether the failure is because the key was revoked, the API is experiencing an outage, the key hit its rate limit, or the key expired. The vault treats all failures the same. Without provider health monitoring, users waste time debugging key issues when the actual problem is a provider outage, or miss revoked keys when the provider is functioning normally.

## Solution

Implement periodic health pings to provider verification endpoints. Each provider (Anthropic, OpenAI, Stripe, AWS, etc.) has a known health check endpoint that can validate whether a key is still active without consuming API credits. The health monitor runs these checks on a configurable schedule (default: every 6 hours), records the result, and updates each key's health status. Failed health checks trigger alerts distinguishing between "key revoked" and "provider down."

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/provider.rs` — Provider health check definitions and executor
- `crates/pqvault-health-mcp/src/providers/mod.rs` — Provider registry
- `crates/pqvault-health-mcp/src/providers/anthropic.rs` — Anthropic-specific health check
- `crates/pqvault-health-mcp/src/providers/openai.rs` — OpenAI-specific health check
- `crates/pqvault-health-mcp/src/providers/stripe.rs` — Stripe-specific health check
- `crates/pqvault-health-mcp/src/lib.rs` — Register health check tools

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Provider definition with health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub health_endpoint: String,
    pub auth_header: String,         // e.g., "x-api-key", "Authorization"
    pub auth_prefix: String,         // e.g., "", "Bearer "
    pub expected_status: Vec<u16>,   // e.g., [200, 401] — 401 means key valid but endpoint restricted
    pub timeout_secs: u64,
    pub check_interval_secs: u64,
}

/// Result of a provider health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub key_name: String,
    pub provider: String,
    pub status: HealthStatus,
    pub response_code: Option<u16>,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,          // Key works, provider up
    KeyRevoked,       // Provider up but key rejected (401/403)
    KeyExpired,       // Provider reports key expired
    RateLimited,      // Key hit rate limit (429)
    ProviderDown,     // Provider endpoint unreachable/5xx
    Timeout,          // Health check timed out
    Unknown,          // Could not determine status
}

/// Built-in provider configurations
pub fn default_providers() -> Vec<ProviderConfig> {
    vec![
        ProviderConfig {
            name: "anthropic".into(),
            health_endpoint: "https://api.anthropic.com/v1/models".into(),
            auth_header: "x-api-key".into(),
            auth_prefix: "".into(),
            expected_status: vec![200],
            timeout_secs: 10,
            check_interval_secs: 21600, // 6 hours
        },
        ProviderConfig {
            name: "openai".into(),
            health_endpoint: "https://api.openai.com/v1/models".into(),
            auth_header: "Authorization".into(),
            auth_prefix: "Bearer ".into(),
            expected_status: vec![200],
            timeout_secs: 10,
            check_interval_secs: 21600,
        },
        ProviderConfig {
            name: "stripe".into(),
            health_endpoint: "https://api.stripe.com/v1/balance".into(),
            auth_header: "Authorization".into(),
            auth_prefix: "Bearer ".into(),
            expected_status: vec![200],
            timeout_secs: 10,
            check_interval_secs: 21600,
        },
    ]
}

/// Health check executor
pub struct HealthChecker {
    client: reqwest::Client,
    providers: Vec<ProviderConfig>,
}

impl HealthChecker {
    pub async fn check_key(
        &self,
        key_name: &str,
        key_value: &str,
        provider: &ProviderConfig,
    ) -> HealthCheckResult {
        let start = std::time::Instant::now();
        let auth_value = format!("{}{}", provider.auth_prefix, key_value);

        let result = self.client
            .get(&provider.health_endpoint)
            .header(&provider.auth_header, &auth_value)
            .timeout(Duration::from_secs(provider.timeout_secs))
            .send()
            .await;

        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let code = response.status().as_u16();
                let status = match code {
                    c if provider.expected_status.contains(&c) => HealthStatus::Healthy,
                    401 | 403 => HealthStatus::KeyRevoked,
                    429 => HealthStatus::RateLimited,
                    500..=599 => HealthStatus::ProviderDown,
                    _ => HealthStatus::Unknown,
                };
                HealthCheckResult {
                    key_name: key_name.into(),
                    provider: provider.name.clone(),
                    status,
                    response_code: Some(code),
                    response_time_ms: elapsed,
                    error_message: None,
                    checked_at: Utc::now(),
                }
            }
            Err(e) => {
                let status = if e.is_timeout() {
                    HealthStatus::Timeout
                } else {
                    HealthStatus::ProviderDown
                };
                HealthCheckResult {
                    key_name: key_name.into(),
                    provider: provider.name.clone(),
                    status,
                    response_code: None,
                    response_time_ms: elapsed,
                    error_message: Some(e.to_string()),
                    checked_at: Utc::now(),
                }
            }
        }
    }
}
```

### MCP Tools

```rust
/// Check health of all keys or a specific key
#[tool(name = "check_provider_health")]
async fn check_provider_health(
    &self,
    #[arg(description = "Key name to check (all if omitted)")] key_name: Option<String>,
    #[arg(description = "Force check even if recently checked")] force: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation: iterate keys, match to providers, run health checks
}

/// List all configured providers
#[tool(name = "list_providers")]
async fn list_providers(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Add custom provider health check
#[tool(name = "add_provider")]
async fn add_provider(
    &self,
    #[arg(description = "Provider name")] name: String,
    #[arg(description = "Health check URL")] url: String,
    #[arg(description = "Auth header name")] auth_header: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Check all keys
pqvault health check
# ANTHROPIC_KEY: Healthy (200, 234ms)
# OPENAI_KEY: KeyRevoked (401, 156ms) — KEY NEEDS ROTATION
# STRIPE_KEY: Healthy (200, 189ms)
# CUSTOM_API: ProviderDown (503, 1023ms)

# Check specific key
pqvault health check --key OPENAI_KEY

# Force recheck (ignore interval)
pqvault health check --force

# Add custom provider
pqvault provider add --name my-api \
  --url https://api.example.com/health \
  --auth-header "X-Api-Key" \
  --expected-status 200

# List providers
pqvault provider list

# Set check interval
pqvault config set health.check_interval_hours 4
```

### Web UI Changes

- Provider health status icons on each key (green/yellow/red)
- Last check time and response latency display
- Provider status page showing all providers and their current status
- Health check history timeline per key

## Dependencies

- `reqwest = "0.12"` (existing) — HTTP client for health checks
- `tokio = "1"` (existing) — Async runtime and scheduling
- `chrono = "0.4"` (existing) — Timestamps

## Testing

### Unit Tests

```rust
#[test]
fn health_status_from_response_code() {
    let provider = default_providers().into_iter().find(|p| p.name == "anthropic").unwrap();
    assert!(provider.expected_status.contains(&200));
}

#[test]
fn provider_config_serialization() {
    let provider = ProviderConfig {
        name: "test".into(),
        health_endpoint: "https://api.test.com/health".into(),
        auth_header: "Authorization".into(),
        auth_prefix: "Bearer ".into(),
        expected_status: vec![200, 201],
        timeout_secs: 5,
        check_interval_secs: 3600,
    };
    let json = serde_json::to_string(&provider).unwrap();
    let back: ProviderConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "test");
}
```

### Integration Tests

```rust
#[tokio::test]
async fn health_check_detects_revoked_key() {
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("GET", "/health")
        .with_status(401)
        .with_body(r#"{"error": "invalid_api_key"}"#)
        .create_async().await;

    let checker = HealthChecker::new();
    let provider = ProviderConfig {
        name: "test".into(),
        health_endpoint: format!("{}/health", server.url()),
        auth_header: "Authorization".into(),
        auth_prefix: "Bearer ".into(),
        expected_status: vec![200],
        timeout_secs: 5,
        check_interval_secs: 3600,
    };

    let result = checker.check_key("TEST_KEY", "invalid-key", &provider).await;
    assert_eq!(result.status, HealthStatus::KeyRevoked);
    mock.assert_async().await;
}

#[tokio::test]
async fn health_check_handles_timeout() {
    // Use a non-routable IP to force timeout
    let provider = ProviderConfig {
        name: "test".into(),
        health_endpoint: "http://192.0.2.1/health".into(),
        auth_header: "Authorization".into(),
        auth_prefix: "".into(),
        expected_status: vec![200],
        timeout_secs: 1,
        check_interval_secs: 3600,
    };

    let checker = HealthChecker::new();
    let result = checker.check_key("KEY", "val", &provider).await;
    assert!(matches!(result.status, HealthStatus::Timeout | HealthStatus::ProviderDown));
}
```

### Manual Verification

1. Add a valid Anthropic API key, run health check — verify "Healthy"
2. Add an invalid key, run health check — verify "KeyRevoked"
3. Block network access, run health check — verify "ProviderDown"
4. Check that health results appear on web dashboard
5. Verify scheduled checks run at configured interval

## Example Usage

```bash
# Morning health check:
pqvault health check
# All keys healthy — start work

# Key stops working during the day:
pqvault health check --key OPENAI_KEY
# OPENAI_KEY: KeyRevoked (401, 156ms)
# Action: rotate this key immediately

# vs. provider outage:
pqvault health check --key OPENAI_KEY
# OPENAI_KEY: ProviderDown (503, 2340ms)
# Action: wait for provider recovery, key is fine
```
