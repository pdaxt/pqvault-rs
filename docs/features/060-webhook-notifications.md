# Feature 060: Webhook Notifications

## Status: Planned
## Phase: 6 (v2.6)
## Priority: Medium

## Problem

All notifications in PQVault are pull-based — users must actively check the dashboard, CLI, or activity feed to learn about events. There is no way to push notifications to external systems like Slack, PagerDuty, email, or custom alerting pipelines. Critical events like key revocation, anomaly detection, or budget overages require immediate attention but go unnoticed until someone manually checks.

## Solution

Fire HTTP webhooks on configurable key events (create, rotate, expire, anomaly, budget, break-glass). Each webhook endpoint is registered with a URL, event filter, and HMAC-SHA256 signing secret. Payloads include full event context — key name, actor, timestamp, severity, and relevant metadata. Failed deliveries are retried with exponential backoff. A delivery log tracks all webhook attempts and their outcomes.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/webhook.rs` — Webhook configuration and delivery engine
- `crates/pqvault-health-mcp/src/webhook_worker.rs` — Background delivery worker with retry logic
- `crates/pqvault-health-mcp/src/lib.rs` — Register webhook management tools
- `crates/pqvault-core/src/webhook.rs` — Webhook persistence and delivery log

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;

/// Webhook endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub secret: String,  // HMAC signing secret
    pub events: HashSet<EventType>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub headers: Vec<(String, String)>,  // Custom headers
    pub retry_count: u32,                // Max retries (default: 3)
    pub retry_interval_secs: u64,        // Base retry interval (default: 30)
    pub timeout_secs: u64,               // Request timeout (default: 10)
}

/// Event types that can trigger webhooks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    KeyCreated,
    KeyRotated,
    KeyDeleted,
    KeyExpiring,
    KeyExpired,
    AnomalyDetected,
    BudgetWarning,
    BudgetExceeded,
    HealthAlert,
    BreakGlassUsed,
    AccessGranted,
    AccessRevoked,
    ProviderDown,
    KeyRevoked,
    SyncFailed,
}

/// Webhook payload sent to endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub key_name: Option<String>,
    pub actor: Option<String>,
    pub severity: String,
    pub message: String,
    pub details: serde_json::Value,
    pub vault_url: String,
}

/// HMAC signature generation
impl WebhookPayload {
    pub fn sign(&self, secret: &str) -> String {
        let payload_json = serde_json::to_string(self).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_json.as_bytes());
        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }
}

/// Delivery attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub id: String,
    pub webhook_id: String,
    pub event_id: String,
    pub attempt_number: u32,
    pub timestamp: DateTime<Utc>,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub success: bool,
}

/// Delivery log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryLog {
    pub event_id: String,
    pub webhook_id: String,
    pub payload: WebhookPayload,
    pub attempts: Vec<DeliveryAttempt>,
    pub final_status: DeliveryStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,     // All retries exhausted
    Cancelled,
}

/// Webhook delivery engine
pub struct WebhookEngine {
    client: reqwest::Client,
    webhooks: Vec<WebhookConfig>,
    delivery_log: Vec<DeliveryLog>,
}

impl WebhookEngine {
    /// Fire webhooks for an event
    pub async fn fire(&mut self, event_type: EventType, payload: WebhookPayload) {
        let matching_webhooks: Vec<_> = self.webhooks.iter()
            .filter(|w| w.enabled && w.events.contains(&event_type))
            .cloned()
            .collect();

        for webhook in matching_webhooks {
            let delivery = self.deliver(&webhook, &payload).await;
            self.delivery_log.push(delivery);
        }
    }

    async fn deliver(&self, webhook: &WebhookConfig, payload: &WebhookPayload) -> DeliveryLog {
        let signature = payload.sign(&webhook.secret);
        let body = serde_json::to_string(payload).unwrap();

        let mut attempts = Vec::new();
        let mut success = false;

        for attempt in 0..=webhook.retry_count {
            if attempt > 0 {
                let delay = webhook.retry_interval_secs * 2u64.pow(attempt - 1);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }

            let start = std::time::Instant::now();
            let result = self.client
                .post(&webhook.url)
                .header("Content-Type", "application/json")
                .header("X-PQVault-Signature", &signature)
                .header("X-PQVault-Event", format!("{:?}", payload.event_type))
                .header("X-PQVault-Delivery", &payload.event_id)
                .body(body.clone())
                .timeout(std::time::Duration::from_secs(webhook.timeout_secs))
                .send()
                .await;

            let duration = start.elapsed().as_millis() as u64;

            let attempt_record = match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body = response.text().await.unwrap_or_default();
                    success = status >= 200 && status < 300;
                    DeliveryAttempt {
                        id: uuid::Uuid::new_v4().to_string(),
                        webhook_id: webhook.id.clone(),
                        event_id: payload.event_id.clone(),
                        attempt_number: attempt,
                        timestamp: Utc::now(),
                        status_code: Some(status),
                        response_body: Some(body),
                        error: None,
                        duration_ms: duration,
                        success,
                    }
                }
                Err(e) => DeliveryAttempt {
                    id: uuid::Uuid::new_v4().to_string(),
                    webhook_id: webhook.id.clone(),
                    event_id: payload.event_id.clone(),
                    attempt_number: attempt,
                    timestamp: Utc::now(),
                    status_code: None,
                    response_body: None,
                    error: Some(e.to_string()),
                    duration_ms: duration,
                    success: false,
                },
            };

            attempts.push(attempt_record);
            if success { break; }
        }

        DeliveryLog {
            event_id: payload.event_id.clone(),
            webhook_id: webhook.id.clone(),
            payload: payload.clone(),
            attempts,
            final_status: if success { DeliveryStatus::Delivered } else { DeliveryStatus::Failed },
            created_at: Utc::now(),
        }
    }
}
```

### MCP Tools

```rust
/// Register a webhook endpoint
#[tool(name = "webhook_register")]
async fn webhook_register(
    &self,
    #[arg(description = "Webhook name")] name: String,
    #[arg(description = "Endpoint URL")] url: String,
    #[arg(description = "Events to subscribe (comma-separated)")] events: String,
    #[arg(description = "Signing secret (auto-generated if omitted)")] secret: Option<String>,
) -> Result<CallToolResult, McpError> {
    let event_types: HashSet<EventType> = events.split(',')
        .filter_map(|e| EventType::from_str(e.trim()).ok())
        .collect();

    let signing_secret = secret.unwrap_or_else(|| generate_secure_token(32));
    let webhook = WebhookConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        url,
        secret: signing_secret.clone(),
        events: event_types,
        enabled: true,
        created_at: Utc::now(),
        headers: vec![],
        retry_count: 3,
        retry_interval_secs: 30,
        timeout_secs: 10,
    };

    self.engine.register(webhook.clone()).await;
    Ok(CallToolResult::success(format!(
        "Webhook registered:\n  ID: {}\n  URL: {}\n  Events: {}\n  Secret: {} (save this!)",
        webhook.id, webhook.url, events, signing_secret
    )))
}

/// List registered webhooks
#[tool(name = "webhook_list")]
async fn webhook_list(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Test a webhook (send a test event)
#[tool(name = "webhook_test")]
async fn webhook_test(
    &self,
    #[arg(description = "Webhook ID")] webhook_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation: sends a test ping event
}

/// View delivery log
#[tool(name = "webhook_deliveries")]
async fn webhook_deliveries(
    &self,
    #[arg(description = "Webhook ID (all if omitted)")] webhook_id: Option<String>,
    #[arg(description = "Only failed deliveries")] failed_only: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Retry failed deliveries
#[tool(name = "webhook_retry")]
async fn webhook_retry(
    &self,
    #[arg(description = "Delivery ID")] delivery_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Delete a webhook
#[tool(name = "webhook_delete")]
async fn webhook_delete(
    &self,
    #[arg(description = "Webhook ID")] webhook_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Register webhook for Slack
pqvault webhook register \
  --name "slack-alerts" \
  --url "https://hooks.slack.com/services/T00/B00/xxx" \
  --events "anomaly_detected,budget_exceeded,break_glass_used,key_revoked"
# Webhook registered. Signing secret: whsec_abc123...

# Register webhook for PagerDuty
pqvault webhook register \
  --name "pagerduty-critical" \
  --url "https://events.pagerduty.com/v2/enqueue" \
  --events "key_revoked,provider_down,break_glass_used" \
  --secret "pd-secret-123"

# List webhooks
pqvault webhook list
# slack-alerts | https://hooks.slack.com/... | 4 events | Active | 23 deliveries
# pagerduty    | https://events.pagerduty... | 3 events | Active | 5 deliveries

# Test a webhook
pqvault webhook test wh-abc123
# Test event sent to https://hooks.slack.com/... → 200 OK (234ms)

# View delivery log
pqvault webhook deliveries --webhook wh-abc123
# [2026-03-07 14:30] AnomalyDetected → 200 OK (156ms)
# [2026-03-07 12:15] BudgetExceeded → 200 OK (234ms)
# [2026-03-06 23:45] KeyRevoked → 502 (retry 1) → 502 (retry 2) → 200 OK

# View failed deliveries
pqvault webhook deliveries --failed-only

# Retry a failed delivery
pqvault webhook retry del-xyz789

# Disable webhook
pqvault webhook disable wh-abc123

# Delete webhook
pqvault webhook delete wh-abc123
```

### Web UI Changes

- Webhook management page with create/edit/delete
- Event type selector with descriptions
- Delivery log with expandable attempt details
- Test button that sends a ping
- Retry button for failed deliveries
- Signing secret display (show once on creation)

## Dependencies

- `reqwest = "0.12"` (existing) — HTTP client for webhook delivery
- `hmac = "0.12"` — HMAC-SHA256 payload signing (existing via crypto stack)
- `sha2 = "0.10"` (existing) — SHA-256 hashing
- `hex = "0.4"` (existing) — Hex encoding for signatures
- `tokio = "1"` (existing) — Async delivery and retry scheduling

## Testing

### Unit Tests

```rust
#[test]
fn hmac_signature_consistent() {
    let payload = WebhookPayload {
        event_id: "evt-1".into(),
        event_type: EventType::KeyRotated,
        timestamp: Utc::now(),
        key_name: Some("STRIPE_KEY".into()),
        actor: Some("alice".into()),
        severity: "info".into(),
        message: "Key rotated".into(),
        details: serde_json::json!({}),
        vault_url: "https://vault.example.com".into(),
    };

    let sig1 = payload.sign("secret123");
    let sig2 = payload.sign("secret123");
    assert_eq!(sig1, sig2);
    assert!(sig1.starts_with("sha256="));
}

#[test]
fn hmac_signature_differs_with_different_secret() {
    let payload = WebhookPayload::test();
    let sig1 = payload.sign("secret1");
    let sig2 = payload.sign("secret2");
    assert_ne!(sig1, sig2);
}

#[test]
fn event_type_filtering() {
    let webhook = WebhookConfig {
        events: [EventType::KeyRotated, EventType::AnomalyDetected].into(),
        ..Default::default()
    };
    assert!(webhook.events.contains(&EventType::KeyRotated));
    assert!(!webhook.events.contains(&EventType::KeyCreated));
}

#[test]
fn retry_backoff_calculation() {
    let base = 30u64;
    assert_eq!(base * 2u64.pow(0), 30);  // First retry: 30s
    assert_eq!(base * 2u64.pow(1), 60);  // Second retry: 60s
    assert_eq!(base * 2u64.pow(2), 120); // Third retry: 120s
}
```

### Integration Tests

```rust
#[tokio::test]
async fn webhook_delivers_on_event() {
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("POST", "/webhook")
        .with_status(200)
        .match_header("X-PQVault-Event", "KeyRotated")
        .match_header("X-PQVault-Signature", mockito::Matcher::Regex("sha256=.*".into()))
        .create_async().await;

    let mut engine = test_webhook_engine().await;
    engine.register(WebhookConfig {
        url: format!("{}/webhook", server.url()),
        events: [EventType::KeyRotated].into(),
        secret: "test-secret".into(),
        ..Default::default()
    }).await;

    engine.fire(EventType::KeyRotated, WebhookPayload::test()).await;
    mock.assert_async().await;
}

#[tokio::test]
async fn webhook_retries_on_failure() {
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("POST", "/webhook")
        .with_status(500)
        .expect(4) // 1 initial + 3 retries
        .create_async().await;

    let mut engine = test_webhook_engine().await;
    engine.register(WebhookConfig {
        url: format!("{}/webhook", server.url()),
        events: [EventType::KeyRotated].into(),
        retry_count: 3,
        retry_interval_secs: 0, // No delay in tests
        ..Default::default()
    }).await;

    engine.fire(EventType::KeyRotated, WebhookPayload::test()).await;
    mock.assert_async().await;
}

#[tokio::test]
async fn webhook_skips_unsubscribed_events() {
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("POST", "/webhook")
        .expect(0) // Should never be called
        .create_async().await;

    let mut engine = test_webhook_engine().await;
    engine.register(WebhookConfig {
        url: format!("{}/webhook", server.url()),
        events: [EventType::KeyRotated].into(), // Only subscribed to rotations
        ..Default::default()
    }).await;

    engine.fire(EventType::KeyCreated, WebhookPayload::test()).await; // Different event
    mock.assert_async().await;
}
```

### Manual Verification

1. Register a webhook pointing to a request bin (e.g., webhook.site)
2. Trigger events (rotate a key, cause an anomaly)
3. Verify webhook is received with correct payload
4. Verify HMAC signature matches
5. Simulate endpoint failure, verify retries with backoff
6. Check delivery log for all attempts
7. Test webhook test command

## Example Usage

```bash
# Slack integration:
pqvault webhook register --name slack \
  --url "https://hooks.slack.com/services/T00/B00/xxx" \
  --events "anomaly_detected,budget_exceeded,key_revoked,break_glass_used"

# Webhook payload example:
# POST https://hooks.slack.com/services/T00/B00/xxx
# X-PQVault-Signature: sha256=abc123...
# X-PQVault-Event: AnomalyDetected
# {
#   "event_id": "evt-abc123",
#   "event_type": "AnomalyDetected",
#   "timestamp": "2026-03-07T14:30:00Z",
#   "key_name": "ANTHROPIC_KEY",
#   "actor": "system",
#   "severity": "critical",
#   "message": "Usage spike: 892 requests vs 45 avg (z=4.21)",
#   "details": {"z_score": 4.21, "expected": 45.2, "actual": 892},
#   "vault_url": "https://vault.company.com"
# }

# Verifying webhook signatures (receiving end):
# signature = request.headers["X-PQVault-Signature"]
# expected = "sha256=" + hmac_sha256(webhook_secret, request.body)
# assert signature == expected
```
