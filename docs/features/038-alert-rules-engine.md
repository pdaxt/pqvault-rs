# Feature 038: Alert Rules Engine

## Status: Planned
## Phase: 4 (v2.4)
## Priority: Medium

## Problem

Alert conditions are fixed and hardcoded — the anomaly detector uses a fixed Z-score threshold, budget alerts fire at fixed percentages. Users cannot create custom alert rules like "alert if daily cost exceeds $100 AND provider is anthropic" or "alert if any key is accessed more than 1000 times in an hour." Every new alert condition requires code changes and a release.

## Solution

Implement a configurable alert rules engine where users define rules as structured conditions with logical operators (AND, OR, NOT). Each rule has a condition expression, severity level, notification targets, and cooldown period. Rules are evaluated against real-time vault events, and matching rules fire alerts through the configured notification channels (dashboard, CLI, webhook).

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/rules.rs` — Alert rule definition and evaluation engine
- `crates/pqvault-health-mcp/src/rules_eval.rs` — Condition expression evaluator
- `crates/pqvault-health-mcp/src/lib.rs` — Register alert rule management tools
- `crates/pqvault-core/src/alerts.rs` — Alert storage and history

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: Condition,
    pub severity: AlertSeverity,
    pub enabled: bool,
    pub cooldown_minutes: u32,
    pub last_fired: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub fire_count: u64,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Condition expression tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Compare a metric to a threshold
    Threshold {
        metric: MetricRef,
        operator: CompareOp,
        value: f64,
    },
    /// Key name matches a pattern
    KeyMatch {
        pattern: String,
    },
    /// Provider matches
    ProviderMatch {
        provider: String,
    },
    /// Logical AND of sub-conditions
    And(Vec<Condition>),
    /// Logical OR of sub-conditions
    Or(Vec<Condition>),
    /// Logical NOT
    Not(Box<Condition>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompareOp {
    Gt,   // >
    Gte,  // >=
    Lt,   // <
    Lte,  // <=
    Eq,   // ==
    Neq,  // !=
}

/// Reference to a metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricRef {
    DailyCost,
    HourlyCost,
    DailyRequests,
    HourlyRequests,
    ErrorRate,
    ResponseTimeMs,
    DaysSinceRotation,
    HealthScore,
    ZScore,
}

/// Evaluation context — metrics available at evaluation time
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub key_name: String,
    pub provider: Option<String>,
    pub metrics: HashMap<String, f64>,
}

/// Alert rule evaluator
pub struct RuleEvaluator;

impl RuleEvaluator {
    pub fn evaluate(condition: &Condition, ctx: &EvalContext) -> bool {
        match condition {
            Condition::Threshold { metric, operator, value } => {
                let actual = Self::resolve_metric(metric, ctx);
                match operator {
                    CompareOp::Gt => actual > *value,
                    CompareOp::Gte => actual >= *value,
                    CompareOp::Lt => actual < *value,
                    CompareOp::Lte => actual <= *value,
                    CompareOp::Eq => (actual - value).abs() < f64::EPSILON,
                    CompareOp::Neq => (actual - value).abs() >= f64::EPSILON,
                }
            }
            Condition::KeyMatch { pattern } => {
                ctx.key_name.to_lowercase().contains(&pattern.to_lowercase())
            }
            Condition::ProviderMatch { provider } => {
                ctx.provider.as_deref() == Some(provider)
            }
            Condition::And(conditions) => conditions.iter().all(|c| Self::evaluate(c, ctx)),
            Condition::Or(conditions) => conditions.iter().any(|c| Self::evaluate(c, ctx)),
            Condition::Not(condition) => !Self::evaluate(condition, ctx),
        }
    }

    fn resolve_metric(metric: &MetricRef, ctx: &EvalContext) -> f64 {
        let key = match metric {
            MetricRef::DailyCost => "daily_cost",
            MetricRef::HourlyCost => "hourly_cost",
            MetricRef::DailyRequests => "daily_requests",
            MetricRef::HourlyRequests => "hourly_requests",
            MetricRef::ErrorRate => "error_rate",
            MetricRef::ResponseTimeMs => "response_time_ms",
            MetricRef::DaysSinceRotation => "days_since_rotation",
            MetricRef::HealthScore => "health_score",
            MetricRef::ZScore => "z_score",
        };
        *ctx.metrics.get(key).unwrap_or(&0.0)
    }
}

/// Fired alert record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub key_name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub fired_at: DateTime<Utc>,
    pub context: HashMap<String, f64>,
    pub acknowledged: bool,
}
```

### MCP Tools

```rust
/// Create a new alert rule
#[tool(name = "create_alert_rule")]
async fn create_alert_rule(
    &self,
    #[arg(description = "Rule name")] name: String,
    #[arg(description = "Rule description")] description: String,
    #[arg(description = "Condition as JSON")] condition_json: String,
    #[arg(description = "Severity: info, warning, critical")] severity: String,
    #[arg(description = "Cooldown in minutes between firings")] cooldown_minutes: Option<u32>,
) -> Result<CallToolResult, McpError> {
    let condition: Condition = serde_json::from_str(&condition_json)?;
    let rule = AlertRule {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        description,
        condition,
        severity: AlertSeverity::from_str(&severity)?,
        enabled: true,
        cooldown_minutes: cooldown_minutes.unwrap_or(60),
        last_fired: None,
        created_at: Utc::now(),
        fire_count: 0,
    };
    self.rules.write().await.push(rule.clone());
    Ok(CallToolResult::success(format!("Rule '{}' created (ID: {})", rule.name, rule.id)))
}

/// List all alert rules
#[tool(name = "list_alert_rules")]
async fn list_alert_rules(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Evaluate all rules against current metrics
#[tool(name = "evaluate_rules")]
async fn evaluate_rules(&self) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// List fired alerts
#[tool(name = "list_alerts")]
async fn list_alerts(
    &self,
    #[arg(description = "Only unacknowledged")] unacked_only: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Create alert rule: high cost on Anthropic
pqvault alert create \
  --name "high-anthropic-cost" \
  --description "Alert when Anthropic daily cost exceeds $100" \
  --severity critical \
  --condition '{
    "And": [
      {"Threshold": {"metric": "DailyCost", "operator": "Gt", "value": 100.0}},
      {"ProviderMatch": {"provider": "anthropic"}}
    ]
  }'

# Create alert rule: key not rotated in 60 days
pqvault alert create \
  --name "rotation-overdue" \
  --description "Key not rotated in 60+ days" \
  --severity warning \
  --condition '{"Threshold": {"metric": "DaysSinceRotation", "operator": "Gt", "value": 60.0}}'

# List rules
pqvault alert rules

# Evaluate rules now
pqvault alert evaluate

# List fired alerts
pqvault alert list --unacked

# Acknowledge an alert
pqvault alert ack <alert-id>

# Disable a rule
pqvault alert disable <rule-id>
```

### Web UI Changes

- Alert rules management page with create/edit/delete
- Visual condition builder (drag-and-drop AND/OR/NOT tree)
- Fired alerts feed with acknowledge buttons
- Alert rule testing ("Preview which keys would match")

## Dependencies

- `serde_json = "1"` (existing) — Condition parsing
- `uuid = "1"` (existing) — Rule IDs
- `chrono = "0.4"` (existing) — Timestamps
- Feature 032 (Anomaly Detection) — Z-score metric source
- Feature 035 (Health Score) — Health score metric source

## Testing

### Unit Tests

```rust
#[test]
fn threshold_condition_gt() {
    let condition = Condition::Threshold {
        metric: MetricRef::DailyCost,
        operator: CompareOp::Gt,
        value: 100.0,
    };
    let mut ctx = EvalContext::default();
    ctx.metrics.insert("daily_cost".into(), 150.0);
    assert!(RuleEvaluator::evaluate(&condition, &ctx));

    ctx.metrics.insert("daily_cost".into(), 50.0);
    assert!(!RuleEvaluator::evaluate(&condition, &ctx));
}

#[test]
fn and_condition() {
    let condition = Condition::And(vec![
        Condition::Threshold { metric: MetricRef::DailyCost, operator: CompareOp::Gt, value: 50.0 },
        Condition::ProviderMatch { provider: "anthropic".into() },
    ]);
    let mut ctx = EvalContext { provider: Some("anthropic".into()), ..Default::default() };
    ctx.metrics.insert("daily_cost".into(), 100.0);
    assert!(RuleEvaluator::evaluate(&condition, &ctx));

    ctx.provider = Some("openai".into());
    assert!(!RuleEvaluator::evaluate(&condition, &ctx));
}

#[test]
fn or_condition() {
    let condition = Condition::Or(vec![
        Condition::KeyMatch { pattern: "PROD".into() },
        Condition::KeyMatch { pattern: "STAGING".into() },
    ]);
    let ctx = EvalContext { key_name: "PROD_DB_URL".into(), ..Default::default() };
    assert!(RuleEvaluator::evaluate(&condition, &ctx));

    let ctx2 = EvalContext { key_name: "DEV_DB_URL".into(), ..Default::default() };
    assert!(!RuleEvaluator::evaluate(&condition, &ctx2));
}

#[test]
fn not_condition() {
    let condition = Condition::Not(Box::new(
        Condition::KeyMatch { pattern: "TEST".into() }
    ));
    let ctx = EvalContext { key_name: "PROD_KEY".into(), ..Default::default() };
    assert!(RuleEvaluator::evaluate(&condition, &ctx));
}

#[test]
fn cooldown_prevents_refiring() {
    let mut rule = AlertRule {
        cooldown_minutes: 60,
        last_fired: Some(Utc::now()),
        ..Default::default()
    };
    assert!(!rule.can_fire());

    rule.last_fired = Some(Utc::now() - chrono::Duration::hours(2));
    assert!(rule.can_fire());
}
```

### Integration Tests

```rust
#[tokio::test]
async fn rule_fires_on_high_cost() {
    let mcp = test_health_mcp().await;
    mcp.create_alert_rule(
        "high-cost", "test",
        r#"{"Threshold": {"metric": "DailyCost", "operator": "Gt", "value": 50.0}}"#,
        "critical", None
    ).await.unwrap();

    // Simulate high cost
    mcp.metrics.record_cost("KEY1", 75.0).await;

    let alerts = mcp.evaluate_rules().await.unwrap();
    assert!(alerts.contains("high-cost"));
}
```

### Manual Verification

1. Create multiple alert rules with different conditions
2. Simulate metrics that should trigger each rule
3. Verify alerts fire with correct severity
4. Test cooldown prevents re-firing
5. Acknowledge alerts and verify they are cleared

## Example Usage

```bash
# Common alert rules:
# 1. Any key costs more than $50/day
pqvault alert create --name "high-daily-cost" --severity warning \
  --condition '{"Threshold": {"metric": "DailyCost", "operator": "Gt", "value": 50.0}}'

# 2. Production key health drops below 50
pqvault alert create --name "unhealthy-prod-key" --severity critical \
  --condition '{"And": [
    {"Threshold": {"metric": "HealthScore", "operator": "Lt", "value": 50.0}},
    {"KeyMatch": {"pattern": "PROD"}}
  ]}'

# 3. Any key with anomalous usage (z > 3)
pqvault alert create --name "usage-spike" --severity warning \
  --condition '{"Threshold": {"metric": "ZScore", "operator": "Gt", "value": 3.0}}'
```
