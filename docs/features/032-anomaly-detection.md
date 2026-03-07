# Feature 032: Anomaly Detection

## Status: Done
## Phase: 4 (v2.4)
## Priority: High

## Problem

Compromised or misused key access goes unnoticed until the monthly bill arrives or a provider revokes the key. There is no automated detection of unusual usage patterns — a key that normally gets 10 requests/day suddenly getting 10,000 would not trigger any alert. Without anomaly detection, the vault is blind to breaches, runaway scripts, and misconfigured agents.

## Solution

Implement Z-score based anomaly detection on daily usage counts per key. The system maintains a rolling 30-day window of daily request counts and costs, calculates the mean and standard deviation, and flags any day where the value exceeds 2 standard deviations from the mean. Anomalies are classified by severity (warning at 2 sigma, critical at 3 sigma) and published to the event bus for real-time dashboard alerts and optional webhook notification.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/anomaly.rs` — Z-score anomaly detection engine
- `crates/pqvault-health-mcp/src/lib.rs` — Register anomaly detection tools
- `crates/pqvault-health-mcp/src/baseline.rs` — Rolling baseline computation and storage
- `crates/pqvault-core/src/metrics.rs` — Daily metrics aggregation

### Data Model Changes

```rust
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Daily usage metrics for a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyMetrics {
    pub key_name: String,
    pub date: NaiveDate,
    pub request_count: u64,
    pub cost_usd: f64,
    pub unique_agents: u32,
    pub error_count: u32,
}

/// Rolling baseline statistics for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub key_name: String,
    pub metric: MetricType,
    pub window_days: u32,
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub data_points: u32,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    RequestCount,
    CostUsd,
    UniqueAgents,
    ErrorCount,
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub key_name: String,
    pub metric: MetricType,
    pub date: NaiveDate,
    pub expected: f64,
    pub actual: f64,
    pub z_score: f64,
    pub severity: AnomalySeverity,
    pub detected_at: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AnomalySeverity {
    Warning,  // 2.0 <= z < 3.0
    Critical, // z >= 3.0
}

/// Anomaly detection engine
pub struct AnomalyDetector {
    window_days: u32,
    warning_threshold: f64,
    critical_threshold: f64,
}

impl AnomalyDetector {
    pub fn new(window_days: u32) -> Self {
        Self {
            window_days,
            warning_threshold: 2.0,
            critical_threshold: 3.0,
        }
    }

    /// Calculate baseline from historical data
    pub fn compute_baseline(
        &self,
        history: &[DailyMetrics],
        metric: MetricType,
    ) -> Baseline {
        let values: Vec<f64> = history.iter().map(|m| match metric {
            MetricType::RequestCount => m.request_count as f64,
            MetricType::CostUsd => m.cost_usd,
            MetricType::UniqueAgents => m.unique_agents as f64,
            MetricType::ErrorCount => m.error_count as f64,
        }).collect();

        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
        let std_dev = variance.sqrt();

        Baseline {
            key_name: history.first().map(|h| h.key_name.clone()).unwrap_or_default(),
            metric,
            window_days: self.window_days,
            mean,
            std_dev,
            min: values.iter().cloned().fold(f64::INFINITY, f64::min),
            max: values.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            data_points: values.len() as u32,
            last_updated: Utc::now(),
        }
    }

    /// Check if a value is anomalous
    pub fn check(&self, baseline: &Baseline, value: f64) -> Option<Anomaly> {
        if baseline.std_dev == 0.0 || baseline.data_points < 7 {
            return None; // Not enough data or zero variance
        }

        let z_score = (value - baseline.mean) / baseline.std_dev;

        if z_score.abs() >= self.warning_threshold {
            let severity = if z_score.abs() >= self.critical_threshold {
                AnomalySeverity::Critical
            } else {
                AnomalySeverity::Warning
            };

            Some(Anomaly {
                key_name: baseline.key_name.clone(),
                metric: baseline.metric,
                date: Utc::now().date_naive(),
                expected: baseline.mean,
                actual: value,
                z_score,
                severity,
                detected_at: Utc::now(),
                acknowledged: false,
            })
        } else {
            None
        }
    }
}
```

### MCP Tools

```rust
/// Run anomaly detection on all keys
#[tool(name = "detect_anomalies")]
async fn detect_anomalies(
    &self,
    #[arg(description = "Specific key to check (all if omitted)")] key_name: Option<String>,
    #[arg(description = "Lookback window in days")] window_days: Option<u32>,
) -> Result<CallToolResult, McpError> {
    let window = window_days.unwrap_or(30);
    let detector = AnomalyDetector::new(window);
    let mut anomalies = Vec::new();

    let keys = match key_name {
        Some(name) => vec![name],
        None => self.vault.list_key_names().await?,
    };

    for key in &keys {
        let history = self.metrics.get_daily_history(key, window).await?;
        for metric in &[MetricType::RequestCount, MetricType::CostUsd, MetricType::ErrorCount] {
            let baseline = detector.compute_baseline(&history, *metric);
            let today_value = history.last().map(|m| match metric {
                MetricType::RequestCount => m.request_count as f64,
                MetricType::CostUsd => m.cost_usd,
                MetricType::ErrorCount => m.error_count as f64,
                _ => 0.0,
            }).unwrap_or(0.0);

            if let Some(anomaly) = detector.check(&baseline, today_value) {
                anomalies.push(anomaly);
            }
        }
    }

    // Format output
    let output = if anomalies.is_empty() {
        "No anomalies detected.".to_string()
    } else {
        anomalies.iter().map(|a| {
            format!(
                "[{:?}] {} — {:?}: expected {:.1}, got {:.1} (z={:.2})",
                a.severity, a.key_name, a.metric, a.expected, a.actual, a.z_score
            )
        }).collect::<Vec<_>>().join("\n")
    };

    Ok(CallToolResult::success(output))
}

/// Acknowledge an anomaly (suppress future alerts for this instance)
#[tool(name = "acknowledge_anomaly")]
async fn acknowledge_anomaly(
    &self,
    #[arg(description = "Key name")] key_name: String,
    #[arg(description = "Metric type")] metric: String,
    #[arg(description = "Reason for acknowledgment")] reason: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}

/// Get baseline statistics for a key
#[tool(name = "get_baseline")]
async fn get_baseline(
    &self,
    #[arg(description = "Key name")] key_name: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Run anomaly detection
pqvault health anomalies
# [CRITICAL] ANTHROPIC_KEY — RequestCount: expected 45.2, got 892.0 (z=4.21)
# [WARNING]  STRIPE_KEY — CostUsd: expected $2.30, got $8.50 (z=2.34)

# Check specific key
pqvault health anomalies --key ANTHROPIC_KEY

# View baseline for a key
pqvault health baseline ANTHROPIC_KEY
# RequestCount: mean=45.2, std=12.3, min=22, max=78 (30 days)
# CostUsd: mean=$2.30, std=$0.45, min=$1.20, max=$3.10

# Acknowledge an anomaly
pqvault health ack ANTHROPIC_KEY --metric request_count --reason "batch job"

# Configure thresholds
pqvault config set anomaly.warning_threshold 2.0
pqvault config set anomaly.critical_threshold 3.0
pqvault config set anomaly.window_days 30
```

### Web UI Changes

- Anomaly alert banner on dashboard (red for critical, yellow for warning)
- Baseline overlay on usage charts (shaded mean +/- 2 sigma band)
- Anomaly timeline view showing detected anomalies over time
- One-click acknowledge with reason field

## Dependencies

- `pqvault-core` (existing) — Metrics storage
- `chrono = "0.4"` (existing) — Date handling
- No new crate dependencies (pure math)

## Testing

### Unit Tests

```rust
#[test]
fn z_score_calculation_correct() {
    let detector = AnomalyDetector::new(30);
    let history = (0..30).map(|i| DailyMetrics {
        key_name: "TEST".into(),
        date: NaiveDate::from_ymd_opt(2026, 1, i + 1).unwrap(),
        request_count: 50,
        cost_usd: 2.0,
        unique_agents: 1,
        error_count: 0,
    }).collect::<Vec<_>>();

    let baseline = detector.compute_baseline(&history, MetricType::RequestCount);
    assert!((baseline.mean - 50.0).abs() < 0.001);
    assert!((baseline.std_dev - 0.0).abs() < 0.001);
}

#[test]
fn anomaly_detected_at_threshold() {
    let detector = AnomalyDetector::new(30);
    let baseline = Baseline {
        key_name: "TEST".into(),
        metric: MetricType::RequestCount,
        mean: 50.0,
        std_dev: 10.0,
        data_points: 30,
        ..Default::default()
    };

    // Below threshold — no anomaly
    assert!(detector.check(&baseline, 65.0).is_none());

    // Warning threshold (z >= 2)
    let anomaly = detector.check(&baseline, 72.0).unwrap();
    assert_eq!(anomaly.severity, AnomalySeverity::Warning);

    // Critical threshold (z >= 3)
    let anomaly = detector.check(&baseline, 85.0).unwrap();
    assert_eq!(anomaly.severity, AnomalySeverity::Critical);
}

#[test]
fn insufficient_data_returns_none() {
    let detector = AnomalyDetector::new(30);
    let baseline = Baseline { data_points: 3, std_dev: 5.0, mean: 50.0, ..Default::default() };
    assert!(detector.check(&baseline, 1000.0).is_none());
}
```

### Integration Tests

```rust
#[tokio::test]
async fn anomaly_published_to_event_bus() {
    let app = test_app().await;
    let mut rx = app.event_bus.subscribe();

    // Generate normal traffic for 30 days
    for day in 0..30 {
        app.metrics.record_daily("KEY1", 50, 2.0).await;
    }
    // Spike
    app.metrics.record_daily("KEY1", 500, 20.0).await;

    app.health.detect_anomalies(None, None).await.unwrap();

    let event = rx.try_recv().unwrap();
    assert!(matches!(event, DashboardEvent::AnomalyAlert { .. }));
}
```

### Manual Verification

1. Generate 30 days of stable usage data for a key
2. Spike usage 10x on day 31
3. Run anomaly detection and verify critical alert fires
4. Check dashboard shows anomaly banner
5. Acknowledge the anomaly and verify it is suppressed

## Example Usage

```bash
# Automated daily anomaly check (run via cron):
pqvault health anomalies --format json > /tmp/anomalies.json
# If any critical anomalies, trigger alert

# In MCP context:
# Agent runs detect_anomalies daily, reports to user:
# "CRITICAL: ANTHROPIC_KEY had 892 requests today vs. average 45.
#  This is 4.21 standard deviations above normal.
#  Possible causes: runaway agent, compromised key, or batch job."
```
