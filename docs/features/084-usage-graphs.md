# Feature 084: Usage Graphs

## Status: Done
## Phase: 9 (v2.9)
## Priority: High

## Problem

Users have no visibility into how frequently their secrets are accessed. Without usage
data, they cannot identify unused keys that should be decommissioned, detect unusual
access patterns that may indicate compromise, or forecast API costs based on key
usage trends. The dashboard shows static data with no temporal dimension.

## Solution

Add per-key usage sparklines and graphs to the dashboard using Chart.js. Each key
shows a 30-day usage trend inline, and the key detail page (Feature 082) includes
full-size interactive charts with daily/hourly breakdowns, accessor distribution,
and cost projections. Usage data is aggregated from the audit log.

## Implementation

### Files to Create/Modify

```
pqvault-web/
  src/
    routes/
      api/
        usage.rs        # GET /api/usage/:key - usage data API
        usage_summary.rs # GET /api/usage/summary - dashboard overview
    services/
      usage_aggregator.rs # Aggregate audit events into usage metrics
  templates/
    components/
      sparkline.html    # Inline sparkline component
      usage_chart.html  # Full-size chart component
  static/
    js/
      charts.js         # Chart.js initialization and configuration
      sparkline.js      # Lightweight sparkline renderer
```

### Data Model Changes

```rust
/// Usage data point for a single day
#[derive(Serialize, Clone)]
pub struct DailyUsage {
    pub date: String,       // "2025-03-15"
    pub access_count: u64,
    pub unique_accessors: u32,
    pub sources: HashMap<String, u64>,  // "cli": 10, "mcp": 5
}

/// Aggregated usage for a key
#[derive(Serialize)]
pub struct KeyUsage {
    pub key_name: String,
    pub total_accesses: u64,
    pub period_days: u32,
    pub daily: Vec<DailyUsage>,
    pub peak_day: Option<DailyUsage>,
    pub avg_daily: f64,
    pub trend: UsageTrend,
}

pub enum UsageTrend {
    Increasing,
    Stable,
    Decreasing,
    Inactive,   // No usage in last 7 days
}

/// Sparkline data for dashboard inline display
#[derive(Serialize)]
pub struct SparklineData {
    pub key_name: String,
    pub values: Vec<u64>,     // Last 30 days, one value per day
    pub total: u64,
    pub trend: String,        // "up", "down", "stable", "inactive"
}

/// Dashboard usage summary
#[derive(Serialize)]
pub struct UsageSummary {
    pub total_accesses_today: u64,
    pub total_accesses_week: u64,
    pub most_accessed: Vec<(String, u64)>,   // Top 5 keys
    pub least_accessed: Vec<(String, u64)>,  // Bottom 5 keys
    pub inactive_keys: Vec<String>,          // No access in 30 days
    pub hourly_distribution: Vec<u64>,       // 24 values for today
}

/// Usage aggregation engine
pub struct UsageAggregator {
    audit_store: Arc<AuditStore>,
}

impl UsageAggregator {
    pub async fn daily_usage(&self, key: &str, days: u32) -> Result<Vec<DailyUsage>> {
        let since = Utc::now() - chrono::Duration::days(days as i64);
        let events = self.audit_store
            .query_events(key, since, Utc::now(), &[AuditEventType::KeyAccessed])
            .await?;

        let mut by_date: BTreeMap<String, DailyUsage> = BTreeMap::new();

        for event in events {
            let date = event.timestamp.format("%Y-%m-%d").to_string();
            let entry = by_date.entry(date.clone()).or_insert(DailyUsage {
                date,
                access_count: 0,
                unique_accessors: 0,
                sources: HashMap::new(),
            });
            entry.access_count += 1;
            *entry.sources.entry(event.source.clone()).or_insert(0) += 1;
        }

        // Fill in zero-days
        let mut result = Vec::new();
        let mut current = since.date_naive();
        let today = Utc::now().date_naive();
        while current <= today {
            let date_str = current.format("%Y-%m-%d").to_string();
            let usage = by_date.remove(&date_str).unwrap_or(DailyUsage {
                date: date_str,
                access_count: 0,
                unique_accessors: 0,
                sources: HashMap::new(),
            });
            result.push(usage);
            current += chrono::Duration::days(1);
        }

        Ok(result)
    }

    pub async fn sparkline_data(&self, key: &str) -> Result<SparklineData> {
        let daily = self.daily_usage(key, 30).await?;
        let values: Vec<u64> = daily.iter().map(|d| d.access_count).collect();
        let total: u64 = values.iter().sum();

        let trend = calculate_trend(&values);

        Ok(SparklineData {
            key_name: key.to_string(),
            values,
            total,
            trend,
        })
    }
}

fn calculate_trend(values: &[u64]) -> String {
    if values.len() < 7 {
        return "stable".to_string();
    }
    let recent: f64 = values[values.len()-7..].iter().sum::<u64>() as f64 / 7.0;
    let earlier: f64 = values[..7].iter().sum::<u64>() as f64 / 7.0;

    if earlier == 0.0 && recent == 0.0 {
        "inactive".to_string()
    } else if recent > earlier * 1.2 {
        "up".to_string()
    } else if recent < earlier * 0.8 {
        "down".to_string()
    } else {
        "stable".to_string()
    }
}
```

### MCP Tools

No new MCP tools. Usage data accessed via web API.

### CLI Commands

```bash
# Show usage summary for a key
pqvault usage STRIPE_SECRET_KEY

# Show inactive keys (no access in 30 days)
pqvault usage --inactive --days 30

# Show top accessed keys
pqvault usage --top 10
```

### Web UI Changes

Chart.js integration for inline sparklines and full charts:

```javascript
// sparkline.js - Lightweight inline sparklines
function renderSparkline(canvas, data) {
    const ctx = canvas.getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map((_, i) => i),
            datasets: [{
                data: data,
                borderColor: getTrendColor(data),
                borderWidth: 1.5,
                pointRadius: 0,
                fill: false,
                tension: 0.3,
            }],
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            scales: {
                x: { display: false },
                y: { display: false, min: 0 },
            },
        },
    });
}
```

## Dependencies

No new Rust dependencies. Chart.js loaded via CDN in the web frontend:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4/dist/chart.umd.min.js"></script>
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trend_calculation_increasing() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        assert_eq!(calculate_trend(&values), "up");
    }

    #[test]
    fn test_trend_calculation_decreasing() {
        let values = vec![14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        assert_eq!(calculate_trend(&values), "down");
    }

    #[test]
    fn test_trend_calculation_stable() {
        let values = vec![5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5];
        assert_eq!(calculate_trend(&values), "stable");
    }

    #[test]
    fn test_trend_calculation_inactive() {
        let values = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(calculate_trend(&values), "inactive");
    }

    #[test]
    fn test_fill_zero_days() {
        let daily = vec![
            daily_usage("2025-03-10", 5),
            daily_usage("2025-03-12", 3), // Gap on 03-11
        ];
        let filled = fill_gaps(&daily, "2025-03-10", "2025-03-12");
        assert_eq!(filled.len(), 3);
        assert_eq!(filled[1].access_count, 0); // 03-11 filled with 0
    }

    #[test]
    fn test_sparkline_data() {
        let values = vec![1, 3, 5, 2, 4, 6, 3];
        let spark = SparklineData {
            key_name: "KEY".into(),
            values: values.clone(),
            total: values.iter().sum(),
            trend: "stable".into(),
        };
        assert_eq!(spark.total, 24);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_usage_api() {
    let app = test_app_with_audit_events(&[
        ("STRIPE_KEY", "2025-03-10T10:00:00Z"),
        ("STRIPE_KEY", "2025-03-10T14:00:00Z"),
        ("STRIPE_KEY", "2025-03-11T09:00:00Z"),
    ]).await;
    let response = app.get("/api/usage/STRIPE_KEY?days=7").await;
    assert_eq!(response.status(), 200);
    let usage: KeyUsage = response.json().await;
    assert_eq!(usage.total_accesses, 3);
}
```

## Example Usage

```
Dashboard with sparklines:

Key                      Category   Health    Usage (30d)      Trend
─────────────────────    ────────   ──────    ─────────────    ─────
STRIPE_SECRET_KEY        payment    healthy   ▂▃▅▆▇▅▃▂▃▅  42  up
AWS_ACCESS_KEY_ID        cloud      healthy   ▅▅▅▅▅▅▅▅▅▅  150  stable
DATABASE_URL             database   warning   ▇▇▇▇▇▇▇▇▇▇  980  stable
OLD_WEBHOOK_SECRET       misc       healthy   ▁▁▁▁▁▁▁▁▁▁  0   inactive
SENTRY_DSN               monitor    healthy   ▂▂▂▃▃▃▃▂▂▂  28  stable

Key Detail Page - Usage Tab:

┌─ STRIPE_SECRET_KEY Usage ─────────────────────────────┐
│                                                        │
│  Daily Accesses (30 days)                             │
│  8│    ╭╮                                              │
│  6│   ╭╯╰╮    ╭╮                                      │
│  4│  ╭╯  ╰╮  ╭╯╰╮  ╭╮                                │
│  2│ ╭╯    ╰──╯  ╰──╯╰──╮                              │
│  0│╰─────────────────────╰──                           │
│    Mar 1              Mar 15                           │
│                                                        │
│  Top Accessors:        By Source:                      │
│  1. deploy-bot (65%)   CLI: 42%                        │
│  2. alice (20%)        MCP: 38%                        │
│  3. ci-runner (15%)    Web: 20%                        │
└────────────────────────────────────────────────────────┘
```
