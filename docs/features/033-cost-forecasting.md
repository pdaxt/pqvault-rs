# Feature 033: Cost Forecasting

## Status: Done
## Phase: 4 (v2.4)
## Priority: High

## Problem

There is no cost visibility until the bill arrives at the end of the month. Users cannot predict whether their current usage trajectory will stay within budget or blow past it. When multiple agents use expensive API keys (Anthropic, OpenAI), costs can escalate rapidly without any advance warning. Budget alerts only fire after the damage is done.

## Solution

Implement linear regression on historical daily cost data to predict month-end cost per key and in aggregate. The system fits a simple linear model to the last 14-30 days of cost data, extrapolates to the end of the current month, and provides confidence intervals. If the predicted month-end cost exceeds a configurable budget threshold, a proactive alert is generated days or weeks before the actual overage occurs.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/forecast.rs` — Linear regression forecasting engine
- `crates/pqvault-health-mcp/src/budget.rs` — Budget definition and threshold checking
- `crates/pqvault-health-mcp/src/lib.rs` — Register forecasting tools
- `crates/pqvault-core/src/cost.rs` — Cost data aggregation and storage

### Data Model Changes

```rust
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Daily cost data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostDataPoint {
    pub date: NaiveDate,
    pub cost_usd: f64,
    pub request_count: u64,
    pub cost_per_request: f64,
}

/// Linear regression result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearModel {
    pub slope: f64,         // daily cost trend
    pub intercept: f64,     // base cost
    pub r_squared: f64,     // goodness of fit
    pub data_points: usize,
}

impl LinearModel {
    /// Fit a linear model: cost = slope * day_index + intercept
    pub fn fit(data: &[(f64, f64)]) -> Self {
        let n = data.len() as f64;
        let sum_x: f64 = data.iter().map(|(x, _)| x).sum();
        let sum_y: f64 = data.iter().map(|(_, y)| y).sum();
        let sum_xy: f64 = data.iter().map(|(x, y)| x * y).sum();
        let sum_x2: f64 = data.iter().map(|(x, _)| x * x).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        // R-squared
        let y_mean = sum_y / n;
        let ss_tot: f64 = data.iter().map(|(_, y)| (y - y_mean).powi(2)).sum();
        let ss_res: f64 = data.iter().map(|(x, y)| (y - (slope * x + intercept)).powi(2)).sum();
        let r_squared = if ss_tot == 0.0 { 1.0 } else { 1.0 - ss_res / ss_tot };

        Self {
            slope,
            intercept,
            r_squared,
            data_points: data.len(),
        }
    }

    /// Predict cost for a future day index
    pub fn predict(&self, day_index: f64) -> f64 {
        (self.slope * day_index + self.intercept).max(0.0)
    }
}

/// Cost forecast result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostForecast {
    pub key_name: String,
    pub current_month_cost: f64,
    pub predicted_month_end: f64,
    pub daily_trend: f64,       // slope: +/- per day
    pub confidence: f64,        // r_squared
    pub days_remaining: u32,
    pub budget: Option<f64>,
    pub over_budget: bool,
    pub estimated_overage: f64,
}

/// Budget configuration per key or global
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub key_name: Option<String>, // None = global budget
    pub monthly_limit_usd: f64,
    pub warning_pct: f64,         // Alert at this % of budget (default: 80%)
    pub critical_pct: f64,        // Critical alert at this % (default: 95%)
}
```

### MCP Tools

```rust
/// Forecast month-end cost for keys
#[tool(name = "cost_forecast")]
async fn cost_forecast(
    &self,
    #[arg(description = "Specific key (all if omitted)")] key_name: Option<String>,
    #[arg(description = "Days of history to use for regression")] lookback_days: Option<u32>,
) -> Result<CallToolResult, McpError> {
    let lookback = lookback_days.unwrap_or(14);
    let today = Utc::now().date_naive();
    let days_in_month = days_in_current_month(today);
    let day_of_month = today.day();
    let days_remaining = days_in_month - day_of_month;

    let keys = match key_name {
        Some(name) => vec![name],
        None => self.vault.list_key_names().await?,
    };

    let mut forecasts = Vec::new();
    for key in &keys {
        let history = self.cost.get_daily_costs(key, lookback).await?;
        if history.len() < 3 {
            continue; // Not enough data
        }

        let data: Vec<(f64, f64)> = history.iter()
            .enumerate()
            .map(|(i, dp)| (i as f64, dp.cost_usd))
            .collect();

        let model = LinearModel::fit(&data);
        let current_cost: f64 = history.iter()
            .filter(|dp| dp.date.month() == today.month())
            .map(|dp| dp.cost_usd)
            .sum();

        let predicted_remaining: f64 = (0..days_remaining)
            .map(|d| model.predict((data.len() + d as usize) as f64))
            .sum();

        let predicted_total = current_cost + predicted_remaining;
        let budget = self.budget.get_budget(key).await?;
        let over_budget = budget.map(|b| predicted_total > b.monthly_limit_usd).unwrap_or(false);

        forecasts.push(CostForecast {
            key_name: key.clone(),
            current_month_cost: current_cost,
            predicted_month_end: predicted_total,
            daily_trend: model.slope,
            confidence: model.r_squared,
            days_remaining,
            budget: budget.map(|b| b.monthly_limit_usd),
            over_budget,
            estimated_overage: if over_budget {
                predicted_total - budget.unwrap().monthly_limit_usd
            } else { 0.0 },
        });
    }

    let output = forecasts.iter().map(|f| {
        let status = if f.over_budget { "OVER BUDGET" } else { "OK" };
        let trend = if f.daily_trend > 0.0 { "increasing" } else { "decreasing" };
        format!(
            "{}: ${:.2}/mo predicted (current: ${:.2}, trend: {} ${:.2}/day, confidence: {:.0}%) [{}]",
            f.key_name, f.predicted_month_end, f.current_month_cost,
            trend, f.daily_trend.abs(), f.confidence * 100.0, status
        )
    }).collect::<Vec<_>>().join("\n");

    Ok(CallToolResult::success(output))
}

/// Set monthly budget for a key
#[tool(name = "set_budget")]
async fn set_budget(
    &self,
    #[arg(description = "Key name (omit for global)")] key_name: Option<String>,
    #[arg(description = "Monthly budget in USD")] limit_usd: f64,
    #[arg(description = "Warning threshold percentage")] warning_pct: Option<f64>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Forecast all key costs
pqvault health forecast
# ANTHROPIC_KEY: $45.20/mo predicted (current: $23.10, trend: increasing $1.50/day, confidence: 89%) [OK]
# OPENAI_KEY: $120.00/mo predicted (current: $80.00, trend: increasing $2.50/day, confidence: 92%) [OVER BUDGET]
# STRIPE_KEY: $3.20/mo predicted (current: $2.10, trend: stable $0.04/day, confidence: 95%) [OK]

# Forecast specific key
pqvault health forecast --key ANTHROPIC_KEY --lookback 30

# Set budget
pqvault budget set ANTHROPIC_KEY --limit 50.00 --warning-pct 80

# View budgets
pqvault budget list

# Check budget status
pqvault budget status
```

### Web UI Changes

- Cost projection chart with regression line and confidence band
- Budget gauge showing current vs. predicted vs. limit
- "Predicted overage" warning banner when forecast exceeds budget
- Daily cost trend sparklines on key list

## Dependencies

- `pqvault-core` (existing) — Cost data storage
- `chrono = "0.4"` (existing) — Date calculations
- No new crate dependencies (linear regression is implemented inline)

## Testing

### Unit Tests

```rust
#[test]
fn linear_model_perfect_fit() {
    let data = vec![(0.0, 0.0), (1.0, 2.0), (2.0, 4.0), (3.0, 6.0)];
    let model = LinearModel::fit(&data);
    assert!((model.slope - 2.0).abs() < 0.001);
    assert!((model.intercept - 0.0).abs() < 0.001);
    assert!((model.r_squared - 1.0).abs() < 0.001);
    assert!((model.predict(4.0) - 8.0).abs() < 0.001);
}

#[test]
fn linear_model_with_noise() {
    let data = vec![(0.0, 1.1), (1.0, 2.9), (2.0, 5.2), (3.0, 6.8)];
    let model = LinearModel::fit(&data);
    assert!(model.slope > 1.5 && model.slope < 2.5);
    assert!(model.r_squared > 0.95);
}

#[test]
fn forecast_detects_over_budget() {
    let forecast = CostForecast {
        key_name: "TEST".into(),
        current_month_cost: 80.0,
        predicted_month_end: 120.0,
        daily_trend: 2.5,
        confidence: 0.92,
        days_remaining: 15,
        budget: Some(100.0),
        over_budget: true,
        estimated_overage: 20.0,
    };
    assert!(forecast.over_budget);
    assert!((forecast.estimated_overage - 20.0).abs() < 0.01);
}

#[test]
fn predict_never_negative() {
    let model = LinearModel { slope: -5.0, intercept: 2.0, r_squared: 0.8, data_points: 10 };
    assert!(model.predict(100.0) >= 0.0);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn forecast_with_real_data() {
    let mcp = test_health_mcp().await;
    // Insert 14 days of increasing costs
    for day in 0..14 {
        mcp.cost.record("KEY1", day as f64 * 2.0 + 1.0).await;
    }
    let result = mcp.cost_forecast(Some("KEY1".into()), Some(14)).await.unwrap();
    assert!(result.contains("increasing"));
}
```

### Manual Verification

1. Record 14 days of cost data with an upward trend
2. Run forecast, verify predicted month-end is reasonable
3. Set budget below predicted amount, verify "OVER BUDGET" alert
4. Check web dashboard shows projection chart with confidence band
5. Compare forecast accuracy after month ends

## Example Usage

```bash
# Daily forecast check by agent:
pqvault health forecast
# Agent reports: "Based on current trends, ANTHROPIC_KEY will cost $120 by month end.
# Your budget is $100. At current rate, you'll exceed budget in 8 days.
# Recommendation: reduce usage or increase budget."

# Set proactive budget alerts:
pqvault budget set ANTHROPIC_KEY --limit 100.00 --warning-pct 70
# Alert fires when forecast predicts 70% of budget will be used
```
