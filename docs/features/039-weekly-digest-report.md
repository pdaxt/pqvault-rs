# Feature 039: Weekly Digest Report

## Status: Done
## Phase: 4 (v2.4)
## Priority: Medium

## Problem

There is no proactive reporting mechanism — users must manually check the dashboard or run CLI commands to understand vault status. Important trends like slowly increasing costs, approaching key expirations, or accumulating dead keys go unnoticed because nobody remembers to check regularly. This is especially problematic for teams where the vault admin is not actively monitoring every day.

## Solution

Generate a comprehensive weekly summary report covering: top cost contributors, keys approaching expiration or overdue for rotation, unused keys, detected anomalies, health score changes, and security events. The report is available as a structured JSON document, rendered HTML, or plain text. It can be delivered through the MCP tool, CLI, web UI, or pushed via webhook (Feature 060).

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/digest.rs` — Weekly digest generation engine
- `crates/pqvault-health-mcp/src/digest_renderer.rs` — Render digest to text, HTML, JSON
- `crates/pqvault-health-mcp/src/lib.rs` — Register digest tools
- `crates/pqvault-health-mcp/src/scheduler.rs` — Scheduled digest generation

### Data Model Changes

```rust
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Complete weekly digest report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyDigest {
    pub report_id: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub generated_at: DateTime<Utc>,
    pub summary: DigestSummary,
    pub cost_section: CostSection,
    pub rotation_section: RotationSection,
    pub health_section: HealthSection,
    pub security_section: SecuritySection,
    pub usage_section: UsageSection,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestSummary {
    pub total_keys: usize,
    pub keys_added: usize,
    pub keys_removed: usize,
    pub total_requests: u64,
    pub total_cost_usd: f64,
    pub cost_change_pct: f64,     // vs. previous week
    pub health_score_avg: f64,
    pub anomalies_detected: usize,
    pub alerts_fired: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSection {
    pub weekly_total: f64,
    pub daily_average: f64,
    pub top_keys: Vec<KeyCostEntry>,
    pub cost_trend: Vec<(NaiveDate, f64)>,
    pub projected_monthly: f64,
    pub vs_last_week_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCostEntry {
    pub key_name: String,
    pub cost_usd: f64,
    pub pct_of_total: f64,
    pub requests: u64,
    pub cost_per_request: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSection {
    pub overdue_keys: Vec<OverdueKey>,
    pub upcoming_expirations: Vec<ExpiringKey>,
    pub rotated_this_week: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverdueKey {
    pub key_name: String,
    pub days_overdue: u64,
    pub last_rotated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiringKey {
    pub key_name: String,
    pub expires_in_days: u64,
    pub expiry_date: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSection {
    pub average_score: f64,
    pub score_change: f64, // vs. last week
    pub critical_keys: Vec<(String, f64)>,
    pub improved_keys: Vec<(String, f64, f64)>, // name, old, new
    pub degraded_keys: Vec<(String, f64, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySection {
    pub anomalies: Vec<AnomalySummary>,
    pub failed_health_checks: Vec<String>,
    pub access_denials: u64,
    pub suspicious_agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalySummary {
    pub key_name: String,
    pub metric: String,
    pub severity: String,
    pub date: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSection {
    pub most_used_keys: Vec<(String, u64)>,
    pub least_used_keys: Vec<(String, u64)>,
    pub dead_key_candidates: Vec<String>,
    pub new_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub action: String,
    pub key_name: Option<String>,
    pub reason: String,
}

/// Digest generator
pub struct DigestGenerator {
    vault: VaultRef,
    metrics: MetricsRef,
    health: HealthRef,
}

impl DigestGenerator {
    pub async fn generate(&self, period_end: NaiveDate) -> Result<WeeklyDigest> {
        let period_start = period_end - chrono::Duration::days(7);

        let summary = self.build_summary(period_start, period_end).await?;
        let cost_section = self.build_cost_section(period_start, period_end).await?;
        let rotation_section = self.build_rotation_section().await?;
        let health_section = self.build_health_section(period_start).await?;
        let security_section = self.build_security_section(period_start, period_end).await?;
        let usage_section = self.build_usage_section(period_start, period_end).await?;
        let recommendations = self.generate_recommendations(&cost_section, &rotation_section, &health_section).await;

        Ok(WeeklyDigest {
            report_id: format!("digest-{}", period_end),
            period_start,
            period_end,
            generated_at: Utc::now(),
            summary,
            cost_section,
            rotation_section,
            health_section,
            security_section,
            usage_section,
            recommendations,
        })
    }

    async fn generate_recommendations(
        &self,
        costs: &CostSection,
        rotation: &RotationSection,
        health: &HealthSection,
    ) -> Vec<Recommendation> {
        let mut recs = Vec::new();

        for key in &rotation.overdue_keys {
            recs.push(Recommendation {
                priority: "High".into(),
                action: "Rotate key".into(),
                key_name: Some(key.key_name.clone()),
                reason: format!("{} days overdue for rotation", key.days_overdue),
            });
        }

        for (name, score) in &health.critical_keys {
            recs.push(Recommendation {
                priority: "Critical".into(),
                action: "Investigate unhealthy key".into(),
                key_name: Some(name.clone()),
                reason: format!("Health score: {:.0}/100", score),
            });
        }

        if costs.vs_last_week_pct > 50.0 {
            recs.push(Recommendation {
                priority: "High".into(),
                action: "Review cost increase".into(),
                key_name: None,
                reason: format!("Costs increased {:.0}% vs. last week", costs.vs_last_week_pct),
            });
        }

        recs
    }
}
```

### MCP Tools

```rust
/// Generate weekly digest report
#[tool(name = "weekly_digest")]
async fn weekly_digest(
    &self,
    #[arg(description = "Format: text, json, html")] format: Option<String>,
    #[arg(description = "Period end date (YYYY-MM-DD), default: today")] end_date: Option<String>,
) -> Result<CallToolResult, McpError> {
    let end = end_date
        .and_then(|d| NaiveDate::parse_from_str(&d, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive());

    let digest = self.digest_gen.generate(end).await?;

    let output = match format.as_deref().unwrap_or("text") {
        "json" => serde_json::to_string_pretty(&digest)?,
        "html" => render_html(&digest),
        _ => render_text(&digest),
    };

    Ok(CallToolResult::success(output))
}

/// List past digest reports
#[tool(name = "list_digests")]
async fn list_digests(
    &self,
    #[arg(description = "Number of past reports")] count: Option<usize>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Generate this week's digest
pqvault digest
# ═══════════════════════════════════════════
# PQVault Weekly Digest — Feb 24 - Mar 2, 2026
# ═══════════════════════════════════════════
#
# SUMMARY
#   Total Keys: 42 (+2 new, -1 removed)
#   Requests: 12,345 (avg 1,763/day)
#   Cost: $67.89 (+12% vs last week)
#   Health: 78/100 avg (-3 vs last week)
#
# TOP COSTS
#   1. ANTHROPIC_KEY — $34.50 (50.8%) — 8,234 requests
#   2. OPENAI_KEY — $22.10 (32.6%) — 3,456 requests
#   3. STRIPE_KEY — $5.20 (7.7%) — 567 requests
#
# ROTATION OVERDUE
#   - DATABASE_URL — 15 days overdue
#   - OLD_API_KEY — 45 days overdue
#
# RECOMMENDATIONS
#   [Critical] Investigate DATABASE_URL — health 23/100
#   [High] Rotate OLD_API_KEY — 45 days overdue
#   [High] Review cost increase — +12% vs last week

# Export as JSON
pqvault digest --format json > digest.json

# Export as HTML
pqvault digest --format html > digest.html

# View past digests
pqvault digest list
```

### Web UI Changes

- Weekly digest page accessible from dashboard
- Visual report with charts, tables, and recommendations
- Email-style rendered view suitable for sharing
- "Generate now" button and past reports archive

## Dependencies

- `pqvault-core` (existing) — Data access
- `chrono = "0.4"` (existing) — Date calculations
- `serde_json = "1"` (existing) — JSON output
- Features 032-037 — Anomaly, cost, health data sources

## Testing

### Unit Tests

```rust
#[test]
fn recommendations_generated_for_overdue_keys() {
    let rotation = RotationSection {
        overdue_keys: vec![OverdueKey {
            key_name: "OLD_KEY".into(),
            days_overdue: 30,
            last_rotated: None,
        }],
        upcoming_expirations: vec![],
        rotated_this_week: vec![],
    };
    let recs = generate_recommendations_sync(&CostSection::default(), &rotation, &HealthSection::default());
    assert!(recs.iter().any(|r| r.key_name == Some("OLD_KEY".to_string())));
}

#[test]
fn cost_increase_triggers_recommendation() {
    let costs = CostSection {
        vs_last_week_pct: 75.0,
        ..Default::default()
    };
    let recs = generate_recommendations_sync(&costs, &RotationSection::default(), &HealthSection::default());
    assert!(recs.iter().any(|r| r.action.contains("cost")));
}

#[test]
fn digest_summary_counts_correct() {
    let summary = DigestSummary {
        total_keys: 42,
        keys_added: 2,
        keys_removed: 1,
        total_requests: 12345,
        total_cost_usd: 67.89,
        cost_change_pct: 12.0,
        health_score_avg: 78.0,
        anomalies_detected: 1,
        alerts_fired: 3,
    };
    let text = render_summary_text(&summary);
    assert!(text.contains("42"));
    assert!(text.contains("$67.89"));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn full_digest_generation() {
    let mcp = test_health_mcp().await;
    // Populate 7 days of data
    for day in 0..7 {
        mcp.metrics.record_daily("KEY1", 100 + day * 10, 5.0 + day as f64).await;
        mcp.metrics.record_daily("KEY2", 50, 2.0).await;
    }

    let result = mcp.weekly_digest(Some("text"), None).await.unwrap();
    assert!(result.contains("Weekly Digest"));
    assert!(result.contains("KEY1"));
}
```

### Manual Verification

1. Run vault for a week with varied usage
2. Generate digest and verify all sections are populated
3. Compare numbers with dashboard data
4. Test HTML output renders correctly in browser
5. Verify JSON output is parseable and complete

## Example Usage

```bash
# Automated weekly digest (cron job, Sunday midnight):
# 0 0 * * 0 pqvault digest --format json | pqvault webhook send --channel digest

# Agent reads digest and summarizes:
pqvault digest --format json | jq '.recommendations'
# Agent: "Your vault has 2 keys overdue for rotation and costs increased 12%.
#         Top priority: DATABASE_URL health score dropped to 23/100."
```
