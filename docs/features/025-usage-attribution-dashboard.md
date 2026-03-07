# Feature 025: Usage Attribution Dashboard

## Status: Planned
## Phase: 3 (v2.3)
## Priority: High

## Problem

There is zero visibility into which agent used which key, when, and at what cost. The current usage tracking (Feature 005) aggregates by key only — it shows that OPENAI_API_KEY was accessed 500 times this month, but not that 400 of those came from a single runaway agent. Operators cannot answer basic questions: "Which agent is our biggest API spender?" "What did agent X access yesterday?" "Are any agents accessing keys they shouldn't?"

## Solution

Build a per-agent usage attribution system with a dedicated dashboard. Every proxied request is attributed to the calling agent (via session/token), recording the key accessed, timestamp, cost, and response metadata. The web dashboard shows an agent activity table with drill-down, time-series charts, and anomaly highlighting. MCP tools provide programmatic access to the same data.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/attribution.rs` — Usage attribution tracking and querying
- `crates/pqvault-health-mcp/src/lib.rs` — New MCP tool: agent_usage_report
- `crates/pqvault-web/static/agents.html` — Agent activity dashboard page
- `crates/pqvault-web/static/agents.js` — Dashboard JavaScript for agent views
- `crates/pqvault-web/src/web.rs` — API endpoints for agent usage data
- `crates/pqvault-core/src/models.rs` — AgentUsageRecord struct

### Data Model Changes

```rust
/// A single usage record attributed to an agent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentUsageRecord {
    /// Timestamp of the access
    pub timestamp: String,
    /// Agent token ID
    pub agent_id: String,
    /// Agent name (denormalized for query convenience)
    pub agent_name: String,
    /// Session ID (if session-based)
    pub session_id: Option<String>,
    /// Key that was accessed
    pub key_name: String,
    /// Operation performed
    pub operation: String,
    /// Estimated cost in USD
    pub cost_usd: f64,
    /// HTTP status code from proxied request
    pub response_status: Option<u16>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Aggregated usage report for an agent
#[derive(Serialize, Deserialize, Debug)]
pub struct AgentUsageReport {
    pub agent_id: String,
    pub agent_name: String,
    pub period: String,
    pub total_requests: u64,
    pub total_cost_usd: f64,
    pub keys_accessed: Vec<KeyUsageSummary>,
    pub daily_breakdown: Vec<DailyUsage>,
    pub hourly_distribution: Vec<u64>,  // 24 entries, one per hour
    pub error_rate: f64,
    pub avg_response_time_ms: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUsageSummary {
    pub key_name: String,
    pub request_count: u64,
    pub total_cost_usd: f64,
    pub last_accessed: String,
    pub avg_response_time_ms: f64,
    pub error_count: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DailyUsage {
    pub date: String,
    pub request_count: u64,
    pub cost_usd: f64,
    pub error_count: u64,
}

/// Dashboard summary across all agents
#[derive(Serialize, Deserialize, Debug)]
pub struct AgentDashboard {
    pub total_agents: usize,
    pub active_sessions: usize,
    pub total_requests_today: u64,
    pub total_cost_today: f64,
    pub top_spenders: Vec<AgentSpendSummary>,
    pub recent_activity: Vec<AgentUsageRecord>,
    pub anomalies: Vec<UsageAnomaly>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentSpendSummary {
    pub agent_name: String,
    pub requests_today: u64,
    pub cost_today: f64,
    pub cost_this_month: f64,
    pub trend: SpendTrend,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SpendTrend {
    Increasing,
    Stable,
    Decreasing,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UsageAnomaly {
    pub agent_name: String,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
    pub detected_at: String,
}
```

### MCP Tools

```rust
// Tool: agent_usage_report
{
    "name": "agent_usage_report",
    "description": "Get usage attribution report for agents",
    "params": {
        "agent_id": "agt_abc123",       // optional: specific agent
        "period": "2025-01",             // optional: YYYY-MM, default current month
        "key_name": "OPENAI_API_KEY",    // optional: filter by key
        "limit": 100
    },
    "returns": {
        "agent_name": "code-gen-agent",
        "period": "2025-01",
        "total_requests": 1523,
        "total_cost_usd": 45.67,
        "keys_accessed": [
            { "key_name": "OPENAI_API_KEY", "request_count": 1200, "total_cost_usd": 42.00 },
            { "key_name": "GITHUB_TOKEN", "request_count": 323, "total_cost_usd": 3.67 }
        ],
        "daily_breakdown": [
            { "date": "2025-01-15", "request_count": 45, "cost_usd": 1.35 }
        ]
    }
}

// Tool: agent_dashboard
{
    "name": "agent_dashboard",
    "description": "Get dashboard overview of all agent activity",
    "params": {},
    "returns": {
        "total_agents": 5,
        "active_sessions": 3,
        "total_requests_today": 892,
        "total_cost_today": 27.50,
        "top_spenders": [...],
        "anomalies": [
            {
                "agent_name": "code-gen-agent",
                "anomaly_type": "unusual_key_access",
                "description": "Accessed PRODUCTION_DB_URL for the first time",
                "severity": "medium"
            }
        ]
    }
}

// Tool: agent_usage_export
{
    "name": "agent_usage_export",
    "description": "Export agent usage data as CSV",
    "params": {
        "period": "2025-01",
        "format": "csv"
    },
    "returns": {
        "csv_content": "timestamp,agent,key,operation,cost_usd\n...",
        "row_count": 1523
    }
}
```

### CLI Commands

```bash
# Dashboard overview
pqvault agent dashboard

# Usage report for specific agent
pqvault agent usage agt_abc123

# Usage report for all agents this month
pqvault agent usage --all

# Export usage data
pqvault agent usage --all --export csv --output agent-usage.csv

# Show anomalies
pqvault agent anomalies

# Show top spenders
pqvault agent top-spenders --period 2025-01

# Real-time activity feed
pqvault agent activity --follow
```

### Web UI Changes

**New page: `/agents`** — Agent Activity Dashboard

Layout:
```
+--------------------------------------------------+
| Agent Activity Dashboard                          |
+--------------------------------------------------+
| Today: 892 requests | $27.50 spent | 3 active    |
+--------------------------------------------------+
| Top Spenders (Today)          | Active Sessions   |
| 1. code-gen   $18.50 (67%)   | ses_abc  30m ♥    |
| 2. ci-pipe    $5.20 (19%)    | ses_def  2h  ♥    |
| 3. admin      $3.80 (14%)    | ses_ghi  5m  ♥    |
+--------------------------------------------------+
| Anomalies                                         |
| ⚠ code-gen accessed PROD_DB for first time       |
+--------------------------------------------------+
| Recent Activity                                   |
| 10:30:15  code-gen  OPENAI_KEY   GET  $0.05 200  |
| 10:30:12  ci-pipe   GITHUB_PAT   GET  $0.00 200  |
| 10:29:58  code-gen  OPENAI_KEY   GET  $0.08 200  |
| ...                                               |
+--------------------------------------------------+
```

**API endpoints:**
```
GET /api/agents/dashboard       -> AgentDashboard
GET /api/agents/:id/usage       -> AgentUsageReport
GET /api/agents/activity        -> Vec<AgentUsageRecord>
GET /api/agents/anomalies       -> Vec<UsageAnomaly>
```

## Core Implementation

### Attribution Tracker

```rust
// crates/pqvault-agent-mcp/src/attribution.rs

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use anyhow::Result;
use chrono::{Utc, Datelike};

pub struct AttributionTracker {
    /// Base directory for attribution logs
    log_dir: PathBuf,
}

impl AttributionTracker {
    pub fn new(pqvault_dir: &Path) -> Self {
        let log_dir = pqvault_dir.join("attribution");
        fs::create_dir_all(&log_dir).ok();
        Self { log_dir }
    }

    /// Record a usage event
    pub fn record(
        &self,
        agent_id: &str,
        agent_name: &str,
        session_id: Option<&str>,
        key_name: &str,
        operation: &str,
        cost_usd: f64,
        response_status: Option<u16>,
        response_time_ms: Option<u64>,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        let record = AgentUsageRecord {
            timestamp: Utc::now().to_rfc3339(),
            agent_id: agent_id.to_string(),
            agent_name: agent_name.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            key_name: key_name.to_string(),
            operation: operation.to_string(),
            cost_usd,
            response_status,
            response_time_ms,
            metadata,
        };

        // Append to daily log file
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log_file = self.log_dir.join(format!("{}.jsonl", today));

        let json = serde_json::to_string(&record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        writeln!(file, "{}", json)?;

        Ok(())
    }

    /// Generate usage report for an agent
    pub fn generate_report(
        &self,
        agent_id: Option<&str>,
        period: &str,  // "2025-01" format
    ) -> Result<Vec<AgentUsageReport>> {
        let records = self.load_period(period)?;

        // Group by agent
        let mut by_agent: HashMap<String, Vec<&AgentUsageRecord>> = HashMap::new();
        for record in &records {
            if let Some(aid) = agent_id {
                if record.agent_id != aid {
                    continue;
                }
            }
            by_agent.entry(record.agent_id.clone())
                .or_default()
                .push(record);
        }

        let mut reports = Vec::new();
        for (aid, agent_records) in &by_agent {
            let agent_name = agent_records.first()
                .map(|r| r.agent_name.clone())
                .unwrap_or_default();

            let total_requests = agent_records.len() as u64;
            let total_cost: f64 = agent_records.iter().map(|r| r.cost_usd).sum();

            // Group by key
            let mut by_key: HashMap<String, Vec<&&AgentUsageRecord>> = HashMap::new();
            for r in agent_records {
                by_key.entry(r.key_name.clone()).or_default().push(r);
            }

            let keys_accessed: Vec<KeyUsageSummary> = by_key.iter().map(|(key, recs)| {
                let error_count = recs.iter()
                    .filter(|r| r.response_status.map(|s| s >= 400).unwrap_or(false))
                    .count() as u64;
                let avg_rt = recs.iter()
                    .filter_map(|r| r.response_time_ms)
                    .sum::<u64>() as f64 / recs.len().max(1) as f64;

                KeyUsageSummary {
                    key_name: key.clone(),
                    request_count: recs.len() as u64,
                    total_cost_usd: recs.iter().map(|r| r.cost_usd).sum(),
                    last_accessed: recs.last().map(|r| r.timestamp.clone()).unwrap_or_default(),
                    avg_response_time_ms: avg_rt,
                    error_count,
                }
            }).collect();

            // Daily breakdown
            let mut by_day: HashMap<String, (u64, f64, u64)> = HashMap::new();
            for r in agent_records {
                let day = &r.timestamp[..10]; // "2025-01-15"
                let entry = by_day.entry(day.to_string()).or_default();
                entry.0 += 1;
                entry.1 += r.cost_usd;
                if r.response_status.map(|s| s >= 400).unwrap_or(false) {
                    entry.2 += 1;
                }
            }
            let daily_breakdown: Vec<DailyUsage> = by_day.into_iter()
                .map(|(date, (count, cost, errors))| DailyUsage {
                    date, request_count: count, cost_usd: cost, error_count: errors,
                })
                .collect();

            // Hourly distribution
            let mut hourly = vec![0u64; 24];
            for r in agent_records {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&r.timestamp) {
                    hourly[dt.hour() as usize] += 1;
                }
            }

            let error_count: u64 = agent_records.iter()
                .filter(|r| r.response_status.map(|s| s >= 400).unwrap_or(false))
                .count() as u64;
            let error_rate = error_count as f64 / total_requests.max(1) as f64;

            let avg_response_time = agent_records.iter()
                .filter_map(|r| r.response_time_ms)
                .sum::<u64>() as f64 / total_requests.max(1) as f64;

            reports.push(AgentUsageReport {
                agent_id: aid.clone(),
                agent_name,
                period: period.to_string(),
                total_requests,
                total_cost_usd: total_cost,
                keys_accessed,
                daily_breakdown,
                hourly_distribution: hourly,
                error_rate,
                avg_response_time_ms: avg_response_time,
            });
        }

        Ok(reports)
    }

    /// Build the dashboard overview
    pub fn build_dashboard(&self) -> Result<AgentDashboard> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let today_records = self.load_day(&today)?;

        let mut agents: HashMap<String, (String, u64, f64)> = HashMap::new();
        for r in &today_records {
            let entry = agents.entry(r.agent_id.clone())
                .or_insert_with(|| (r.agent_name.clone(), 0, 0.0));
            entry.1 += 1;
            entry.2 += r.cost_usd;
        }

        let mut top_spenders: Vec<AgentSpendSummary> = agents.iter()
            .map(|(_, (name, reqs, cost))| AgentSpendSummary {
                agent_name: name.clone(),
                requests_today: *reqs,
                cost_today: *cost,
                cost_this_month: *cost, // TODO: accumulate from month
                trend: SpendTrend::Stable,
            })
            .collect();
        top_spenders.sort_by(|a, b| b.cost_today.partial_cmp(&a.cost_today).unwrap());

        let anomalies = self.detect_anomalies(&today_records);

        Ok(AgentDashboard {
            total_agents: agents.len(),
            active_sessions: 0, // Filled by session manager
            total_requests_today: today_records.len() as u64,
            total_cost_today: today_records.iter().map(|r| r.cost_usd).sum(),
            top_spenders,
            recent_activity: today_records.into_iter().rev().take(20).collect(),
            anomalies,
        })
    }

    /// Detect anomalies in usage patterns
    fn detect_anomalies(&self, records: &[AgentUsageRecord]) -> Vec<UsageAnomaly> {
        let mut anomalies = Vec::new();

        // Detect: agent accessing a key for the first time
        // Detect: unusual access time (outside normal hours)
        // Detect: high error rate
        // (Implementation details would use historical data comparison)

        // Example: high error rate detection
        let mut error_rates: HashMap<String, (u64, u64)> = HashMap::new();
        for r in records {
            let entry = error_rates.entry(r.agent_id.clone()).or_default();
            entry.0 += 1;
            if r.response_status.map(|s| s >= 400).unwrap_or(false) {
                entry.1 += 1;
            }
        }

        for (agent_id, (total, errors)) in &error_rates {
            let rate = *errors as f64 / *total as f64;
            if rate > 0.5 && *total >= 10 {
                anomalies.push(UsageAnomaly {
                    agent_name: agent_id.clone(),
                    anomaly_type: "high_error_rate".into(),
                    description: format!(
                        "Error rate {:.0}% ({}/{} requests)",
                        rate * 100.0, errors, total
                    ),
                    severity: "high".into(),
                    detected_at: Utc::now().to_rfc3339(),
                });
            }
        }

        anomalies
    }

    fn load_period(&self, period: &str) -> Result<Vec<AgentUsageRecord>> {
        let mut records = Vec::new();
        let pattern = format!("{}-*.jsonl", period);

        if let Ok(entries) = fs::read_dir(&self.log_dir) {
            for entry in entries.flatten() {
                let filename = entry.file_name().to_string_lossy().to_string();
                if filename.starts_with(period) && filename.ends_with(".jsonl") {
                    let file = fs::File::open(entry.path())?;
                    for line in BufReader::new(file).lines() {
                        if let Ok(line) = line {
                            if let Ok(record) = serde_json::from_str::<AgentUsageRecord>(&line) {
                                records.push(record);
                            }
                        }
                    }
                }
            }
        }

        Ok(records)
    }

    fn load_day(&self, date: &str) -> Result<Vec<AgentUsageRecord>> {
        let path = self.log_dir.join(format!("{}.jsonl", date));
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&path)?;
        let mut records = Vec::new();
        for line in BufReader::new(file).lines() {
            if let Ok(line) = line {
                if let Ok(record) = serde_json::from_str::<AgentUsageRecord>(&line) {
                    records.push(record);
                }
            }
        }

        Ok(records)
    }
}
```

## Dependencies

- No new crate dependencies
- Uses existing `serde_json`, `chrono`
- Requires Feature 021 (Agent-Scoped Tokens) for agent identification
- Requires Feature 024 (Session-Based Access) for session correlation
- Requires Feature 009 (Separate Web UI Files) for dashboard page

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_record_and_load() {
        let dir = tempdir().unwrap();
        let tracker = AttributionTracker::new(dir.path());

        tracker.record(
            "agt_1", "test-agent", Some("ses_1"),
            "OPENAI_KEY", "GET", 0.05,
            Some(200), Some(150), HashMap::new(),
        ).unwrap();

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let records = tracker.load_day(&today).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].agent_name, "test-agent");
        assert_eq!(records[0].cost_usd, 0.05);
    }

    #[test]
    fn test_generate_report() {
        let dir = tempdir().unwrap();
        let tracker = AttributionTracker::new(dir.path());

        // Record 10 requests across 2 keys
        for i in 0..10 {
            let key = if i < 7 { "OPENAI_KEY" } else { "GITHUB_TOKEN" };
            let cost = if key == "OPENAI_KEY" { 0.05 } else { 0.0 };
            tracker.record(
                "agt_1", "test-agent", None,
                key, "GET", cost, Some(200), Some(100), HashMap::new(),
            ).unwrap();
        }

        let period = Utc::now().format("%Y-%m").to_string();
        let reports = tracker.generate_report(Some("agt_1"), &period).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].total_requests, 10);
        assert!((reports[0].total_cost_usd - 0.35).abs() < 0.01);
        assert_eq!(reports[0].keys_accessed.len(), 2);
    }

    #[test]
    fn test_dashboard() {
        let dir = tempdir().unwrap();
        let tracker = AttributionTracker::new(dir.path());

        for i in 0..20 {
            let agent = if i < 15 { ("agt_1", "code-gen") } else { ("agt_2", "ci-pipe") };
            tracker.record(
                agent.0, agent.1, None,
                "KEY", "GET", 0.1, Some(200), Some(50), HashMap::new(),
            ).unwrap();
        }

        let dashboard = tracker.build_dashboard().unwrap();
        assert_eq!(dashboard.total_agents, 2);
        assert_eq!(dashboard.total_requests_today, 20);
        assert!((dashboard.total_cost_today - 2.0).abs() < 0.01);
        assert_eq!(dashboard.top_spenders[0].agent_name, "code-gen");
    }

    #[test]
    fn test_anomaly_detection_high_error_rate() {
        let mut records = Vec::new();
        for i in 0..20 {
            records.push(AgentUsageRecord {
                timestamp: Utc::now().to_rfc3339(),
                agent_id: "agt_1".into(),
                agent_name: "broken-agent".into(),
                session_id: None,
                key_name: "KEY".into(),
                operation: "GET".into(),
                cost_usd: 0.01,
                response_status: Some(if i < 15 { 500 } else { 200 }),
                response_time_ms: Some(100),
                metadata: HashMap::new(),
            });
        }

        let tracker = AttributionTracker::new(Path::new("/tmp"));
        let anomalies = tracker.detect_anomalies(&records);
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].anomaly_type == "high_error_rate");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_attribution_flow() {
    let dir = tempdir().unwrap();
    let tracker = AttributionTracker::new(dir.path());

    // Simulate agent activity over 3 days
    // ... (create records with varied timestamps)

    // Generate monthly report
    let period = Utc::now().format("%Y-%m").to_string();
    let reports = tracker.generate_report(None, &period).unwrap();
    assert!(!reports.is_empty());

    // Build dashboard
    let dashboard = tracker.build_dashboard().unwrap();
    assert!(dashboard.total_agents > 0);
}
```

### Manual Verification

1. Configure multiple agent tokens
2. Make various API calls through different agents
3. Open web dashboard `/agents` — verify data displayed correctly
4. Run `pqvault agent dashboard` — verify CLI output matches
5. Check anomaly detection: simulate high error rate, verify alert
6. Export usage data: `pqvault agent usage --export csv`

## Example Usage

```bash
# Dashboard overview
$ pqvault agent dashboard
Agent Activity Dashboard — 2025-01-15
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Today: 892 requests | $27.50 spent | 3 active sessions

Top Spenders:
  1. code-gen-agent    $18.50 (67%)  ▲ increasing
  2. ci-pipeline       $5.20  (19%)  — stable
  3. admin-agent       $3.80  (14%)  ▼ decreasing

Anomalies:
  ⚠ HIGH  code-gen-agent: Error rate 45% on OPENAI_API_KEY (last 1h)
  ⚠ MED   ci-pipeline: First-time access to PROD_DATABASE_URL

Recent Activity:
  10:30:15  code-gen   OPENAI_KEY      GET  $0.05  200  145ms
  10:30:12  ci-pipe    GITHUB_TOKEN    GET  $0.00  200  230ms
  10:29:58  code-gen   OPENAI_KEY      GET  $0.08  200  312ms
  10:29:45  admin      STRIPE_KEY      GET  $0.00  200  89ms
  ...

# Detailed report for an agent
$ pqvault agent usage agt_abc123
Usage Report: code-gen-agent (January 2025)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total: 1,523 requests | $45.67 cost | 2.8% error rate

Keys Accessed:
  OPENAI_API_KEY    1200 reqs  $42.00  avg 250ms  1.5% errors
  GITHUB_TOKEN       323 reqs  $3.67   avg 180ms  7.4% errors

Daily Trend:
  Jan 13 ███████████░░░░  120 reqs  $3.60
  Jan 14 ██████████████░  180 reqs  $5.40
  Jan 15 █████████████████ 210 reqs  $6.30

# Export for accounting
$ pqvault agent usage --all --export csv --output jan-2025-usage.csv
Exported 4,521 records to jan-2025-usage.csv
```
