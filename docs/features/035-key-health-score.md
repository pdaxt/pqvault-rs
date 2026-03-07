# Feature 035: Key Health Score

## Status: Planned
## Phase: 4 (v2.4)
## Priority: Medium

## Problem

Multiple health signals exist in isolation — age, last verification time, usage patterns, rotation status, provider health — but there is no unified view. A user must check each signal independently to determine whether a key needs attention. This makes it impossible to prioritize which keys to address first when dozens need varying levels of attention.

## Solution

Compute a composite 0-100 health score for each key by weighting multiple factors: age since last rotation (30%), last successful verification (20%), usage pattern normality (20%), rotation compliance (15%), and provider health (15%). Keys scoring below 50 are flagged as "unhealthy," below 25 as "critical." The score provides a single sortable metric for prioritizing key maintenance.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/score.rs` — Health score computation engine
- `crates/pqvault-health-mcp/src/lib.rs` — Register health score tools
- `crates/pqvault-core/src/models.rs` — Add `health_score` field to key metadata

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Individual health factor with score and weight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthFactor {
    pub name: String,
    pub score: f64,       // 0.0 - 100.0
    pub weight: f64,      // 0.0 - 1.0
    pub reason: String,
    pub recommendation: Option<String>,
}

/// Composite key health score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHealthScore {
    pub key_name: String,
    pub overall_score: f64,       // 0 - 100
    pub grade: HealthGrade,
    pub factors: Vec<HealthFactor>,
    pub computed_at: DateTime<Utc>,
    pub top_issue: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HealthGrade {
    Excellent, // 90-100
    Good,      // 70-89
    Fair,      // 50-69
    Poor,      // 25-49
    Critical,  // 0-24
}

impl From<f64> for HealthGrade {
    fn from(score: f64) -> Self {
        match score as u32 {
            90..=100 => HealthGrade::Excellent,
            70..=89 => HealthGrade::Good,
            50..=69 => HealthGrade::Fair,
            25..=49 => HealthGrade::Poor,
            _ => HealthGrade::Critical,
        }
    }
}

/// Health score calculator with configurable weights
pub struct HealthScorer {
    pub age_weight: f64,          // default: 0.30
    pub verification_weight: f64, // default: 0.20
    pub usage_weight: f64,        // default: 0.20
    pub rotation_weight: f64,     // default: 0.15
    pub provider_weight: f64,     // default: 0.15
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self {
            age_weight: 0.30,
            verification_weight: 0.20,
            usage_weight: 0.20,
            rotation_weight: 0.15,
            provider_weight: 0.15,
        }
    }
}

impl HealthScorer {
    /// Calculate age score (100 = recently rotated, 0 = very old)
    fn age_score(&self, last_rotated: Option<DateTime<Utc>>, max_age_days: u32) -> HealthFactor {
        let days_old = last_rotated
            .map(|lr| (Utc::now() - lr).num_days() as f64)
            .unwrap_or(365.0);

        let score = ((1.0 - days_old / max_age_days as f64) * 100.0).clamp(0.0, 100.0);
        let recommendation = if score < 50.0 {
            Some(format!("Key is {:.0} days old — consider rotating", days_old))
        } else {
            None
        };

        HealthFactor {
            name: "Age".into(),
            score,
            weight: self.age_weight,
            reason: format!("{:.0} days since last rotation", days_old),
            recommendation,
        }
    }

    /// Calculate verification score (100 = recently verified, 0 = never verified)
    fn verification_score(&self, last_verified: Option<DateTime<Utc>>) -> HealthFactor {
        let hours_since = last_verified
            .map(|lv| (Utc::now() - lv).num_hours() as f64)
            .unwrap_or(720.0); // 30 days

        let score = ((1.0 - hours_since / 168.0) * 100.0).clamp(0.0, 100.0); // 7 days = 168h
        HealthFactor {
            name: "Verification".into(),
            score,
            weight: self.verification_weight,
            reason: format!("{:.0}h since last provider check", hours_since),
            recommendation: if score < 50.0 {
                Some("Run health check to verify key is still valid".into())
            } else {
                None
            },
        }
    }

    /// Calculate usage score (100 = normal pattern, 0 = anomalous)
    fn usage_score(&self, z_score: Option<f64>) -> HealthFactor {
        let score = match z_score {
            Some(z) if z.abs() > 3.0 => 0.0,
            Some(z) if z.abs() > 2.0 => 30.0,
            Some(z) => ((1.0 - z.abs() / 3.0) * 100.0).clamp(0.0, 100.0),
            None => 80.0, // No anomaly data = assume healthy
        };
        HealthFactor {
            name: "Usage Pattern".into(),
            score,
            weight: self.usage_weight,
            reason: format!("Z-score: {:.2}", z_score.unwrap_or(0.0)),
            recommendation: if score < 50.0 {
                Some("Unusual usage pattern detected — investigate".into())
            } else {
                None
            },
        }
    }

    /// Calculate composite score
    pub fn compute(&self, factors: Vec<HealthFactor>) -> KeyHealthScore {
        let weighted_sum: f64 = factors.iter().map(|f| f.score * f.weight).sum();
        let total_weight: f64 = factors.iter().map(|f| f.weight).sum();
        let overall = weighted_sum / total_weight;

        let top_issue = factors.iter()
            .filter(|f| f.score < 50.0)
            .min_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .and_then(|f| f.recommendation.clone());

        KeyHealthScore {
            key_name: String::new(), // Set by caller
            overall_score: overall,
            grade: HealthGrade::from(overall),
            factors,
            computed_at: Utc::now(),
            top_issue,
        }
    }
}
```

### MCP Tools

```rust
/// Get health score for all keys or a specific key
#[tool(name = "key_health_score")]
async fn key_health_score(
    &self,
    #[arg(description = "Key name (all if omitted)")] key_name: Option<String>,
    #[arg(description = "Sort by score ascending (worst first)")] worst_first: Option<bool>,
) -> Result<CallToolResult, McpError> {
    let scorer = HealthScorer::default();
    let keys = match key_name {
        Some(name) => vec![name],
        None => self.vault.list_key_names().await?,
    };

    let mut scores = Vec::new();
    for key in &keys {
        let meta = self.vault.get_metadata(key).await?;
        let factors = vec![
            scorer.age_score(meta.last_rotated, 90),
            scorer.verification_score(meta.last_verified),
            scorer.usage_score(self.anomaly.latest_z_score(key).await),
            // ... rotation and provider factors
        ];
        let mut score = scorer.compute(factors);
        score.key_name = key.clone();
        scores.push(score);
    }

    if worst_first.unwrap_or(false) {
        scores.sort_by(|a, b| a.overall_score.partial_cmp(&b.overall_score).unwrap());
    } else {
        scores.sort_by(|a, b| b.overall_score.partial_cmp(&a.overall_score).unwrap());
    }

    let output = scores.iter().map(|s| {
        let issue = s.top_issue.as_deref().unwrap_or("None");
        format!("{}: {:.0}/100 ({:?}) — Top issue: {}", s.key_name, s.overall_score, s.grade, issue)
    }).collect::<Vec<_>>().join("\n");

    Ok(CallToolResult::success(output))
}
```

### CLI Commands

```bash
# Health scores for all keys (best first)
pqvault health scores
# STRIPE_KEY: 92/100 (Excellent) — Top issue: None
# ANTHROPIC_KEY: 71/100 (Good) — Top issue: Key is 45 days old
# DATABASE_URL: 38/100 (Poor) — Top issue: Never verified
# OLD_KEY: 12/100 (Critical) — Top issue: Key is 340 days old

# Worst keys first
pqvault health scores --worst-first

# Single key detail
pqvault health score ANTHROPIC_KEY
# ANTHROPIC_KEY: 71/100 (Good)
#   Age:          55/100 (weight: 30%) — 45 days since last rotation
#   Verification: 90/100 (weight: 20%) — 12h since last check
#   Usage:        80/100 (weight: 20%) — Z-score: 0.45
#   Rotation:     65/100 (weight: 15%) — Due in 15 days
#   Provider:    100/100 (weight: 15%) — Healthy (200, 234ms)
```

### Web UI Changes

- Health score badge on each key in the key list (color-coded by grade)
- Radar chart showing all health factors for a selected key
- "Keys needing attention" widget on dashboard (score < 50)
- Health score trend over time (weekly computation history)

## Dependencies

- `pqvault-core` (existing) — Key metadata
- `chrono = "0.4"` (existing) — Date calculations
- Feature 032 (Anomaly Detection) — Z-score data for usage factor
- Feature 034 (Provider Health) — Provider health for provider factor

## Testing

### Unit Tests

```rust
#[test]
fn health_grade_boundaries() {
    assert_eq!(HealthGrade::from(95.0), HealthGrade::Excellent);
    assert_eq!(HealthGrade::from(75.0), HealthGrade::Good);
    assert_eq!(HealthGrade::from(55.0), HealthGrade::Fair);
    assert_eq!(HealthGrade::from(30.0), HealthGrade::Poor);
    assert_eq!(HealthGrade::from(10.0), HealthGrade::Critical);
}

#[test]
fn age_score_decreases_with_time() {
    let scorer = HealthScorer::default();
    let recent = scorer.age_score(Some(Utc::now()), 90);
    let old = scorer.age_score(Some(Utc::now() - chrono::Duration::days(80)), 90);
    assert!(recent.score > old.score);
}

#[test]
fn composite_score_respects_weights() {
    let scorer = HealthScorer::default();
    let factors = vec![
        HealthFactor { name: "A".into(), score: 100.0, weight: 0.5, reason: "".into(), recommendation: None },
        HealthFactor { name: "B".into(), score: 0.0, weight: 0.5, reason: "".into(), recommendation: None },
    ];
    let result = scorer.compute(factors);
    assert!((result.overall_score - 50.0).abs() < 0.1);
}

#[test]
fn top_issue_is_worst_factor() {
    let scorer = HealthScorer::default();
    let factors = vec![
        HealthFactor { name: "A".into(), score: 90.0, weight: 0.5, reason: "".into(), recommendation: None },
        HealthFactor { name: "B".into(), score: 20.0, weight: 0.5, reason: "".into(), recommendation: Some("Fix B".into()) },
    ];
    let result = scorer.compute(factors);
    assert_eq!(result.top_issue, Some("Fix B".to_string()));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn health_score_reflects_all_factors() {
    let mcp = test_health_mcp().await;
    mcp.vault.store_with_metadata("KEY1", "val", Metadata {
        last_rotated: Some(Utc::now()),
        last_verified: Some(Utc::now()),
        ..Default::default()
    }).await.unwrap();

    let result = mcp.key_health_score(Some("KEY1".into()), None).await.unwrap();
    assert!(result.contains("Excellent") || result.contains("Good"));
}
```

### Manual Verification

1. Create a key that was never rotated or verified
2. Check health score — should be Critical
3. Rotate the key, verify score improves
4. Run provider health check, verify score improves further
5. Compare dashboard display with CLI output

## Example Usage

```bash
# Agent daily check:
pqvault health scores --worst-first --limit 5
# Prioritize fixing the worst keys first

# Automated health report:
pqvault health scores --format json | jq '.[] | select(.overall_score < 50)'
# Returns only keys that need immediate attention
```
