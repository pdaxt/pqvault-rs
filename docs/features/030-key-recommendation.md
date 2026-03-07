# Feature 030: Key Recommendation

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Low

## Problem

Agents must request keys by exact name or not at all. When an agent is tasked with "deploy the app to production," it has no way to know which keys are needed — `PROD_DATABASE_URL`, `PROD_REDIS_URL`, `AWS_PROD_ACCESS_KEY`, etc. The human must manually list every key the agent needs, which defeats the purpose of automation and creates friction for multi-key workflows.

## Solution

Agents describe their task in natural language, and the vault suggests which keys they likely need based on project context, key categories, tags, and historical co-access patterns. For example, "deploy to AWS" would suggest AWS credentials, database URLs, and any keys tagged with `deploy` or `production`. The recommendation engine combines tag-based matching, category lookup, and co-occurrence analysis from audit logs.

## Implementation

### Files to Create/Modify

- `crates/pqvault-agent-mcp/src/recommend.rs` — Recommendation engine with multiple strategies
- `crates/pqvault-agent-mcp/src/lib.rs` — Register `vault_recommend` tool
- `crates/pqvault-core/src/cooccurrence.rs` — Co-occurrence matrix from audit log
- `crates/pqvault-core/src/models.rs` — Add `project` field to key metadata

### Data Model Changes

```rust
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Task-to-key recommendation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub key_name: String,
    pub confidence: f64,   // 0.0 - 1.0
    pub reason: String,
    pub strategy: RecommendStrategy,
}

/// Which strategy produced the recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendStrategy {
    TagMatch,        // Key's tags match task keywords
    CategoryMatch,   // Key's category matches task domain
    ProjectMatch,    // Key belongs to the same project
    CoOccurrence,    // Key is frequently used alongside other matched keys
    HistoricalTask,  // Similar task descriptions used these keys before
}

/// Co-occurrence matrix: tracks which keys are used together
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoOccurrenceMatrix {
    /// (key_a, key_b) -> count of times used in same session
    pub pairs: HashMap<(String, String), u32>,
    /// Total sessions per key
    pub key_sessions: HashMap<String, u32>,
}

impl CoOccurrenceMatrix {
    /// Probability that key_b is needed given key_a is needed
    pub fn conditional_probability(&self, key_a: &str, key_b: &str) -> f64 {
        let pair_key = if key_a < key_b {
            (key_a.to_string(), key_b.to_string())
        } else {
            (key_b.to_string(), key_a.to_string())
        };
        let co_count = *self.pairs.get(&pair_key).unwrap_or(&0) as f64;
        let a_count = *self.key_sessions.get(key_a).unwrap_or(&1) as f64;
        co_count / a_count
    }
}

/// Task keyword to category mapping
pub fn task_category_map() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("deploy", vec!["cloud", "infrastructure", "database"]);
    m.insert("test", vec!["testing", "ci-cd"]);
    m.insert("api", vec!["api-keys", "external-services"]);
    m.insert("email", vec!["email", "notifications"]);
    m.insert("payment", vec!["payment", "billing"]);
    m.insert("database", vec!["database", "storage"]);
    m.insert("auth", vec!["authentication", "oauth"]);
    m
}
```

### MCP Tools

```rust
/// Recommend keys for a task description
#[tool(name = "vault_recommend")]
async fn vault_recommend(
    &self,
    #[arg(description = "Task description, e.g. 'deploy to production on AWS'")] task: String,
    #[arg(description = "Project name to scope recommendations")] project: Option<String>,
    #[arg(description = "Maximum recommendations")] limit: Option<usize>,
    #[arg(description = "Minimum confidence threshold (0.0-1.0)")] min_confidence: Option<f64>,
) -> Result<CallToolResult, McpError> {
    let limit = limit.unwrap_or(10);
    let min_confidence = min_confidence.unwrap_or(0.3);

    let mut recommendations = Vec::new();

    // Strategy 1: Tag matching
    let task_tokens = tokenize(&task);
    for key in self.vault.list_metadata().await? {
        let tag_score = key.tags.iter()
            .filter(|t| task_tokens.iter().any(|tt| strsim::jaro_winkler(tt, &t.to_lowercase()) > 0.85))
            .count() as f64 / task_tokens.len().max(1) as f64;
        if tag_score > 0.0 {
            recommendations.push(Recommendation {
                key_name: key.name.clone(),
                confidence: tag_score.min(1.0),
                reason: format!("Tags match task keywords"),
                strategy: RecommendStrategy::TagMatch,
            });
        }
    }

    // Strategy 2: Category matching
    let category_map = task_category_map();
    let matched_categories: Vec<&str> = task_tokens.iter()
        .filter_map(|t| category_map.get(t.as_str()))
        .flatten()
        .copied()
        .collect();

    for key in self.vault.list_metadata().await? {
        if let Some(ref cat) = key.category {
            if matched_categories.contains(&cat.as_str()) {
                recommendations.push(Recommendation {
                    key_name: key.name.clone(),
                    confidence: 0.6,
                    reason: format!("Category '{cat}' matches task domain"),
                    strategy: RecommendStrategy::CategoryMatch,
                });
            }
        }
    }

    // Strategy 3: Project scoping
    if let Some(ref proj) = project {
        for key in self.vault.list_metadata().await? {
            if key.project.as_deref() == Some(proj) {
                recommendations.push(Recommendation {
                    key_name: key.name.clone(),
                    confidence: 0.5,
                    reason: format!("Belongs to project '{proj}'"),
                    strategy: RecommendStrategy::ProjectMatch,
                });
            }
        }
    }

    // Deduplicate and merge scores
    let mut merged = merge_recommendations(recommendations);
    merged.retain(|r| r.confidence >= min_confidence);
    merged.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    merged.truncate(limit);

    let output = format_recommendations(&merged);
    Ok(CallToolResult::success(output))
}

/// Record that keys were used together (builds co-occurrence data)
#[tool(name = "vault_record_cooccurrence")]
async fn vault_record_cooccurrence(
    &self,
    #[arg(description = "Keys used together in this session")] keys: Vec<String>,
    #[arg(description = "Session/task identifier")] session_id: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Get key recommendations for a task
pqvault recommend "deploy the app to production on AWS"
# Recommendations:
#   1. AWS_PROD_ACCESS_KEY (confidence: 0.92) — Tags match + project match
#   2. AWS_PROD_SECRET_KEY (confidence: 0.92) — Co-occurrence with ACCESS_KEY
#   3. PROD_DATABASE_URL (confidence: 0.78) — Category 'database' + tag 'production'
#   4. PROD_REDIS_URL (confidence: 0.65) — Co-occurrence with DATABASE_URL

# Scope to a project
pqvault recommend "run tests" --project dataxlr8

# Set minimum confidence
pqvault recommend "send emails" --min-confidence 0.5

# Build co-occurrence data from audit history
pqvault recommend build-index
```

### Web UI Changes

- "What keys do I need?" search box on dashboard
- Recommendation cards with confidence bars and explanations
- One-click "Grant access to all recommended keys" for agents
- Co-occurrence graph visualization

## Dependencies

- `strsim = "0.11"` — String similarity for tag matching (shared with Feature 029)
- `pqvault-core` — Key metadata and audit log access
- `pqvault-audit-mcp` — Historical usage data for co-occurrence
- Feature 029 (Natural Language Search) — Shares tokenization and similarity logic

## Testing

### Unit Tests

```rust
#[test]
fn co_occurrence_probability() {
    let mut matrix = CoOccurrenceMatrix::default();
    matrix.pairs.insert(("AWS_ACCESS".into(), "AWS_SECRET".into()), 10);
    matrix.key_sessions.insert("AWS_ACCESS".into(), 12);
    let prob = matrix.conditional_probability("AWS_ACCESS", "AWS_SECRET");
    assert!((prob - 0.833).abs() < 0.01);
}

#[test]
fn task_category_mapping() {
    let map = task_category_map();
    assert!(map["deploy"].contains(&"infrastructure"));
    assert!(map["payment"].contains(&"billing"));
}

#[test]
fn merge_deduplicates_and_combines_scores() {
    let recs = vec![
        Recommendation { key_name: "KEY1".into(), confidence: 0.5, ..default() },
        Recommendation { key_name: "KEY1".into(), confidence: 0.3, ..default() },
    ];
    let merged = merge_recommendations(recs);
    assert_eq!(merged.len(), 1);
    assert!(merged[0].confidence > 0.5); // Combined score
}
```

### Integration Tests

```rust
#[tokio::test]
async fn recommend_deploy_keys() {
    let mcp = test_mcp_with_keys(&[
        ("AWS_PROD_ACCESS_KEY", "AWS access key", &["production", "aws", "deploy"]),
        ("TEST_KEY", "Test key", &["testing"]),
    ]).await;

    let results = mcp.vault_recommend("deploy to production", None, None, None).await.unwrap();
    assert!(results.contains("AWS_PROD_ACCESS_KEY"));
    assert!(!results.contains("TEST_KEY"));
}
```

### Manual Verification

1. Populate vault with 20+ categorized and tagged keys
2. Run recommendation with various task descriptions
3. Verify recommendations match human intuition
4. Run multiple sessions, then check co-occurrence improves results
5. Benchmark recommendation latency with 500+ keys

## Example Usage

```bash
# Agent workflow:
# 1. Agent gets task: "Deploy dataxlr8 to Google Cloud"
# 2. Agent asks vault what it needs:
pqvault recommend "deploy dataxlr8 to Google Cloud"
# → GCP_SERVICE_ACCOUNT_KEY (0.95)
# → PROD_DATABASE_URL (0.82)
# → PROD_REDIS_URL (0.71)
# → CLOUDFLARE_API_TOKEN (0.58)

# 3. Agent requests access to recommended keys
# 4. Agent proceeds with deployment using vault_proxy

# Over time, co-occurrence data improves:
# If GCP_KEY and DATABASE_URL are always used together in deploy tasks,
# future recommendations for "deploy" automatically include both.
```
