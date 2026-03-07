# Feature 029: Natural Language Search

## Status: Planned
## Phase: 3 (v2.3)
## Priority: Low

## Problem

Searching for keys in the vault is limited to exact keyword matching on key names. Users must remember the precise naming convention (e.g., `ANTHROPIC_API_KEY` vs `CLAUDE_KEY` vs `anthropic-key`). This is especially painful when a vault grows to hundreds of keys across multiple projects and categories. Agents calling `vault_search` fail completely if they use natural language like "the Stripe production key" instead of the exact name.

## Solution

Implement fuzzy matching using Levenshtein distance and Jaro-Winkler similarity, combined with TF-IDF scoring over key names, descriptions, tags, and categories. A query like "stripe production" would match `PROD_STRIPE_SECRET_KEY` even without exact substring overlap. Results are ranked by composite relevance score combining string similarity, TF-IDF, and recency of use.

## Implementation

### Files to Create/Modify

- `crates/pqvault-mcp/src/search.rs` — Search engine with fuzzy matching and TF-IDF
- `crates/pqvault-mcp/src/lib.rs` — Add `vault_search_nl` tool
- `crates/pqvault-core/src/index.rs` — Inverted index over key metadata for TF-IDF
- `crates/pqvault-core/src/models.rs` — Ensure description and tags fields exist on key metadata

### Data Model Changes

```rust
use std::collections::HashMap;

/// Search index for natural language queries
pub struct SearchIndex {
    /// Inverted index: token -> list of (key_name, field, tf_idf_score)
    inverted: HashMap<String, Vec<IndexEntry>>,
    /// Document frequency per token
    doc_freq: HashMap<String, usize>,
    /// Total number of documents (keys)
    total_docs: usize,
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub key_name: String,
    pub field: IndexField,
    pub term_frequency: f64,
}

#[derive(Debug, Clone, Copy)]
pub enum IndexField {
    Name,        // weight: 3.0
    Description, // weight: 2.0
    Tags,        // weight: 2.5
    Category,    // weight: 1.5
    Provider,    // weight: 1.0
}

impl IndexField {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Name => 3.0,
            Self::Description => 2.0,
            Self::Tags => 2.5,
            Self::Category => 1.5,
            Self::Provider => 1.0,
        }
    }
}

/// Search result with relevance scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub key_name: String,
    pub score: f64,
    pub match_reasons: Vec<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Tokenizer for search queries and key metadata
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .replace('_', " ")
        .replace('-', " ")
        .replace('.', " ")
        .split_whitespace()
        .filter(|t| t.len() > 1)
        .map(String::from)
        .collect()
}

/// Calculate Jaro-Winkler similarity between two strings
fn jaro_winkler(a: &str, b: &str) -> f64 {
    strsim::jaro_winkler(a, b)
}

/// Composite search scoring
pub fn score_match(query_tokens: &[String], key: &KeyMetadata) -> SearchResult {
    let key_tokens = tokenize(&key.name);
    let desc_tokens = key.description.as_deref().map(tokenize).unwrap_or_default();
    let tag_tokens: Vec<String> = key.tags.iter().flat_map(|t| tokenize(t)).collect();

    let mut score = 0.0;
    let mut reasons = Vec::new();

    for qt in query_tokens {
        // Exact substring match in name (highest score)
        if key.name.to_lowercase().contains(&qt.to_lowercase()) {
            score += 5.0;
            reasons.push(format!("name contains '{qt}'"));
        }

        // Fuzzy match against name tokens
        for kt in &key_tokens {
            let sim = jaro_winkler(qt, kt);
            if sim > 0.85 {
                score += sim * IndexField::Name.weight();
                reasons.push(format!("name token '{kt}' ~ '{qt}' ({sim:.2})"));
            }
        }

        // Fuzzy match against description
        for dt in &desc_tokens {
            let sim = jaro_winkler(qt, dt);
            if sim > 0.80 {
                score += sim * IndexField::Description.weight();
                reasons.push(format!("description match '{dt}' ~ '{qt}'"));
            }
        }

        // Tag matching
        for tt in &tag_tokens {
            let sim = jaro_winkler(qt, tt);
            if sim > 0.85 {
                score += sim * IndexField::Tags.weight();
                reasons.push(format!("tag match '{tt}' ~ '{qt}'"));
            }
        }
    }

    // Recency boost: keys used in last 7 days get +1.0
    if let Some(last_used) = key.last_used {
        let days_ago = (Utc::now() - last_used).num_days();
        if days_ago < 7 {
            score += 1.0;
            reasons.push("recently used".to_string());
        }
    }

    SearchResult {
        key_name: key.name.clone(),
        score,
        match_reasons: reasons,
        category: key.category.clone(),
        tags: key.tags.clone(),
        last_used: key.last_used,
    }
}
```

### MCP Tools

```rust
/// Natural language search across vault keys
#[tool(name = "vault_search_nl")]
async fn vault_search_nl(
    &self,
    #[arg(description = "Natural language query, e.g. 'stripe production key'")] query: String,
    #[arg(description = "Maximum results to return")] limit: Option<usize>,
    #[arg(description = "Minimum score threshold (0.0-10.0)")] min_score: Option<f64>,
) -> Result<CallToolResult, McpError> {
    let limit = limit.unwrap_or(5);
    let min_score = min_score.unwrap_or(1.0);
    let query_tokens = tokenize(&query);

    let keys = self.vault.list_metadata().await?;
    let mut results: Vec<SearchResult> = keys
        .iter()
        .map(|k| score_match(&query_tokens, k))
        .filter(|r| r.score >= min_score)
        .collect();

    results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    results.truncate(limit);

    let output = results.iter().enumerate().map(|(i, r)| {
        format!(
            "{}. {} (score: {:.1})\n   Reasons: {}\n   Category: {}\n   Tags: [{}]",
            i + 1, r.key_name, r.score,
            r.match_reasons.join(", "),
            r.category.as_deref().unwrap_or("none"),
            r.tags.join(", "),
        )
    }).collect::<Vec<_>>().join("\n\n");

    Ok(CallToolResult::success(output))
}
```

### CLI Commands

```bash
# Natural language search
pqvault search "stripe production secret"
# Results:
#   1. PROD_STRIPE_SECRET_KEY (score: 8.3)
#   2. STRIPE_WEBHOOK_SECRET (score: 5.1)
#   3. STRIPE_TEST_KEY (score: 3.2)

# Search with minimum score
pqvault search "openai api" --min-score 3.0

# Search with limit
pqvault search "database" --limit 3

# Fuzzy search handles typos
pqvault search "antrhopic key"  # Still finds ANTHROPIC_API_KEY
```

### Web UI Changes

- Replace exact-match search bar with natural language search
- Show match reasons and scores in search results
- Highlight matched tokens in key names/descriptions
- "Did you mean?" suggestions for zero-result queries

## Dependencies

- `strsim = "0.11"` — String similarity algorithms (Jaro-Winkler, Levenshtein) (new dependency)
- `pqvault-core` (existing) — Key metadata access
- `unicode-segmentation = "1.11"` — Proper Unicode tokenization (optional)

## Testing

### Unit Tests

```rust
#[test]
fn tokenize_splits_correctly() {
    assert_eq!(tokenize("STRIPE_SECRET_KEY"), vec!["stripe", "secret", "key"]);
    assert_eq!(tokenize("my-api-key"), vec!["my", "api", "key"]);
    assert_eq!(tokenize("openai.v2.key"), vec!["openai", "v2", "key"]);
}

#[test]
fn exact_substring_scores_highest() {
    let key = KeyMetadata::new("STRIPE_SECRET_KEY");
    let result = score_match(&tokenize("stripe"), &key);
    assert!(result.score > 5.0);
}

#[test]
fn fuzzy_match_handles_typos() {
    let key = KeyMetadata::new("ANTHROPIC_API_KEY");
    let result = score_match(&tokenize("antrhopic"), &key);
    assert!(result.score > 2.0, "Fuzzy match should handle transposition");
}

#[test]
fn tag_matching_works() {
    let mut key = KeyMetadata::new("API_KEY_1");
    key.tags = vec!["production".to_string(), "stripe".to_string()];
    let result = score_match(&tokenize("production stripe"), &key);
    assert!(result.score > 4.0);
}

#[test]
fn no_match_returns_zero() {
    let key = KeyMetadata::new("DATABASE_URL");
    let result = score_match(&tokenize("stripe webhook"), &key);
    assert!(result.score < 1.0);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn search_nl_returns_ranked_results() {
    let mcp = test_mcp_with_keys(&[
        ("PROD_STRIPE_KEY", "Stripe production API key"),
        ("TEST_STRIPE_KEY", "Stripe test API key"),
        ("OPENAI_KEY", "OpenAI API key"),
    ]).await;

    let results = mcp.vault_search_nl("stripe production", Some(5), None).await.unwrap();
    // PROD_STRIPE_KEY should rank first
    assert!(results.contains("PROD_STRIPE_KEY"));
}
```

### Manual Verification

1. Add 10+ keys with varied names, descriptions, and tags
2. Search using natural language queries
3. Verify ranking makes intuitive sense
4. Test with typos and abbreviations
5. Benchmark search latency with 1000+ keys

## Example Usage

```bash
# Agent asks for a key by description:
# "I need the key for calling Claude API"
pqvault search "claude api key"
# → ANTHROPIC_API_KEY (score: 7.2)

# User looking for database credentials:
pqvault search "postgres production database"
# → PROD_DATABASE_URL (score: 8.1)
# → PROD_PG_PASSWORD (score: 5.3)

# Handling abbreviations:
pqvault search "aws prod"
# → AWS_PROD_ACCESS_KEY (score: 6.5)
# → AWS_PROD_SECRET_KEY (score: 6.5)
```
