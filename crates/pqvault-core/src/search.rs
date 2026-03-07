use crate::models::SecretEntry;
use std::collections::HashMap;

/// Tokenize a key name or search query into lowercase words
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

/// Search result with relevance scoring
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub key_name: String,
    pub score: f64,
    pub match_reasons: Vec<String>,
    pub category: String,
    pub projects: Vec<String>,
    pub lifecycle: String,
}

/// Score how well a secret entry matches a query
fn score_entry(query_tokens: &[String], name: &str, entry: &SecretEntry) -> SearchResult {
    let key_tokens = tokenize(name);
    let cat_tokens = tokenize(&entry.category);

    let mut score = 0.0;
    let mut reasons = Vec::new();

    for qt in query_tokens {
        // Exact substring match in name (highest score)
        if name.to_lowercase().contains(&qt.to_lowercase()) {
            score += 5.0;
            reasons.push(format!("name contains '{}'", qt));
        }

        // Exact category match
        if entry.category.to_lowercase() == *qt {
            score += 3.0;
            reasons.push(format!("category = '{}'", qt));
        }

        // Project match
        for proj in &entry.projects {
            if proj.to_lowercase().contains(&qt.to_lowercase()) {
                score += 3.0;
                reasons.push(format!("project '{}'", proj));
                break;
            }
        }

        // Tag match
        for tag in &entry.tags {
            if tag.to_lowercase().contains(&qt.to_lowercase()) {
                score += 2.5;
                reasons.push(format!("tag '{}'", tag));
                break;
            }
        }

        // Fuzzy match against name tokens
        for kt in &key_tokens {
            let sim = strsim::jaro_winkler(qt, kt);
            if sim > 0.85 && !name.to_lowercase().contains(&qt.to_lowercase()) {
                score += sim * 3.0;
                reasons.push(format!("'{}' ~ '{}' ({:.0}%)", kt, qt, sim * 100.0));
            }
        }

        // Fuzzy match against category tokens
        for ct in &cat_tokens {
            let sim = strsim::jaro_winkler(qt, ct);
            if sim > 0.85 && entry.category.to_lowercase() != *qt {
                score += sim * 1.5;
                reasons.push(format!("category '{}' ~ '{}'", ct, qt));
            }
        }
    }

    SearchResult {
        key_name: name.to_string(),
        score,
        match_reasons: reasons,
        category: entry.category.clone(),
        projects: entry.projects.clone(),
        lifecycle: entry.lifecycle.clone(),
    }
}

/// Search vault secrets using natural language query
/// Takes the secrets HashMap directly (key name -> entry)
pub fn search_secrets(
    secrets: &HashMap<String, SecretEntry>,
    query: &str,
    min_score: f64,
    limit: usize,
) -> Vec<SearchResult> {
    let query_tokens = tokenize(query);
    if query_tokens.is_empty() {
        return vec![];
    }

    let mut results: Vec<SearchResult> = secrets
        .iter()
        .map(|(name, entry)| score_entry(&query_tokens, name, entry))
        .filter(|r| r.score >= min_score)
        .collect();

    results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    results.truncate(limit);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secrets(entries: &[(&str, &str, &[&str])]) -> HashMap<String, SecretEntry> {
        let mut map = HashMap::new();
        for (name, category, projects) in entries {
            map.insert(
                name.to_string(),
                SecretEntry {
                    value: "encrypted".to_string(),
                    category: category.to_string(),
                    description: String::new(),
                    created: String::new(),
                    rotated: String::new(),
                    expires: None,
                    rotation_days: 90,
                    projects: projects.iter().map(|s| s.to_string()).collect(),
                    tags: vec![],
                    account: None,
                    environment: None,
                    related_keys: vec![],
                    last_verified: None,
                    last_error: None,
                    key_status: "active".to_string(),
                    lifecycle: "active".to_string(),
                    lifecycle_reason: None,
                    lifecycle_changed: None,
                    versions: vec![],
                    max_versions: 10,
                    rotation_policy: None,
                },
            );
        }
        map
    }

    #[test]
    fn test_tokenize() {
        assert_eq!(tokenize("STRIPE_SECRET_KEY"), vec!["stripe", "secret", "key"]);
        assert_eq!(tokenize("my-api-key"), vec!["my", "api", "key"]);
    }

    #[test]
    fn test_exact_match_scores_high() {
        let secrets = make_secrets(&[("STRIPE_SECRET_KEY", "payment", &[])]);
        let results = search_secrets(&secrets, "stripe", 0.0, 10);
        assert_eq!(results.len(), 1);
        assert!(results[0].score >= 5.0);
    }

    #[test]
    fn test_fuzzy_match() {
        let secrets = make_secrets(&[("ANTHROPIC_API_KEY", "ai", &[])]);
        let results = search_secrets(&secrets, "antrhopic", 0.0, 10);
        assert!(!results.is_empty());
        assert!(results[0].score > 1.0);
    }

    #[test]
    fn test_no_match() {
        let secrets = make_secrets(&[("DATABASE_URL", "database", &[])]);
        let results = search_secrets(&secrets, "stripe webhook", 1.0, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_category_match() {
        let secrets = make_secrets(&[
            ("KEY_A", "payment", &[]),
            ("KEY_B", "database", &[]),
        ]);
        let results = search_secrets(&secrets, "payment", 0.0, 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].key_name, "KEY_A");
    }

    #[test]
    fn test_project_match() {
        let secrets = make_secrets(&[
            ("KEY_A", "api", &["production"]),
            ("KEY_B", "api", &["staging"]),
        ]);
        let results = search_secrets(&secrets, "production", 0.0, 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].key_name, "KEY_A");
    }

    #[test]
    fn test_results_sorted_by_score() {
        let secrets = make_secrets(&[
            ("OPENAI_KEY", "ai", &[]),
            ("STRIPE_SECRET_KEY", "payment", &[]),
            ("STRIPE_WEBHOOK_KEY", "payment", &[]),
        ]);
        let results = search_secrets(&secrets, "stripe secret", 0.0, 10);
        // STRIPE_SECRET_KEY matches both "stripe" and "secret" = highest
        assert_eq!(results[0].key_name, "STRIPE_SECRET_KEY");
    }
}
