# Feature 064: Fuzzy Search

## Status: Done
## Phase: 7 (v2.7)
## Priority: Medium

## Problem

Users must type exact key names to retrieve secrets. When managing hundreds of keys,
remembering exact names like `STRIPE_RESTRICTED_KEY_LIVE_V2` is impractical. A typo
or partial recall means falling back to `pqvault list | grep`, which exposes all keys
in terminal history and is slow for large vaults.

## Solution

Add fuzzy matching to `pqvault get` so that `pqvault get str` matches
`STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, etc. Uses the `nucleo` crate (the same
fuzzy matcher powering Helix editor) for fast, high-quality matching. When multiple
matches exist, the user is prompted to select from a ranked list. Single matches
resolve immediately.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    search/
      mod.rs           # Fuzzy search module root
      matcher.rs       # Nucleo-based fuzzy matcher
      scorer.rs        # Custom scoring: recency, frequency, exact prefix boost
      selector.rs      # Interactive selection when multiple matches
    commands/
      get.rs           # Modify existing `get` to try fuzzy on exact miss
```

### Data Model Changes

```rust
use nucleo_matcher::{Matcher, Config};
use nucleo_matcher::pattern::{Pattern, CaseMatching, Normalization};

pub struct FuzzyMatcher {
    matcher: Matcher,
    config: FuzzyConfig,
}

pub struct FuzzyConfig {
    /// Minimum score threshold (0-1000)
    pub min_score: u32,
    /// Maximum number of results to show
    pub max_results: usize,
    /// Boost score for recently accessed keys
    pub recency_boost: bool,
    /// Boost score for frequently accessed keys
    pub frequency_boost: bool,
}

impl Default for FuzzyConfig {
    fn default() -> Self {
        Self {
            min_score: 50,
            max_results: 10,
            recency_boost: true,
            frequency_boost: true,
        }
    }
}

pub struct FuzzyMatch {
    pub key_name: String,
    pub score: u32,
    pub matched_indices: Vec<usize>,  // character positions that matched
    pub category: Option<String>,
    pub provider: Option<String>,
}

impl FuzzyMatcher {
    pub fn new(config: FuzzyConfig) -> Self {
        Self {
            matcher: Matcher::new(Config::DEFAULT),
            config,
        }
    }

    pub fn search(&mut self, query: &str, keys: &[KeyEntry]) -> Vec<FuzzyMatch> {
        let pattern = Pattern::parse(
            query,
            CaseMatching::Ignore,
            Normalization::Smart,
        );

        let mut results: Vec<FuzzyMatch> = keys
            .iter()
            .filter_map(|key| {
                let mut buf = Vec::new();
                let haystack = nucleo_matcher::Utf32Str::new(&key.name, &mut buf);
                pattern.score(haystack, &mut self.matcher).map(|score| {
                    let mut indices = Vec::new();
                    pattern.indices(haystack, &mut self.matcher, &mut indices);
                    FuzzyMatch {
                        key_name: key.name.clone(),
                        score,
                        matched_indices: indices.iter().map(|&i| i as usize).collect(),
                        category: key.category.clone(),
                        provider: key.provider.clone(),
                    }
                })
            })
            .filter(|m| m.score >= self.config.min_score)
            .collect();

        results.sort_by(|a, b| b.score.cmp(&a.score));
        results.truncate(self.config.max_results);
        results
    }
}
```

### MCP Tools

No new MCP tools. Fuzzy search is a CLI-only UX enhancement.

### CLI Commands

```bash
# Fuzzy match — single result auto-resolves
pqvault get str
# → Matched: STRIPE_SECRET_KEY
# → sk_live_51N...

# Fuzzy match — multiple results prompt selection
pqvault get aws
# → Multiple matches:
# →   1. AWS_ACCESS_KEY_ID     (score: 850)
# →   2. AWS_SECRET_ACCESS_KEY (score: 820)
# →   3. AWS_REGION            (score: 780)
# → Select [1-3]:

# Disable fuzzy, require exact match
pqvault get STRIPE_SECRET_KEY --exact

# Show matches without resolving (for scripting)
pqvault search str --json
```

Modified `get` command:

```rust
#[derive(Args)]
pub struct GetArgs {
    /// Key name or fuzzy search query
    pub key: String,

    /// Require exact match (disable fuzzy)
    #[arg(long, default_value_t = false)]
    exact: bool,

    /// Minimum fuzzy match score (0-1000)
    #[arg(long, default_value_t = 50)]
    min_score: u32,

    /// Auto-select first match without prompting
    #[arg(long, default_value_t = false)]
    first: bool,
}

pub async fn handle_get(args: GetArgs, vault: &Vault) -> Result<()> {
    // Try exact match first
    if let Ok(value) = vault.get(&args.key).await {
        print_secret(&args.key, &value);
        return Ok(());
    }

    if args.exact {
        return Err(anyhow!("Key '{}' not found", args.key));
    }

    // Fall back to fuzzy search
    let keys = vault.list_keys().await?;
    let mut matcher = FuzzyMatcher::new(FuzzyConfig {
        min_score: args.min_score,
        ..Default::default()
    });

    let matches = matcher.search(&args.key, &keys);

    match matches.len() {
        0 => Err(anyhow!("No keys matching '{}' (try lowering --min-score)", args.key)),
        1 | _ if args.first => {
            let key = &matches[0].key_name;
            let value = vault.get(key).await?;
            print_secret(key, &value);
            Ok(())
        }
        _ => {
            let selected = prompt_selection(&matches)?;
            let value = vault.get(&selected.key_name).await?;
            print_secret(&selected.key_name, &value);
            Ok(())
        }
    }
}
```

### Web UI Changes

None. The web dashboard (Feature 082+) will have its own search implementation.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `nucleo-matcher` | 0.3 | High-performance fuzzy matching (from Helix editor) |

Add to `pqvault-cli/Cargo.toml`:

```toml
[dependencies]
nucleo-matcher = "0.3"
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_exact_substring() {
        let mut m = FuzzyMatcher::new(FuzzyConfig::default());
        let keys = test_keys(&["STRIPE_SECRET_KEY", "AWS_KEY", "DB_URL"]);
        let results = m.search("stripe", &keys);
        assert_eq!(results[0].key_name, "STRIPE_SECRET_KEY");
    }

    #[test]
    fn test_fuzzy_abbreviation() {
        let mut m = FuzzyMatcher::new(FuzzyConfig::default());
        let keys = test_keys(&["STRIPE_SECRET_KEY", "SENTRY_DSN", "S3_BUCKET"]);
        let results = m.search("ssk", &keys);
        assert_eq!(results[0].key_name, "STRIPE_SECRET_KEY");
    }

    #[test]
    fn test_fuzzy_no_match() {
        let mut m = FuzzyMatcher::new(FuzzyConfig::default());
        let keys = test_keys(&["API_KEY", "DB_URL"]);
        let results = m.search("zzzzz", &keys);
        assert!(results.is_empty());
    }

    #[test]
    fn test_fuzzy_case_insensitive() {
        let mut m = FuzzyMatcher::new(FuzzyConfig::default());
        let keys = test_keys(&["DATABASE_URL"]);
        let results = m.search("database", &keys);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_fuzzy_score_ordering() {
        let mut m = FuzzyMatcher::new(FuzzyConfig::default());
        let keys = test_keys(&["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "CLOUDFLARE_API_KEY"]);
        let results = m.search("aws", &keys);
        // Both AWS keys should score higher than CLOUDFLARE
        assert!(results[0].key_name.starts_with("AWS"));
        assert!(results[1].key_name.starts_with("AWS"));
    }

    #[test]
    fn test_min_score_filter() {
        let mut m = FuzzyMatcher::new(FuzzyConfig { min_score: 500, ..Default::default() });
        let keys = test_keys(&["STRIPE_SECRET_KEY", "SENTRY_DSN"]);
        let results = m.search("x", &keys);
        assert!(results.is_empty()); // Low-quality matches filtered out
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_get_with_fuzzy_fallback() {
    let vault = test_vault_with_keys(&[
        ("STRIPE_SECRET_KEY", "sk_live_123"),
        ("STRIPE_PUBLISHABLE_KEY", "pk_live_456"),
    ]).await;

    // Exact match works
    let val = get_key(&vault, "STRIPE_SECRET_KEY", false).await.unwrap();
    assert_eq!(val, "sk_live_123");

    // Fuzzy match with auto-first
    let val = get_key_fuzzy_first(&vault, "str sec", false).await.unwrap();
    assert_eq!(val, "sk_live_123");
}
```

## Example Usage

```
$ pqvault get str
  Fuzzy match: STRIPE_SECRET_KEY (score: 920)
  sk_live_51N████████████████████

$ pqvault get aws
  Multiple matches for "aws":
    1. AWS_ACCESS_KEY_ID        score: 880  [cloud]
    2. AWS_SECRET_ACCESS_KEY    score: 850  [cloud]
    3. AWS_SESSION_TOKEN        score: 720  [cloud]
    4. AWS_REGION               score: 680  [cloud]
  Select [1-4]: 2
  AKIA████████████████████████████

$ pqvault get dburl
  Fuzzy match: DATABASE_URL (score: 760)
  postgres://user:████@db.example.com:5432/myapp

$ pqvault search api --json
  [
    {"key": "API_KEY", "score": 950, "category": "general"},
    {"key": "OPENAI_API_KEY", "score": 820, "category": "ai"},
    {"key": "GITHUB_API_TOKEN", "score": 780, "category": "vcs"}
  ]
```
