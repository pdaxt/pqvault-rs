# Feature 072: Breach Database Cross-Reference

## Status: Planned
## Phase: 8 (v2.8)
## Priority: High

## Problem

API keys and passwords can be compromised through third-party data breaches without
the key owner's knowledge. A developer's Stripe key might appear in a breach dump
months before Stripe detects it. Currently PQVault has no way to check if stored
secrets have appeared in known breaches, leaving users unknowingly exposed.

## Solution

Implement breach database cross-referencing that checks vault key values against known
breach datasets using k-anonymity (similar to HaveIBeenPwned's API approach). Values
are never sent in full — only a partial hash is transmitted, preserving privacy. The
system checks against HIBP's API for passwords and maintains a local bloom filter
of known compromised API key patterns for offline checking.

## Implementation

### Files to Create/Modify

```
pqvault-scan-mcp/
  src/
    breach/
      mod.rs             # Breach checking module root
      hibp.rs            # HaveIBeenPwned API client (k-anonymity)
      bloom.rs           # Local bloom filter for known compromised patterns
      checker.rs         # Orchestrator: checks all sources
      cache.rs           # Cache results to avoid repeated API calls
    tools/
      breach_check.rs    # MCP tool: check keys against breach DBs
```

### Data Model Changes

```rust
use std::collections::HashSet;

/// Result of checking a key against breach databases
pub struct BreachCheckResult {
    pub key_name: String,
    pub status: BreachStatus,
    pub sources_checked: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

pub enum BreachStatus {
    /// Key not found in any breach database
    Clean,
    /// Key found in breach database(s)
    Compromised {
        breach_count: usize,
        earliest_breach: Option<DateTime<Utc>>,
        sources: Vec<BreachSource>,
    },
    /// Could not check (API unavailable, etc.)
    Unknown(String),
}

pub struct BreachSource {
    pub name: String,           // "HaveIBeenPwned", "local-bloom"
    pub breach_date: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

/// K-anonymity client for HaveIBeenPwned
pub struct HibpClient {
    client: reqwest::Client,
    base_url: String,
    rate_limiter: RateLimiter,
}

impl HibpClient {
    /// Check a value using k-anonymity (only sends first 5 chars of SHA-1)
    pub async fn check_password(&self, value: &str) -> Result<BreachCheckResult> {
        let sha1 = sha1_hex(value);
        let prefix = &sha1[..5];
        let suffix = &sha1[5..];

        let url = format!("{}/range/{}", self.base_url, prefix);
        let response = self.client.get(&url)
            .header("Add-Padding", "true")
            .send()
            .await?;

        let body = response.text().await?;
        let found = body.lines().any(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            parts.first().map_or(false, |h| h.eq_ignore_ascii_case(suffix))
        });

        Ok(if found {
            BreachCheckResult {
                status: BreachStatus::Compromised {
                    breach_count: 1,
                    earliest_breach: None,
                    sources: vec![BreachSource {
                        name: "HaveIBeenPwned".into(),
                        breach_date: None,
                        description: Some("Password found in known breach database".into()),
                    }],
                },
                ..Default::default()
            }
        } else {
            BreachCheckResult {
                status: BreachStatus::Clean,
                ..Default::default()
            }
        })
    }
}

/// Local bloom filter for API key patterns
pub struct BreachBloomFilter {
    /// Bloom filter bits
    filter: Vec<u8>,
    /// Number of hash functions
    k: usize,
    /// Filter size in bits
    m: usize,
}

impl BreachBloomFilter {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Ok(Self::from_bytes(&data))
    }

    pub fn might_contain(&self, value: &str) -> bool {
        let hashes = compute_k_hashes(value, self.k, self.m);
        hashes.iter().all(|&idx| {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            self.filter[byte_idx] & (1 << bit_idx) != 0
        })
    }
}
```

### MCP Tools

```rust
#[tool(description = "Check vault secrets against known breach databases")]
async fn breach_check(
    /// Specific keys to check (comma-separated), or 'all' for entire vault
    #[arg(default = "all")]
    keys: String,
    /// Include HIBP API check (requires internet)
    #[arg(default = true)]
    include_hibp: bool,
    /// Include local bloom filter check
    #[arg(default = true)]
    include_local: bool,
) -> Result<CallToolResult> {
    let vault = load_vault().await?;
    let keys_to_check = if keys == "all" {
        vault.list_keys().await?
    } else {
        keys.split(',').map(|k| k.trim().to_string()).collect()
    };

    let checker = BreachChecker::new(include_hibp, include_local).await?;
    let mut results = Vec::new();

    for key in &keys_to_check {
        let value = vault.get(key).await?;
        let result = checker.check(key, &value.value).await?;
        results.push(result);
    }

    Ok(format_breach_results(&results))
}
```

### CLI Commands

```bash
# Check all vault keys against breach databases
pqvault scan breach

# Check specific keys
pqvault scan breach --keys DATABASE_URL,API_KEY

# Offline only (no API calls)
pqvault scan breach --offline

# Auto-rotate compromised keys
pqvault scan breach --auto-rotate

# Update local bloom filter database
pqvault scan breach --update-db

# JSON output for CI/CD integration
pqvault scan breach --format json --exit-code
```

### Web UI Changes

None directly. Results feed into health dashboard.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sha1` | 0.10 | SHA-1 hashing for HIBP k-anonymity API |
| `reqwest` | 0.12 | HTTP client (already in workspace) |

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_prefix_extraction() {
        let value = "password123";
        let sha1 = sha1_hex(value);
        let prefix = &sha1[..5];
        let suffix = &sha1[5..];
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn test_hibp_response_parsing() {
        let response = "0018A45C4D1DEF81644B54AB7F969B88D65:3\n\
                         00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n\
                         011053FD0102E94D6AE2F8B83D76FAF94F6:1";
        let suffix = "0018A45C4D1DEF81644B54AB7F969B88D65";
        let found = response.lines().any(|line| {
            line.split(':').next().map_or(false, |h| h.eq_ignore_ascii_case(suffix))
        });
        assert!(found);
    }

    #[test]
    fn test_bloom_filter_insert_and_check() {
        let mut bloom = BreachBloomFilter::new(1000, 3);
        bloom.insert("compromised_key_123");
        assert!(bloom.might_contain("compromised_key_123"));
        assert!(!bloom.might_contain("safe_key_456")); // Probabilistic, but likely
    }

    #[test]
    fn test_breach_status_display() {
        let result = BreachCheckResult {
            key_name: "API_KEY".into(),
            status: BreachStatus::Compromised {
                breach_count: 2,
                earliest_breach: Some(parse_dt("2024-01-15T00:00:00Z")),
                sources: vec![],
            },
            sources_checked: vec!["HIBP".into()],
            checked_at: Utc::now(),
        };
        assert!(result.is_compromised());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, Duration::from_secs(1));
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire()); // Should be rate limited
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_breach_check_known_password() {
    // "password" is known to be in HIBP
    let client = HibpClient::new();
    let result = client.check_password("password").await.unwrap();
    assert!(matches!(result.status, BreachStatus::Compromised { .. }));
}

#[tokio::test]
async fn test_breach_check_strong_random() {
    let client = HibpClient::new();
    let random_val = generate_random_string(64);
    let result = client.check_password(&random_val).await.unwrap();
    assert!(matches!(result.status, BreachStatus::Clean));
}
```

## Example Usage

```
$ pqvault scan breach

  Breach Database Cross-Reference
  ════════════════════════════════════════════════

  Checking 24 keys against breach databases...
  Sources: HaveIBeenPwned (API), Local Bloom Filter

  Key                      HIBP    Local    Status
  ───────────────────────  ──────  ───────  ──────────
  STRIPE_SECRET_KEY        clean   clean    SAFE
  DATABASE_URL             clean   clean    SAFE
  AWS_ACCESS_KEY_ID        clean   clean    SAFE
  OLD_API_PASSWORD         FOUND   clean    COMPROMISED
  LEGACY_WEBHOOK_SECRET    clean   FOUND    COMPROMISED
  ...20 more keys...       clean   clean    SAFE

  ════════════════════════════════════════════════
  Results: 22 safe, 2 compromised, 0 unknown

  COMPROMISED KEYS:
    OLD_API_PASSWORD         — Found in HIBP (seen in 47 breaches)
    LEGACY_WEBHOOK_SECRET    — Matches known compromised pattern

  Recommended: Rotate compromised keys immediately.
  Run `pqvault scan breach --auto-rotate` to auto-rotate.
```
