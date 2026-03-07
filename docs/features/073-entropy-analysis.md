# Feature 073: Entropy Analysis

## Status: Planned
## Phase: 8 (v2.8)
## Priority: High

## Problem

Not all secrets are created equal. Some developers use weak values like `password123`,
test keys in production (`sk_test_` instead of `sk_live_`), or copy-paste placeholder
values that never get updated. PQVault currently stores any value without evaluating
its strength, leaving users unaware that their "secrets" provide little actual security.

## Solution

Implement entropy analysis that evaluates the cryptographic strength of every stored
secret. It calculates Shannon entropy, checks for common patterns (sequential chars,
dictionary words, test/placeholder values), detects environment mismatches (test keys
in production), and flags keys below configurable thresholds. Results integrate into
the health dashboard as security scores.

## Implementation

### Files to Create/Modify

```
pqvault-health-mcp/
  src/
    entropy/
      mod.rs           # Entropy analysis module root
      shannon.rs       # Shannon entropy calculator
      patterns.rs      # Pattern detection (sequential, repeated, dictionary)
      environment.rs   # Environment mismatch detection (test vs prod)
      scorer.rs        # Overall strength scoring
    tools/
      entropy_check.rs # MCP tool: analyze key entropy
```

### Data Model Changes

```rust
/// Complete entropy analysis result for a single key
pub struct EntropyReport {
    pub key_name: String,
    pub value_length: usize,
    pub shannon_entropy: f64,        // Bits per character
    pub total_entropy_bits: f64,     // shannon * length
    pub strength: StrengthRating,
    pub issues: Vec<EntropyIssue>,
    pub score: u32,                  // 0-100 overall score
}

pub enum StrengthRating {
    Excellent,  // 80+ bits effective entropy
    Good,       // 60-79 bits
    Fair,       // 40-59 bits
    Weak,       // 20-39 bits
    Critical,   // <20 bits
}

pub enum EntropyIssue {
    /// Value has low Shannon entropy
    LowEntropy { bits: f64, threshold: f64 },
    /// Contains sequential characters (abc, 123)
    SequentialChars { sequence: String },
    /// Contains repeated patterns
    RepeatedPattern { pattern: String, count: usize },
    /// Contains dictionary words
    DictionaryWord { word: String },
    /// Test/placeholder value in production context
    TestKeyInProduction { indicator: String },
    /// Common weak value
    CommonValue { category: String },
    /// Too short for its purpose
    TooShort { length: usize, recommended: usize },
    /// Looks like a default/example value
    DefaultValue,
    /// All same character class (all lowercase, all digits)
    LimitedCharacterSet { classes_used: usize, classes_available: usize },
}

/// Shannon entropy calculator
pub fn shannon_entropy(value: &str) -> f64 {
    let len = value.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in value.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Pattern detector
pub struct PatternDetector {
    /// Common weak passwords/values
    common_values: HashSet<String>,
    /// Dictionary words (top 10k English words)
    dictionary: HashSet<String>,
    /// Test key indicators by provider
    test_indicators: HashMap<String, Vec<String>>,
}

impl PatternDetector {
    pub fn detect_issues(&self, key_name: &str, value: &str) -> Vec<EntropyIssue> {
        let mut issues = Vec::new();

        // Check Shannon entropy
        let entropy = shannon_entropy(value);
        if entropy < 3.0 {
            issues.push(EntropyIssue::LowEntropy {
                bits: entropy,
                threshold: 3.0,
            });
        }

        // Check for sequential characters
        if let Some(seq) = detect_sequential(value) {
            issues.push(EntropyIssue::SequentialChars { sequence: seq });
        }

        // Check for repeated patterns
        if let Some((pattern, count)) = detect_repeated(value) {
            issues.push(EntropyIssue::RepeatedPattern { pattern, count });
        }

        // Check for test keys in production
        if key_name.contains("PROD") || key_name.contains("LIVE") {
            for (provider, indicators) in &self.test_indicators {
                for indicator in indicators {
                    if value.contains(indicator) {
                        issues.push(EntropyIssue::TestKeyInProduction {
                            indicator: indicator.clone(),
                        });
                    }
                }
            }
        }

        // Check character set diversity
        let classes = count_char_classes(value);
        if classes < 2 {
            issues.push(EntropyIssue::LimitedCharacterSet {
                classes_used: classes,
                classes_available: 4, // lower, upper, digit, special
            });
        }

        issues
    }
}

fn detect_sequential(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    for window in chars.windows(4) {
        let diffs: Vec<i32> = window.windows(2)
            .map(|w| w[1] as i32 - w[0] as i32)
            .collect();
        if diffs.iter().all(|&d| d == 1) || diffs.iter().all(|&d| d == -1) {
            return Some(window.iter().collect());
        }
    }
    None
}

fn count_char_classes(value: &str) -> usize {
    let mut classes = 0;
    if value.chars().any(|c| c.is_ascii_lowercase()) { classes += 1; }
    if value.chars().any(|c| c.is_ascii_uppercase()) { classes += 1; }
    if value.chars().any(|c| c.is_ascii_digit()) { classes += 1; }
    if value.chars().any(|c| !c.is_ascii_alphanumeric()) { classes += 1; }
    classes
}
```

### MCP Tools

```rust
#[tool(description = "Analyze entropy and strength of vault secrets")]
async fn entropy_check(
    /// Specific keys to analyze (comma-separated), or 'all'
    #[arg(default = "all")]
    keys: String,
    /// Minimum score threshold to pass (0-100)
    #[arg(default = 50)]
    threshold: u32,
    /// Include detailed issue breakdown
    #[arg(default = true)]
    detailed: bool,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Analyze all keys
pqvault health entropy

# Analyze specific keys
pqvault health entropy --keys API_KEY,DATABASE_URL

# Set minimum threshold
pqvault health entropy --threshold 70

# CI mode: exit 1 if any key below threshold
pqvault health entropy --threshold 60 --exit-code

# JSON output
pqvault health entropy --format json
```

### Web UI Changes

None. Results feed into health dashboard scores.

## Dependencies

No new crate dependencies. Uses standard library math for entropy calculation.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All unique characters: high entropy
        let entropy = shannon_entropy("abcdefghijklmnop");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_shannon_entropy_single_char() {
        let entropy = shannon_entropy("aaaaaaaaaa");
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_shannon_entropy_binary() {
        let entropy = shannon_entropy("ababababab");
        assert!((entropy - 1.0).abs() < 0.01); // ~1 bit per char
    }

    #[test]
    fn test_detect_sequential_ascending() {
        assert!(detect_sequential("abc1234xyz").is_some());
    }

    #[test]
    fn test_detect_sequential_none() {
        assert!(detect_sequential("sk_live_51NqOz7").is_none());
    }

    #[test]
    fn test_test_key_detection() {
        let detector = PatternDetector::default();
        let issues = detector.detect_issues("PROD_STRIPE_KEY", "sk_test_51NqOz7abc");
        assert!(issues.iter().any(|i| matches!(i, EntropyIssue::TestKeyInProduction { .. })));
    }

    #[test]
    fn test_strong_key_no_issues() {
        let detector = PatternDetector::default();
        let strong_key = "sk_live_51NqOz7aBcDeFgHiJkLmNoPqRsTuVwXyZ";
        let issues = detector.detect_issues("STRIPE_KEY", strong_key);
        assert!(issues.is_empty() || issues.iter().all(|i| !matches!(i,
            EntropyIssue::LowEntropy { .. } | EntropyIssue::TestKeyInProduction { .. }
        )));
    }

    #[test]
    fn test_char_class_count() {
        assert_eq!(count_char_classes("abcdef"), 1);
        assert_eq!(count_char_classes("aBcDeF"), 2);
        assert_eq!(count_char_classes("aBc123"), 3);
        assert_eq!(count_char_classes("aBc1!@"), 4);
    }

    #[test]
    fn test_strength_rating() {
        assert!(matches!(StrengthRating::from_bits(128.0), StrengthRating::Excellent));
        assert!(matches!(StrengthRating::from_bits(45.0), StrengthRating::Fair));
        assert!(matches!(StrengthRating::from_bits(10.0), StrengthRating::Critical));
    }
}
```

## Example Usage

```
$ pqvault health entropy

  Entropy Analysis (24 keys)
  ══════════════════════════════════════════════════════

  Key                      Entropy  Bits   Score  Rating     Issues
  ───────────────────────  ───────  ─────  ─────  ─────────  ──────
  STRIPE_SECRET_KEY        4.8/ch   168    95     Excellent  -
  AWS_SECRET_ACCESS_KEY    5.1/ch   204    98     Excellent  -
  DATABASE_URL             3.9/ch   195    85     Excellent  -
  JWT_SECRET               4.5/ch   144    90     Excellent  -
  LEGACY_API_KEY           2.1/ch   21     22     Weak       low entropy, limited chars
  TEST_WEBHOOK             1.8/ch   18     15     Critical   test key in prod context
  OLD_PASSWORD             1.5/ch   12     8      Critical   dictionary word, sequential

  ══════════════════════════════════════════════════════
  Summary: 21 excellent, 1 weak, 2 critical
  Action required: Rotate 3 keys with score < 50
```
