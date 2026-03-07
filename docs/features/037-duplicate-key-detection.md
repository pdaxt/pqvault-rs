# Feature 037: Duplicate Key Detection

## Status: Done
## Phase: 4 (v2.4)
## Priority: Medium

## Problem

The same secret value can be stored under multiple different key names without any warning. For example, `STRIPE_KEY`, `STRIPE_SECRET`, and `PAYMENT_API_KEY` might all contain the identical Stripe secret. This wastes vault space, makes rotation error-prone (rotate one, forget the others), and creates confusion about which key name is the canonical one.

## Solution

Compute a SHA-256 hash of each key's decrypted value and compare across all keys to detect duplicates. The hash comparison never exposes the plaintext — it only reveals whether two values are identical. Duplicates are reported with a recommendation to consolidate under a single canonical name. The system can optionally create aliases so existing references continue working.

## Implementation

### Files to Create/Modify

- `crates/pqvault-health-mcp/src/duplicates.rs` — Duplicate detection engine using hash comparison
- `crates/pqvault-health-mcp/src/lib.rs` — Register duplicate detection tools
- `crates/pqvault-core/src/models.rs` — Add `value_hash` field to encrypted key metadata
- `crates/pqvault-core/src/alias.rs` — Key alias system for consolidation

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Hash of a key's value (never store plaintext)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueHash(pub String);

impl ValueHash {
    pub fn compute(plaintext: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        Self(hex::encode(hasher.finalize()))
    }
}

/// Group of keys with identical values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub value_hash: String,
    pub key_names: Vec<String>,
    pub canonical: Option<String>,  // Suggested primary key name
    pub categories: Vec<String>,
    pub last_used: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)>,
}

/// Key alias mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAlias {
    pub alias_name: String,
    pub target_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reason: String,
}

/// Duplicate detector
pub struct DuplicateDetector;

impl DuplicateDetector {
    /// Find all groups of duplicate keys
    pub fn detect(keys: &[(String, ValueHash)]) -> Vec<DuplicateGroup> {
        let mut hash_groups: HashMap<String, Vec<String>> = HashMap::new();
        for (name, hash) in keys {
            hash_groups.entry(hash.0.clone()).or_default().push(name.clone());
        }

        hash_groups.into_iter()
            .filter(|(_, names)| names.len() > 1)
            .map(|(hash, mut names)| {
                names.sort();
                let canonical = Self::suggest_canonical(&names);
                DuplicateGroup {
                    value_hash: hash,
                    canonical: Some(canonical),
                    key_names: names,
                    categories: vec![],
                    last_used: vec![],
                }
            })
            .collect()
    }

    /// Suggest which key should be the canonical one
    fn suggest_canonical(names: &[String]) -> String {
        // Prefer: shortest name, most descriptive, has PROD/MAIN prefix
        names.iter()
            .min_by_key(|n| {
                let mut score: i32 = n.len() as i32;
                if n.contains("PROD") || n.contains("MAIN") { score -= 50; }
                if n.contains("OLD") || n.contains("DEPRECATED") { score += 50; }
                score
            })
            .cloned()
            .unwrap_or_else(|| names[0].clone())
    }
}
```

### MCP Tools

```rust
/// Detect duplicate keys in the vault
#[tool(name = "detect_duplicates")]
async fn detect_duplicates(&self) -> Result<CallToolResult, McpError> {
    let keys = self.vault.list_key_names().await?;
    let mut hashes = Vec::new();

    for key_name in &keys {
        let value = self.vault.get_raw(key_name).await?;
        let hash = ValueHash::compute(&value);
        hashes.push((key_name.clone(), hash));
    }

    let groups = DuplicateDetector::detect(&hashes);

    if groups.is_empty() {
        return Ok(CallToolResult::success("No duplicates found."));
    }

    let output = groups.iter().enumerate().map(|(i, g)| {
        let canonical = g.canonical.as_deref().unwrap_or("?");
        let others: Vec<&str> = g.key_names.iter()
            .filter(|n| n.as_str() != canonical)
            .map(|n| n.as_str())
            .collect();
        format!(
            "Group {}: {} keys with same value\n  Canonical: {}\n  Duplicates: {}\n  Hash: {}...{}",
            i + 1, g.key_names.len(), canonical,
            others.join(", "),
            &g.value_hash[..8], &g.value_hash[56..]
        )
    }).collect::<Vec<_>>().join("\n\n");

    Ok(CallToolResult::success(format!("{} duplicate groups found:\n\n{}", groups.len(), output)))
}

/// Consolidate duplicates under canonical name
#[tool(name = "consolidate_duplicates")]
async fn consolidate_duplicates(
    &self,
    #[arg(description = "Canonical key name to keep")] canonical: String,
    #[arg(description = "Duplicate key names to alias")] duplicates: Vec<String>,
    #[arg(description = "Delete duplicates instead of aliasing")] delete: Option<bool>,
) -> Result<CallToolResult, McpError> {
    // Implementation: create aliases or delete duplicates
}

/// Create a key alias
#[tool(name = "create_alias")]
async fn create_alias(
    &self,
    #[arg(description = "Alias name")] alias: String,
    #[arg(description = "Target key name")] target: String,
    #[arg(description = "Reason for alias")] reason: String,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### CLI Commands

```bash
# Detect duplicates
pqvault health duplicates
# 2 duplicate groups found:
#
# Group 1: 3 keys with same value
#   Canonical: STRIPE_SECRET_KEY
#   Duplicates: STRIPE_KEY, PAYMENT_API_KEY
#   Hash: a1b2c3d4...e5f6g7h8
#
# Group 2: 2 keys with same value
#   Canonical: DATABASE_URL
#   Duplicates: PROD_DB_URL
#   Hash: 9f8e7d6c...b5a4c3d2

# Consolidate (create aliases)
pqvault consolidate STRIPE_SECRET_KEY --alias STRIPE_KEY PAYMENT_API_KEY

# Consolidate (delete duplicates)
pqvault consolidate STRIPE_SECRET_KEY --delete STRIPE_KEY PAYMENT_API_KEY

# Create manual alias
pqvault alias create MY_ALIAS --target STRIPE_SECRET_KEY --reason "legacy name"

# List aliases
pqvault alias list
```

### Web UI Changes

- "Duplicates" tab in health dashboard
- Visual grouping of duplicate keys with consolidation actions
- Alias management panel
- Warning indicator on duplicate keys in key list

## Dependencies

- `sha2 = "0.10"` (existing via encryption stack) — Value hashing
- `hex = "0.4"` (existing) — Hash display
- `pqvault-core` (existing) — Key storage and metadata

## Testing

### Unit Tests

```rust
#[test]
fn value_hash_consistent() {
    let h1 = ValueHash::compute(b"secret_value_123");
    let h2 = ValueHash::compute(b"secret_value_123");
    assert_eq!(h1, h2);
}

#[test]
fn different_values_different_hashes() {
    let h1 = ValueHash::compute(b"value_a");
    let h2 = ValueHash::compute(b"value_b");
    assert_ne!(h1, h2);
}

#[test]
fn detect_duplicate_group() {
    let keys = vec![
        ("KEY_A".to_string(), ValueHash::compute(b"same")),
        ("KEY_B".to_string(), ValueHash::compute(b"same")),
        ("KEY_C".to_string(), ValueHash::compute(b"different")),
    ];
    let groups = DuplicateDetector::detect(&keys);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].key_names.len(), 2);
}

#[test]
fn no_duplicates_returns_empty() {
    let keys = vec![
        ("KEY_A".to_string(), ValueHash::compute(b"val_a")),
        ("KEY_B".to_string(), ValueHash::compute(b"val_b")),
    ];
    let groups = DuplicateDetector::detect(&keys);
    assert!(groups.is_empty());
}

#[test]
fn canonical_prefers_prod() {
    let canonical = DuplicateDetector::suggest_canonical(&[
        "OLD_STRIPE_KEY".to_string(),
        "PROD_STRIPE_KEY".to_string(),
        "STRIPE_KEY".to_string(),
    ]);
    assert_eq!(canonical, "PROD_STRIPE_KEY");
}
```

### Integration Tests

```rust
#[tokio::test]
async fn detect_real_duplicates() {
    let mcp = test_health_mcp().await;
    mcp.vault.store("KEY_A", "same_secret").await.unwrap();
    mcp.vault.store("KEY_B", "same_secret").await.unwrap();
    mcp.vault.store("KEY_C", "different").await.unwrap();

    let result = mcp.detect_duplicates().await.unwrap();
    assert!(result.contains("KEY_A"));
    assert!(result.contains("KEY_B"));
    assert!(!result.contains("KEY_C"));
}

#[tokio::test]
async fn alias_resolves_to_target() {
    let mcp = test_health_mcp().await;
    mcp.vault.store("CANONICAL_KEY", "the_value").await.unwrap();
    mcp.create_alias("ALIAS_KEY", "CANONICAL_KEY", "migration").await.unwrap();

    let value = mcp.vault.get("ALIAS_KEY").await.unwrap();
    assert_eq!(value, "the_value");
}
```

### Manual Verification

1. Store the same value under 3 different key names
2. Run duplicate detection and verify all 3 are grouped
3. Consolidate under one name with aliases
4. Verify alias resolution works (vault_get on alias returns correct value)
5. Rotate the canonical key and verify aliases still work

## Example Usage

```bash
# Discover duplicates after onboarding a messy project:
pqvault health duplicates
# Found 5 duplicate groups — vault has 40% redundancy

# Clean up:
pqvault consolidate STRIPE_SECRET_KEY \
  --alias STRIPE_KEY PAYMENT_API_KEY OLD_STRIPE \
  --reason "Consolidating to single canonical name"

# Now rotations only need to happen once:
pqvault rotate STRIPE_SECRET_KEY
# Aliases automatically get the new value
```
