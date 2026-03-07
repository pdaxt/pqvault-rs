# Feature 066: pqvault bulk

## Status: Planned
## Phase: 7 (v2.7)
## Priority: Medium

## Problem

Onboarding a new project or rotating keys for a compliance audit requires running
dozens of individual `pqvault set` or `pqvault rotate` commands. This is tedious,
error-prone, and impossible to codify into repeatable processes. Teams cannot
define a "desired state" for their vault and apply it in one operation.

## Solution

Implement `pqvault bulk` which reads a YAML manifest file describing desired vault
operations (add, rotate, delete) and executes them transactionally. The manifest
format is declarative, version-controllable, and supports variables. Failed operations
roll back all changes made in that batch.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      bulk.rs           # Bulk command entry point
    bulk/
      mod.rs            # Module root
      manifest.rs       # YAML manifest parser and validator
      executor.rs       # Transactional execution engine
      rollback.rs       # Rollback logic for failed batches
      report.rs         # Summary report generation
```

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};

/// Root of a bulk manifest YAML file
#[derive(Deserialize, Serialize)]
pub struct BulkManifest {
    /// Manifest format version
    pub version: String, // "1.0"
    /// Optional description
    pub description: Option<String>,
    /// Operations to execute
    pub operations: Vec<BulkOperation>,
    /// Variables for templating
    #[serde(default)]
    pub variables: HashMap<String, String>,
    /// Execution options
    #[serde(default)]
    pub options: BulkOptions,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action")]
pub enum BulkOperation {
    #[serde(rename = "add")]
    Add {
        key: String,
        value: Option<String>,
        generate: Option<GenerateSpec>,
        category: Option<String>,
        provider: Option<String>,
        tags: Option<Vec<String>>,
    },
    #[serde(rename = "rotate")]
    Rotate {
        key: String,
        #[serde(default)]
        auto: bool, // Use provider auto-rotation if available
    },
    #[serde(rename = "delete")]
    Delete {
        key: String,
        #[serde(default)]
        force: bool,
    },
    #[serde(rename = "update")]
    Update {
        key: String,
        value: String,
    },
    #[serde(rename = "copy")]
    Copy {
        source: String,
        target: String,
    },
}

#[derive(Deserialize, Serialize)]
pub struct GenerateSpec {
    /// Type: random, uuid, hex, base64
    pub r#type: String,
    /// Length for random generation
    pub length: Option<usize>,
    /// Prefix to prepend
    pub prefix: Option<String>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct BulkOptions {
    /// Stop on first error or continue
    #[serde(default)]
    pub stop_on_error: bool,
    /// Dry run mode
    #[serde(default)]
    pub dry_run: bool,
    /// Require confirmation before each operation
    #[serde(default)]
    pub confirm_each: bool,
}

pub struct BulkResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<OperationResult>,
    pub rolled_back: bool,
}

pub struct OperationResult {
    pub operation: String,
    pub key: String,
    pub status: OperationStatus,
    pub message: Option<String>,
    pub duration: Duration,
}

pub enum OperationStatus {
    Success,
    Failed(String),
    Skipped(String),
    RolledBack,
}
```

### MCP Tools

No new MCP tools. Bulk operations use existing vault APIs from `pqvault-core`.

### CLI Commands

```bash
# Apply a bulk manifest
pqvault bulk apply manifest.yaml

# Dry run first
pqvault bulk apply manifest.yaml --dry-run

# Validate manifest without executing
pqvault bulk validate manifest.yaml

# Generate a template manifest
pqvault bulk init > manifest.yaml

# Apply with variable overrides
pqvault bulk apply manifest.yaml --var env=production --var region=us-east-1
```

Command definition:

```rust
#[derive(Subcommand)]
pub enum BulkCommands {
    /// Apply operations from a manifest file
    Apply(BulkApplyArgs),
    /// Validate a manifest file
    Validate(BulkValidateArgs),
    /// Generate a template manifest
    Init,
}

#[derive(Args)]
pub struct BulkApplyArgs {
    /// Path to YAML manifest file
    pub manifest: PathBuf,

    /// Dry run: show plan without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Variable overrides (key=value)
    #[arg(long = "var", value_parser = parse_var)]
    variables: Vec<(String, String)>,

    /// Stop on first error (override manifest setting)
    #[arg(long)]
    stop_on_error: Option<bool>,
}
```

### Web UI Changes

None. Bulk operations are CLI-only; web UI bulk ops are covered in Feature 083.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `serde_yaml` | 0.9 | YAML manifest parsing |

Already in workspace: `serde`, `serde_json`, `chrono`.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let yaml = r#"
version: "1.0"
description: "Setup Stripe integration"
operations:
  - action: add
    key: STRIPE_SECRET_KEY
    generate:
      type: random
      length: 32
      prefix: "sk_live_"
    category: payment
    provider: stripe
  - action: add
    key: STRIPE_PUBLISHABLE_KEY
    value: "pk_live_known_value"
  - action: rotate
    key: OLD_API_KEY
    auto: true
"#;
        let manifest: BulkManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(manifest.operations.len(), 3);
    }

    #[test]
    fn test_variable_substitution() {
        let yaml = r#"
version: "1.0"
variables:
  env: staging
operations:
  - action: add
    key: "DB_URL_${env}"
    value: "postgres://${env}-db.example.com/app"
"#;
        let manifest: BulkManifest = serde_yaml::from_str(yaml).unwrap();
        let resolved = resolve_variables(&manifest).unwrap();
        assert_eq!(resolved.operations[0].key(), "DB_URL_staging");
    }

    #[test]
    fn test_validate_manifest_missing_key() {
        let yaml = r#"
version: "1.0"
operations:
  - action: add
    value: "no_key_specified"
"#;
        let result: Result<BulkManifest, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_spec_random() {
        let spec = GenerateSpec { r#type: "random".into(), length: Some(32), prefix: Some("sk_".into()) };
        let value = generate_value(&spec).unwrap();
        assert!(value.starts_with("sk_"));
        assert_eq!(value.len(), 3 + 32); // prefix + random
    }

    #[test]
    fn test_bulk_result_summary() {
        let result = BulkResult {
            total: 5, succeeded: 3, failed: 1, skipped: 1,
            results: vec![], rolled_back: false,
        };
        assert!(!result.all_succeeded());
        assert_eq!(result.failure_rate(), 0.2);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_bulk_apply_adds_keys() {
    let mut vault = empty_test_vault().await;
    let manifest = BulkManifest {
        version: "1.0".into(),
        operations: vec![
            BulkOperation::Add { key: "KEY_A".into(), value: Some("val_a".into()), ..Default::default() },
            BulkOperation::Add { key: "KEY_B".into(), value: Some("val_b".into()), ..Default::default() },
        ],
        ..Default::default()
    };
    let result = execute_bulk(&mut vault, &manifest).await.unwrap();
    assert_eq!(result.succeeded, 2);
    assert_eq!(vault.list_keys().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_bulk_rollback_on_failure() {
    let mut vault = test_vault_with_keys(&[("EXISTING", "val")]).await;
    let manifest = BulkManifest {
        version: "1.0".into(),
        options: BulkOptions { stop_on_error: true, ..Default::default() },
        operations: vec![
            BulkOperation::Add { key: "NEW_KEY".into(), value: Some("v".into()), ..Default::default() },
            BulkOperation::Delete { key: "NONEXISTENT".into(), force: false },
        ],
        ..Default::default()
    };
    let result = execute_bulk(&mut vault, &manifest).await.unwrap();
    assert!(result.rolled_back);
    // NEW_KEY should have been rolled back
    assert!(vault.get("NEW_KEY").await.is_err());
}
```

## Example Usage

```yaml
# manifest.yaml — Setup new microservice secrets
version: "1.0"
description: "Initialize secrets for payment-service"

variables:
  env: production
  region: us-east-1

operations:
  - action: add
    key: "STRIPE_SECRET_KEY_${env}"
    generate:
      type: random
      length: 48
      prefix: "sk_live_"
    category: payment
    provider: stripe

  - action: add
    key: "DATABASE_URL_${env}"
    value: "postgres://app:${DB_PASSWORD}@db-${region}.internal:5432/payments"
    category: database

  - action: add
    key: "REDIS_URL_${env}"
    value: "redis://cache-${region}.internal:6379/0"
    category: cache

  - action: rotate
    key: "OLD_PAYMENT_KEY"
    auto: true

  - action: delete
    key: "DEPRECATED_WEBHOOK_SECRET"
    force: true
```

```
$ pqvault bulk apply manifest.yaml --dry-run

  Bulk Operations Plan (DRY RUN)
  ──────────────────────────────

  #  Action   Key                          Details
  ─  ──────   ────────────────────────────  ────────────────
  1  ADD      STRIPE_SECRET_KEY_production  generate: random(48)
  2  ADD      DATABASE_URL_production       explicit value
  3  ADD      REDIS_URL_production          explicit value
  4  ROTATE   OLD_PAYMENT_KEY               auto-rotate via provider
  5  DELETE   DEPRECATED_WEBHOOK_SECRET     force: true

  Summary: 3 add, 1 rotate, 1 delete
  Run without --dry-run to execute.

$ pqvault bulk apply manifest.yaml
  Executing 5 operations...
  [1/5] ADD    STRIPE_SECRET_KEY_production    ... done (12ms)
  [2/5] ADD    DATABASE_URL_production         ... done (8ms)
  [3/5] ADD    REDIS_URL_production            ... done (9ms)
  [4/5] ROTATE OLD_PAYMENT_KEY                 ... done (1.2s)
  [5/5] DELETE DEPRECATED_WEBHOOK_SECRET       ... done (6ms)

  Bulk complete: 5/5 succeeded, 0 failed.
```
