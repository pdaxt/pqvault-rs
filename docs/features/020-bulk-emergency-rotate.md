# Feature 020: Bulk Emergency Rotate

## Status: Planned
## Phase: 2 (v2.2)
## Priority: High

## Problem

When a security breach is detected, every affected key must be rotated immediately. Currently this means running `pqvault rotate` one key at a time, waiting for each to complete, and verifying each individually. A breach affecting 15 payment keys takes 30+ minutes of manual work. During that time, the compromised keys remain active. Every minute counts during incident response.

## Solution

`pqvault rotate --category payment --all` rotates all keys matching a filter in parallel. Supports filtering by category, provider, project, or custom tag. Executes rotations concurrently (with configurable parallelism), provides real-time progress, and generates a detailed report. Failed rotations are retried once, then reported as failures requiring manual intervention.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/bulk_rotate.rs` — Bulk rotation orchestration
- `crates/pqvault-rotation-mcp/src/engine.rs` — Add concurrent rotation support
- `crates/pqvault-rotation-mcp/src/lib.rs` — Bulk rotation MCP tool
- `crates/pqvault-cli/src/main.rs` — Integrate bulk rotate CLI flags

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct BulkRotationResult {
    pub total: usize,
    pub succeeded: Vec<BulkRotationSuccess>,
    pub failed: Vec<BulkRotationFailure>,
    pub skipped: Vec<BulkRotationSkip>,
    pub duration_ms: u64,
    pub started_at: String,
    pub completed_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BulkRotationSuccess {
    pub key_name: String,
    pub provider: String,
    pub old_preview: String,
    pub new_preview: String,
    pub verified: bool,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BulkRotationFailure {
    pub key_name: String,
    pub provider: String,
    pub error: String,
    pub retried: bool,
    pub action_required: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BulkRotationSkip {
    pub key_name: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct BulkRotateFilter {
    pub category: Option<String>,
    pub provider: Option<String>,
    pub project: Option<String>,
    pub key_names: Vec<String>,
    pub max_parallel: usize,
    pub retry_failures: bool,
}
```

### MCP Tools

```rust
// Tool: vault_bulk_rotate
{
    "name": "vault_bulk_rotate",
    "description": "Emergency rotate all keys matching a filter",
    "params": {
        "category": "payment",        // optional
        "provider": "stripe",         // optional
        "project": "production",      // optional
        "max_parallel": 5,            // default 5
        "verify": true                // default true
    },
    "returns": {
        "total": 8,
        "succeeded": [...],
        "failed": [...],
        "skipped": [...],
        "duration_ms": 12500
    }
}
```

### CLI Commands

```bash
# Rotate all payment keys
pqvault rotate --category payment --all

# Rotate all keys for a provider
pqvault rotate --provider stripe --all

# Rotate all keys in a project
pqvault rotate --project production --all

# Rotate everything (nuclear option)
pqvault rotate --all --confirm-all

# Control parallelism
pqvault rotate --category payment --all --parallel 3

# Dry run
pqvault rotate --category payment --all --dry-run

# Generate incident report
pqvault rotate --category payment --all --report /tmp/rotation-report.json
```

## Core Implementation

```rust
// crates/pqvault-cli/src/bulk_rotate.rs

use tokio::sync::Semaphore;
use std::sync::Arc;
use futures::future::join_all;

pub async fn bulk_rotate(
    vault: &mut Vault,
    engine: &RotationEngine,
    filter: &BulkRotateFilter,
    master_password: &str,
) -> Result<BulkRotationResult> {
    let start = std::time::Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Collect keys to rotate
    let targets: Vec<&SecretEntry> = vault.entries.iter()
        .filter(|e| matches_filter(e, filter))
        .collect();

    if targets.is_empty() {
        eprintln!("No keys match the specified filter.");
        return Ok(BulkRotationResult {
            total: 0,
            succeeded: vec![],
            failed: vec![],
            skipped: vec![],
            duration_ms: 0,
            started_at,
            completed_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    eprintln!("Rotating {} keys (max {} parallel)...",
        targets.len(), filter.max_parallel);

    let semaphore = Arc::new(Semaphore::new(filter.max_parallel));
    let mut handles = Vec::new();

    for entry in &targets {
        let sem = semaphore.clone();
        let key_name = entry.name.clone();
        let provider = entry.provider.clone().unwrap_or_default();

        // Skip keys without rotation providers
        if entry.provider.is_none() {
            continue;
        }

        let old_value = match vault.decrypt_value(&entry.encrypted_value, master_password) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  SKIP {} (decrypt failed: {})", key_name, e);
                continue;
            }
        };

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let key_start = std::time::Instant::now();

            let result = engine.rotate_key(
                &entry.clone(),
                &old_value,
                &RotationOptions::default(),
            ).await;

            let duration = key_start.elapsed().as_millis() as u64;

            match result {
                Ok(rotation) => {
                    eprintln!("  OK   {} ({}ms)", key_name, duration);
                    RotateOutcome::Success(BulkRotationSuccess {
                        key_name,
                        provider,
                        old_preview: preview(&old_value),
                        new_preview: preview(&rotation.new_key),
                        verified: true,
                        duration_ms: duration,
                    })
                }
                Err(e) => {
                    eprintln!("  FAIL {} ({}): {}", key_name, duration, e);
                    RotateOutcome::Failure(BulkRotationFailure {
                        key_name,
                        provider,
                        error: e.to_string(),
                        retried: false,
                        action_required: "Manual rotation required".into(),
                    })
                }
            }
        }));
    }

    let outcomes = join_all(handles).await;

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();

    for outcome in outcomes {
        match outcome.unwrap() {
            RotateOutcome::Success(s) => succeeded.push(s),
            RotateOutcome::Failure(f) => {
                if filter.retry_failures {
                    // Retry once
                    eprintln!("  RETRY {}", f.key_name);
                    // ... retry logic ...
                }
                failed.push(f);
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    Ok(BulkRotationResult {
        total: targets.len(),
        succeeded,
        failed,
        skipped: vec![],
        duration_ms: duration,
        started_at,
        completed_at: chrono::Utc::now().to_rfc3339(),
    })
}

fn matches_filter(entry: &SecretEntry, filter: &BulkRotateFilter) -> bool {
    if let Some(cat) = &filter.category {
        if &entry.category != cat { return false; }
    }
    if let Some(prov) = &filter.provider {
        if entry.provider.as_deref() != Some(prov.as_str()) { return false; }
    }
    if let Some(proj) = &filter.project {
        if entry.project.as_deref() != Some(proj.as_str()) { return false; }
    }
    if !filter.key_names.is_empty() && !filter.key_names.contains(&entry.name) {
        return false;
    }
    true
}

fn preview(value: &str) -> String {
    if value.len() > 8 {
        format!("{}...{}", &value[..4], &value[value.len()-4..])
    } else {
        "****".into()
    }
}

enum RotateOutcome {
    Success(BulkRotationSuccess),
    Failure(BulkRotationFailure),
}
```

## Dependencies

- `tokio = { version = "1", features = ["sync", "rt-multi-thread"] }` — Already a dependency
- `futures = "0.3"` — For join_all concurrent execution
- Requires Feature 011 (Auto-Rotation Engine)
- Requires Feature 013 (Pre-Rotation Testing) for verification

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_by_category() {
        let entry = make_entry("KEY", "payment", Some("stripe"), None);
        let filter = BulkRotateFilter { category: Some("payment".into()), ..Default::default() };
        assert!(matches_filter(&entry, &filter));

        let filter2 = BulkRotateFilter { category: Some("database".into()), ..Default::default() };
        assert!(!matches_filter(&entry, &filter2));
    }

    #[test]
    fn test_filter_by_provider() {
        let entry = make_entry("KEY", "payment", Some("stripe"), None);
        let filter = BulkRotateFilter { provider: Some("stripe".into()), ..Default::default() };
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn test_filter_combined() {
        let entry = make_entry("KEY", "payment", Some("stripe"), Some("prod"));
        let filter = BulkRotateFilter {
            category: Some("payment".into()),
            project: Some("prod".into()),
            ..Default::default()
        };
        assert!(matches_filter(&entry, &filter));
    }
}
```

### Manual Verification

1. Set up multiple test keys across categories and providers
2. Run `pqvault rotate --category payment --all --dry-run` — verify correct keys selected
3. Run actual bulk rotation and verify all keys rotated
4. Simulate a failure (invalid provider key) and verify partial success reporting

## Example Usage

```bash
# Emergency: rotate all payment keys
$ pqvault rotate --category payment --all
EMERGENCY ROTATION: 5 payment keys
  Rotating with max 5 parallel...

  OK   STRIPE_SECRET_KEY       (1.2s)  sk_l...xyz -> sk_l...abc
  OK   STRIPE_WEBHOOK_SECRET   (0.8s)  whse...123 -> whse...456
  OK   STRIPE_CONNECT_KEY      (1.1s)  sk_l...def -> sk_l...ghi
  FAIL PAYPAL_CLIENT_SECRET    (2.0s)  API error: rate limited
  OK   ADYEN_API_KEY           (0.9s)  AQEf...mno -> AQEf...pqr

Results: 4 succeeded, 1 failed, 0 skipped (6.0s total)

FAILED (manual action required):
  PAYPAL_CLIENT_SECRET: API error: rate limited
    -> Log in to PayPal dashboard and rotate manually

# Generate incident report
$ pqvault rotate --category payment --all --report /tmp/incident-2025-01-15.json
Report saved to /tmp/incident-2025-01-15.json
```
