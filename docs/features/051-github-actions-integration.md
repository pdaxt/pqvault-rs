# Feature 051: GitHub Actions Integration

## Status: Done
## Phase: 6 (v2.6)
## Priority: Critical

## Problem

CI/CD pipelines still rely on GitHub Secrets for sensitive values. GitHub Secrets have no rotation capability, no audit trail of which workflow accessed which secret, no cost tracking, and no integration with PQVault's health monitoring. Changing a secret requires manual updates in GitHub settings, and there is no way to verify that secrets are still valid before a workflow runs.

## Solution

Create a GitHub Action (`pdaxt/pqvault-action@v1`) that injects PQVault secrets into CI workflows as environment variables. The action authenticates with PQVault using a service account token, fetches the requested keys, and exports them as masked environment variables. Secrets are never written to disk and are automatically masked in logs. The action supports key validation, rotation-aware caching, and audit trail integration.

## Implementation

### Files to Create/Modify

- `.github/actions/pqvault-action/action.yml` — Action metadata
- `.github/actions/pqvault-action/src/index.ts` — Action entry point
- `.github/actions/pqvault-action/src/client.ts` — PQVault API client
- `.github/actions/pqvault-action/src/mask.ts` — Secret masking utilities
- `crates/pqvault-web/src/api/service_account.rs` — Service account authentication
- `crates/pqvault-core/src/service_account.rs` — Service account model

### Data Model Changes

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Service account for CI/CD integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: String,
    pub name: String,
    pub token_hash: String,           // SHA-256 of the bearer token
    pub allowed_keys: Vec<String>,    // Keys this SA can access
    pub allowed_key_patterns: Vec<String>, // Glob patterns like "PROD_*"
    pub allowed_ips: Vec<String>,     // IP allowlist (GitHub Actions ranges)
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub rate_limit: u32,              // Max requests per hour
}

/// API request from GitHub Action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiSecretRequest {
    pub keys: Vec<String>,
    pub service_account_id: String,
    pub workflow_name: Option<String>,
    pub run_id: Option<String>,
    pub repository: Option<String>,
}

/// API response to GitHub Action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiSecretResponse {
    pub secrets: Vec<CiSecret>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiSecret {
    pub key_name: String,
    pub value: String,
    pub env_name: String, // Environment variable name to export
    pub rotation_due: bool,
    pub health_score: f64,
}
```

### GitHub Action (TypeScript)

```typescript
// .github/actions/pqvault-action/src/index.ts
import * as core from '@actions/core';

async function run(): Promise<void> {
  try {
    const vaultUrl = core.getInput('vault-url', { required: true });
    const token = core.getInput('token', { required: true });
    const keys = core.getInput('keys', { required: true }).split(',').map(k => k.trim());
    const prefix = core.getInput('prefix') || '';
    const failOnUnhealthy = core.getBooleanInput('fail-on-unhealthy');

    // Mask the token immediately
    core.setSecret(token);

    // Fetch secrets from PQVault
    const response = await fetch(`${vaultUrl}/api/v1/ci/secrets`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-GitHub-Run-ID': process.env.GITHUB_RUN_ID || '',
        'X-GitHub-Repository': process.env.GITHUB_REPOSITORY || '',
        'X-GitHub-Workflow': process.env.GITHUB_WORKFLOW || '',
      },
      body: JSON.stringify({ keys }),
    });

    if (!response.ok) {
      throw new Error(`PQVault API error: ${response.status} ${await response.text()}`);
    }

    const data: CiSecretResponse = await response.json();

    // Export each secret as a masked env var
    for (const secret of data.secrets) {
      const envName = prefix ? `${prefix}${secret.env_name}` : secret.env_name;
      core.setSecret(secret.value);
      core.exportVariable(envName, secret.value);
      core.info(`Exported ${envName} (health: ${secret.health_score}/100)`);

      if (secret.rotation_due) {
        core.warning(`Key ${secret.key_name} is due for rotation!`);
      }

      if (failOnUnhealthy && secret.health_score < 50) {
        core.setFailed(`Key ${secret.key_name} has unhealthy score: ${secret.health_score}`);
      }
    }

    for (const warning of data.warnings) {
      core.warning(warning);
    }

    core.info(`Successfully loaded ${data.secrets.length} secrets from PQVault`);
  } catch (error) {
    core.setFailed(`PQVault Action failed: ${(error as Error).message}`);
  }
}

run();
```

### Action YAML

```yaml
# .github/actions/pqvault-action/action.yml
name: 'PQVault Secrets'
description: 'Load secrets from PQVault into GitHub Actions'
branding:
  icon: 'lock'
  color: 'blue'

inputs:
  vault-url:
    description: 'PQVault server URL'
    required: true
  token:
    description: 'PQVault service account token'
    required: true
  keys:
    description: 'Comma-separated list of key names to fetch'
    required: true
  prefix:
    description: 'Prefix for exported environment variables'
    required: false
    default: ''
  fail-on-unhealthy:
    description: 'Fail if any key has health score < 50'
    required: false
    default: 'false'

runs:
  using: 'node20'
  main: 'dist/index.js'
```

### CLI Commands

```bash
# Create service account for CI
pqvault service-account create \
  --name "github-ci" \
  --keys "STRIPE_KEY,DATABASE_URL,REDIS_URL" \
  --allowed-ips "140.82.112.0/20" # GitHub Actions IP range
# Token: pqv_sa_aBcDeFgHiJkLmN...
# Store this token as PQVAULT_TOKEN in GitHub Secrets

# List service accounts
pqvault service-account list

# Rotate service account token
pqvault service-account rotate-token github-ci

# Disable service account
pqvault service-account disable github-ci
```

### Web UI Changes

- Service account management page
- CI/CD integration setup wizard
- Usage statistics per service account
- GitHub Actions workflow examples

## Dependencies

- `@actions/core` — GitHub Actions toolkit (TypeScript, for the action)
- `pqvault-web` (existing) — API endpoint
- `sha2 = "0.10"` (existing) — Token hashing
- Feature 041 (RBAC) — Service account model

## Testing

### Unit Tests

```rust
#[test]
fn service_account_key_pattern_matching() {
    let sa = ServiceAccount {
        allowed_key_patterns: vec!["PROD_*".into(), "STAGING_*".into()],
        ..Default::default()
    };
    assert!(sa.can_access("PROD_DATABASE_URL"));
    assert!(sa.can_access("STAGING_REDIS_URL"));
    assert!(!sa.can_access("DEV_DATABASE_URL"));
}

#[test]
fn service_account_ip_allowlist() {
    let sa = ServiceAccount {
        allowed_ips: vec!["140.82.112.0/20".into()],
        ..Default::default()
    };
    assert!(sa.is_ip_allowed("140.82.112.1"));
    assert!(!sa.is_ip_allowed("192.168.1.1"));
}

#[test]
fn token_is_hashed_not_stored() {
    let (token, sa) = ServiceAccount::create("test", vec![], vec![]);
    assert_ne!(sa.token_hash, token);
    assert!(sa.verify_token(&token));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn ci_endpoint_returns_secrets() {
    let app = test_app().await;
    let (token, _) = app.create_service_account("ci-test", vec!["KEY1"]).await;
    app.vault.store("KEY1", "secret_value").await.unwrap();

    let response = app.client
        .post(&format!("http://{}/api/v1/ci/secrets", app.addr))
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({"keys": ["KEY1"]}))
        .send().await.unwrap();

    assert_eq!(response.status(), 200);
    let body: CiSecretResponse = response.json().await.unwrap();
    assert_eq!(body.secrets[0].value, "secret_value");
}

#[tokio::test]
async fn ci_endpoint_rejects_unauthorized_key() {
    let app = test_app().await;
    let (token, _) = app.create_service_account("ci-test", vec!["KEY1"]).await;
    app.vault.store("KEY2", "secret").await.unwrap();

    let response = app.client
        .post(&format!("http://{}/api/v1/ci/secrets", app.addr))
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({"keys": ["KEY2"]}))
        .send().await.unwrap();

    assert_eq!(response.status(), 403);
}
```

### Manual Verification

1. Create service account with restricted keys
2. Store token as GitHub Secret
3. Create workflow using the action
4. Run workflow and verify secrets are injected
5. Check PQVault audit log for CI access events
6. Verify secrets are masked in workflow logs

## Example Usage

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: pdaxt/pqvault-action@v1
        with:
          vault-url: ${{ secrets.PQVAULT_URL }}
          token: ${{ secrets.PQVAULT_TOKEN }}
          keys: 'STRIPE_KEY,DATABASE_URL,REDIS_URL'
          fail-on-unhealthy: true

      - run: echo "Deploying with secrets loaded as env vars"
      - run: ./deploy.sh
        # $STRIPE_KEY, $DATABASE_URL, $REDIS_URL are available
        # and masked in logs
```
