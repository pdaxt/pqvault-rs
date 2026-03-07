# Feature 096: GitOps for Secrets

## Status: Done
## Phase: 10 (v3.0)
## Priority: Medium

## Problem

Secret configuration is imperative — engineers run individual commands to create,
update, and delete keys. There is no declarative "desired state" that can be
version-controlled, reviewed in pull requests, and applied automatically. When a
new team member joins, they cannot reconstruct the vault from a specification.
Infrastructure-as-code practices do not extend to secret management.

## Solution

Implement GitOps-style declarative secret management where the desired vault state
is defined in a YAML file checked into version control. Running `pqvault converge`
compares the declared state with actual vault state and applies the minimal set of
changes needed to converge. Deleted keys in the YAML are removed from the vault.
The YAML contains metadata and policies but never actual secret values.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      converge.rs      # Converge command entry point
    gitops/
      mod.rs           # GitOps module root
      spec.rs          # YAML spec parser
      differ.rs        # Spec vs actual state diff
      applier.rs       # Apply changes to converge
      validator.rs     # Spec validation
```

### Data Model Changes

```rust
/// Declarative vault specification
#[derive(Serialize, Deserialize)]
pub struct VaultSpec {
    pub apiVersion: String,    // "pqvault.io/v1"
    pub kind: String,          // "VaultSpec"
    pub metadata: SpecMetadata,
    pub spec: SpecBody,
}

#[derive(Serialize, Deserialize)]
pub struct SpecMetadata {
    pub name: String,
    pub environment: String,
    pub owner: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SpecBody {
    pub defaults: SpecDefaults,
    pub secrets: Vec<SecretSpec>,
}

#[derive(Serialize, Deserialize)]
pub struct SpecDefaults {
    pub rotation_days: Option<u32>,
    pub category: Option<String>,
}

/// Specification for a single secret (no values!)
#[derive(Serialize, Deserialize)]
pub struct SecretSpec {
    pub name: String,
    pub category: String,
    pub provider: Option<String>,
    pub rotation_days: Option<u32>,
    pub tags: Option<Vec<String>>,
    pub ip_policy: Option<IpPolicySpec>,
    pub time_policy: Option<TimePolicySpec>,
    pub services: Option<Vec<String>>,
    /// How to obtain the value (never stored in YAML)
    pub source: SecretSource,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    /// Prompt user for value on first create
    Prompt,
    /// Generate random value
    Generate { length: usize, charset: Option<String> },
    /// Reference environment variable
    EnvVar { name: String },
    /// Reference another vault key
    VaultRef { key: String },
    /// Already exists, don't touch the value
    Existing,
}

/// Result of comparing spec with actual state
pub struct ConvergeResult {
    pub to_create: Vec<String>,
    pub to_update: Vec<UpdateAction>,
    pub to_delete: Vec<String>,
    pub unchanged: Vec<String>,
    pub errors: Vec<String>,
}

pub struct UpdateAction {
    pub key: String,
    pub changes: Vec<String>,  // "category: general -> cloud"
}

pub fn compute_convergence(spec: &VaultSpec, actual: &VaultState) -> ConvergeResult {
    let mut result = ConvergeResult::default();
    let actual_keys: HashSet<&str> = actual.keys.iter().map(|k| k.name.as_str()).collect();
    let spec_keys: HashSet<&str> = spec.spec.secrets.iter().map(|s| s.name.as_str()).collect();

    // Keys in spec but not in vault → create
    for secret in &spec.spec.secrets {
        if !actual_keys.contains(secret.name.as_str()) {
            result.to_create.push(secret.name.clone());
        } else {
            // Key exists — check metadata matches
            let actual_key = actual.keys.iter().find(|k| k.name == secret.name).unwrap();
            let changes = compare_metadata(secret, actual_key);
            if changes.is_empty() {
                result.unchanged.push(secret.name.clone());
            } else {
                result.to_update.push(UpdateAction {
                    key: secret.name.clone(),
                    changes,
                });
            }
        }
    }

    // Keys in vault but not in spec → delete (if managed)
    for key in &actual.keys {
        if !spec_keys.contains(key.name.as_str()) && key.managed {
            result.to_delete.push(key.name.clone());
        }
    }

    result
}
```

### MCP Tools

No new MCP tools. GitOps convergence is a CLI operation.

### CLI Commands

```bash
# Converge vault to match spec (dry-run first)
pqvault converge vault-spec.yaml --dry-run

# Apply convergence
pqvault converge vault-spec.yaml

# Validate spec file
pqvault converge validate vault-spec.yaml

# Generate spec from current vault state
pqvault converge export > vault-spec.yaml

# Show diff between spec and actual
pqvault converge diff vault-spec.yaml
```

### Web UI Changes

None. GitOps is a CLI workflow.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `serde_yaml` | 0.9 | YAML parsing (already in workspace) |

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vault_spec() {
        let yaml = r#"
apiVersion: pqvault.io/v1
kind: VaultSpec
metadata:
  name: production
  environment: prod
spec:
  defaults:
    rotation_days: 90
  secrets:
    - name: STRIPE_SECRET_KEY
      category: payment
      provider: stripe
      rotation_days: 60
      source:
        prompt: {}
    - name: DATABASE_URL
      category: database
      source:
        existing: {}
"#;
        let spec: VaultSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.spec.secrets.len(), 2);
        assert_eq!(spec.metadata.environment, "prod");
    }

    #[test]
    fn test_convergence_create() {
        let spec = mock_spec(&["KEY_A", "KEY_B"]);
        let actual = mock_state(&["KEY_A"]);
        let result = compute_convergence(&spec, &actual);
        assert_eq!(result.to_create, vec!["KEY_B"]);
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn test_convergence_delete() {
        let spec = mock_spec(&["KEY_A"]);
        let actual = mock_state_managed(&["KEY_A", "KEY_B"]);
        let result = compute_convergence(&spec, &actual);
        assert_eq!(result.to_delete, vec!["KEY_B"]);
    }

    #[test]
    fn test_convergence_update_metadata() {
        let spec = mock_spec_with_category(&[("KEY_A", "cloud")]);
        let actual = mock_state_with_category(&[("KEY_A", "general")]);
        let result = compute_convergence(&spec, &actual);
        assert_eq!(result.to_update.len(), 1);
        assert!(result.to_update[0].changes[0].contains("category"));
    }

    #[test]
    fn test_validate_spec() {
        let spec = VaultSpec {
            apiVersion: "pqvault.io/v1".into(),
            kind: "VaultSpec".into(),
            metadata: SpecMetadata { name: "test".into(), environment: "dev".into(), owner: None },
            spec: SpecBody { defaults: SpecDefaults::default(), secrets: vec![] },
        };
        assert!(validate_spec(&spec).is_ok());
    }
}
```

## Example Usage

```yaml
# vault-spec.yaml
apiVersion: pqvault.io/v1
kind: VaultSpec
metadata:
  name: payment-service
  environment: production
  owner: payments-team

spec:
  defaults:
    rotation_days: 90
    category: payment

  secrets:
    - name: STRIPE_SECRET_KEY
      provider: stripe
      rotation_days: 60
      tags: [api, revenue-critical]
      services: [payment-api, checkout]
      source:
        prompt: {}

    - name: STRIPE_PUBLISHABLE_KEY
      provider: stripe
      rotation_days: null  # Never rotates
      source:
        prompt: {}

    - name: STRIPE_WEBHOOK_SECRET
      provider: stripe
      rotation_days: 180
      source:
        prompt: {}

    - name: PAYMENT_DB_URL
      category: database
      services: [payment-api]
      source:
        existing: {}
```

```
$ pqvault converge vault-spec.yaml --dry-run

  Convergence Plan: payment-service (production)
  ═══════════════════════════════════════════════

  CREATE (1):
    + STRIPE_WEBHOOK_SECRET    (will prompt for value)

  UPDATE (1):
    ~ STRIPE_SECRET_KEY        rotation_days: 90 -> 60

  DELETE (1):
    - OLD_PAYMENT_TOKEN        (not in spec, managed)

  UNCHANGED (2):
    = STRIPE_PUBLISHABLE_KEY
    = PAYMENT_DB_URL

  Summary: 1 create, 1 update, 1 delete, 2 unchanged
  Run without --dry-run to apply.
```
