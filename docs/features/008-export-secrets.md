# Feature 008: Export Secrets

## Status: Planned
## Phase: 1 (v2.1)
## Priority: Medium

## Problem

PQVault can import secrets but has no corresponding export capability. Teams need to export secrets in standard formats for CI/CD pipelines, Docker deployments, Kubernetes manifests, and migration to other tools. Without export, PQVault becomes a roach motel for secrets — data goes in but can't come out in useful formats.

## Solution

`pqvault export --project myapp --format env|json|yaml|docker` exports secrets in common formats. Exports are protected by master password confirmation and logged in the audit trail. Supports stdout output (default) or writing to a file, with optional encryption of the exported file.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/export.rs` — Export logic for all formats
- `crates/pqvault-cli/src/main.rs` — Add `Export` subcommand

### Data Model Changes

No vault model changes needed. New structs for export configuration:

```rust
#[derive(Debug, Clone)]
pub struct ExportConfig {
    pub project: Option<String>,
    pub category: Option<String>,
    pub keys: Vec<String>,
    pub format: ExportFormat,
    pub output: Option<PathBuf>,
    pub encrypt_output: bool,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ExportFormat {
    /// KEY=VALUE format (.env)
    Env,
    /// JSON object {"KEY": "VALUE"}
    Json,
    /// YAML mapping
    Yaml,
    /// Docker --env-file format
    Docker,
    /// Kubernetes Secret YAML
    K8s,
    /// GitHub Actions secrets format
    GithubActions,
}
```

### MCP Tools

```rust
// Tool: vault_export
{
    "name": "vault_export",
    "description": "Export secrets in a specified format",
    "params": {
        "project": "myapp",           // optional
        "category": "database",        // optional
        "format": "json",              // required: env|json|yaml|docker|k8s
        "include_metadata": false       // include category, created_at, etc.
    },
    "returns": {
        "content": "...",              // The exported content as a string
        "format": "json",
        "secret_count": 5
    }
}
```

### CLI Commands

```bash
# Export project secrets as .env format (stdout)
pqvault export --project myapp --format env

# Export to file
pqvault export --project myapp --format env --output .env.production

# Export as JSON
pqvault export --project myapp --format json

# Export as YAML
pqvault export --project myapp --format yaml

# Export for Docker
pqvault export --project myapp --format docker --output docker.env

# Export as Kubernetes Secret
pqvault export --project myapp --format k8s --output k8s-secret.yaml

# Export specific category
pqvault export --category database --format env

# Export specific keys
pqvault export --keys DATABASE_URL,REDIS_URL --format env

# Export with metadata (includes comments with category, dates)
pqvault export --project myapp --format env --metadata

# Export encrypted (for sharing)
pqvault export --project myapp --format json --encrypt --output secrets.json.enc
```

### Web UI Changes

"Export" button on the secrets list page that downloads secrets in the selected format. Requires TOTP confirmation (if auth is enabled) before exporting.

## Core Implementation

```rust
// crates/pqvault-cli/src/export.rs

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

pub fn export_secrets(
    config: &ExportConfig,
    vault: &Vault,
    master_password: &str,
) -> Result<String> {
    // Collect secrets to export
    let entries = collect_entries(vault, config, master_password)?;

    if entries.is_empty() {
        anyhow::bail!("No secrets match the export criteria");
    }

    // Generate output in requested format
    let content = match config.format {
        ExportFormat::Env => format_env(&entries, config.include_metadata),
        ExportFormat::Json => format_json(&entries, config.include_metadata)?,
        ExportFormat::Yaml => format_yaml(&entries, config.include_metadata)?,
        ExportFormat::Docker => format_docker(&entries),
        ExportFormat::K8s => format_k8s(&entries, config.project.as_deref())?,
        ExportFormat::GithubActions => format_github_actions(&entries),
    };

    // Write to file or stdout
    if let Some(output_path) = &config.output {
        if config.encrypt_output {
            let encrypted = pqvault_core::crypto::password_encrypt(
                content.as_bytes(),
                master_password,
            )?;
            fs::write(output_path, &encrypted)
                .context(format!("Failed to write {}", output_path.display()))?;
            eprintln!("Exported {} secrets (encrypted) to {}", entries.len(), output_path.display());
        } else {
            fs::write(output_path, &content)
                .context(format!("Failed to write {}", output_path.display()))?;
            // Set restrictive permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(output_path, fs::Permissions::from_mode(0o600))?;
            }
            eprintln!("Exported {} secrets to {}", entries.len(), output_path.display());
        }
    }

    Ok(content)
}

struct ExportEntry {
    name: String,
    value: String,
    category: String,
    created: String,
    project: Option<String>,
}

fn collect_entries(
    vault: &Vault,
    config: &ExportConfig,
    master_password: &str,
) -> Result<Vec<ExportEntry>> {
    let mut entries = Vec::new();

    for secret in &vault.entries {
        // Filter by project
        if let Some(ref proj) = config.project {
            if secret.project.as_deref() != Some(proj.as_str()) {
                continue;
            }
        }

        // Filter by category
        if let Some(ref cat) = config.category {
            if &secret.category != cat {
                continue;
            }
        }

        // Filter by specific keys
        if !config.keys.is_empty() && !config.keys.contains(&secret.name) {
            continue;
        }

        let value = vault.decrypt_value(&secret.encrypted_value, master_password)?;
        entries.push(ExportEntry {
            name: secret.name.clone(),
            value,
            category: secret.category.clone(),
            created: secret.created.clone(),
            project: secret.project.clone(),
        });
    }

    // Sort by name for deterministic output
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn format_env(entries: &[ExportEntry], include_metadata: bool) -> String {
    let mut output = String::new();

    if include_metadata {
        output.push_str("# Exported from PQVault\n");
        output.push_str(&format!("# Date: {}\n", chrono::Utc::now().to_rfc3339()));
        output.push_str("#\n\n");
    }

    let mut current_category = String::new();
    for entry in entries {
        if include_metadata && entry.category != current_category {
            if !current_category.is_empty() {
                output.push('\n');
            }
            output.push_str(&format!("# {}\n", entry.category.to_uppercase()));
            current_category = entry.category.clone();
        }

        // Quote values that contain spaces, quotes, or special characters
        let needs_quoting = entry.value.contains(' ')
            || entry.value.contains('"')
            || entry.value.contains('\'')
            || entry.value.contains('#')
            || entry.value.contains('\n');

        if needs_quoting {
            let escaped = entry.value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            output.push_str(&format!("{}=\"{}\"\n", entry.name, escaped));
        } else {
            output.push_str(&format!("{}={}\n", entry.name, entry.value));
        }
    }

    output
}

fn format_json(entries: &[ExportEntry], include_metadata: bool) -> Result<String> {
    if include_metadata {
        let map: BTreeMap<String, serde_json::Value> = entries
            .iter()
            .map(|e| {
                (e.name.clone(), serde_json::json!({
                    "value": e.value,
                    "category": e.category,
                    "created": e.created,
                    "project": e.project,
                }))
            })
            .collect();
        Ok(serde_json::to_string_pretty(&map)?)
    } else {
        let map: BTreeMap<String, String> = entries
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect();
        Ok(serde_json::to_string_pretty(&map)?)
    }
}

fn format_yaml(entries: &[ExportEntry], include_metadata: bool) -> Result<String> {
    if include_metadata {
        let map: BTreeMap<String, serde_json::Value> = entries
            .iter()
            .map(|e| {
                (e.name.clone(), serde_json::json!({
                    "value": e.value,
                    "category": e.category,
                }))
            })
            .collect();
        Ok(serde_yaml::to_string(&map)?)
    } else {
        let map: BTreeMap<String, String> = entries
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect();
        Ok(serde_yaml::to_string(&map)?)
    }
}

fn format_docker(entries: &[ExportEntry]) -> String {
    // Docker --env-file format: KEY=VALUE, no quotes
    entries
        .iter()
        .map(|e| format!("{}={}", e.name, e.value))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn format_k8s(entries: &[ExportEntry], project: Option<&str>) -> Result<String> {
    let name = project.unwrap_or("pqvault-secrets");

    let data: BTreeMap<String, String> = entries
        .iter()
        .map(|e| (e.name.clone(), BASE64.encode(&e.value)))
        .collect();

    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "labels": {
                "managed-by": "pqvault"
            }
        },
        "type": "Opaque",
        "data": data
    });

    // Convert to YAML for k8s
    Ok(serde_yaml::to_string(&secret)?)
}

fn format_github_actions(entries: &[ExportEntry]) -> String {
    // GitHub Actions format for setting secrets via gh cli
    let mut output = String::from("#!/bin/bash\n# Set GitHub Actions secrets\n\n");

    for entry in entries {
        output.push_str(&format!(
            "echo '{}' | gh secret set {}\n",
            entry.value.replace('\'', "'\\''"),
            entry.name,
        ));
    }

    output
}
```

## Dependencies

- `serde_yaml = "0.9"` — YAML serialization for YAML and K8s export formats
- `base64 = "0.22"` — Already a dependency, used for K8s secret encoding
- Uses existing `serde_json`, `chrono`

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<ExportEntry> {
        vec![
            ExportEntry {
                name: "DATABASE_URL".into(),
                value: "postgres://user:pass@host:5432/db".into(),
                category: "database".into(),
                created: "2025-01-01T00:00:00Z".into(),
                project: Some("myapp".into()),
            },
            ExportEntry {
                name: "API_KEY".into(),
                value: "sk_live_abc123".into(),
                category: "payment".into(),
                created: "2025-01-02T00:00:00Z".into(),
                project: Some("myapp".into()),
            },
        ]
    }

    #[test]
    fn test_format_env() {
        let output = format_env(&sample_entries(), false);
        assert!(output.contains("API_KEY=sk_live_abc123"));
        assert!(output.contains("DATABASE_URL=postgres://user:pass@host:5432/db"));
    }

    #[test]
    fn test_format_env_with_metadata() {
        let output = format_env(&sample_entries(), true);
        assert!(output.contains("# Exported from PQVault"));
        assert!(output.contains("# DATABASE"));
        assert!(output.contains("# PAYMENT"));
    }

    #[test]
    fn test_format_env_quotes_special_chars() {
        let entries = vec![ExportEntry {
            name: "MSG".into(),
            value: "hello world with spaces".into(),
            category: "config".into(),
            created: "2025-01-01T00:00:00Z".into(),
            project: None,
        }];
        let output = format_env(&entries, false);
        assert!(output.contains("MSG=\"hello world with spaces\""));
    }

    #[test]
    fn test_format_json() {
        let output = format_json(&sample_entries(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["API_KEY"], "sk_live_abc123");
        assert_eq!(parsed["DATABASE_URL"], "postgres://user:pass@host:5432/db");
    }

    #[test]
    fn test_format_yaml() {
        let output = format_yaml(&sample_entries(), false).unwrap();
        assert!(output.contains("API_KEY:"));
        assert!(output.contains("sk_live_abc123"));
    }

    #[test]
    fn test_format_k8s() {
        let output = format_k8s(&sample_entries(), Some("myapp")).unwrap();
        assert!(output.contains("kind: Secret"));
        assert!(output.contains("name: myapp"));
        // Values should be base64 encoded
        let b64_value = BASE64.encode("sk_live_abc123");
        assert!(output.contains(&b64_value));
    }

    #[test]
    fn test_format_docker() {
        let output = format_docker(&sample_entries());
        assert!(output.contains("API_KEY=sk_live_abc123"));
        assert!(!output.contains("\"")); // Docker format has no quotes
    }

    #[test]
    fn test_output_is_deterministic() {
        let output1 = format_env(&sample_entries(), false);
        let output2 = format_env(&sample_entries(), false);
        assert_eq!(output1, output2);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_export_to_file_sets_permissions() {
    let dir = tempdir().unwrap();
    let vault = create_test_vault_with_entries(&dir);
    let output_path = dir.path().join("exported.env");

    let config = ExportConfig {
        project: None,
        category: None,
        keys: vec![],
        format: ExportFormat::Env,
        output: Some(output_path.clone()),
        encrypt_output: false,
        include_metadata: false,
    };

    export_secrets(&config, &vault, "test-password").unwrap();

    assert!(output_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&output_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn test_export_encrypted_roundtrip() {
    let dir = tempdir().unwrap();
    let vault = create_test_vault_with_entries(&dir);
    let output_path = dir.path().join("secrets.enc");

    let config = ExportConfig {
        project: None,
        category: None,
        keys: vec![],
        format: ExportFormat::Json,
        output: Some(output_path.clone()),
        encrypt_output: true,
        include_metadata: false,
    };

    let original = export_secrets(&config, &vault, "test-password").unwrap();

    // Decrypt and verify
    let encrypted = fs::read(&output_path).unwrap();
    let decrypted = pqvault_core::crypto::password_decrypt(&encrypted, "test-password").unwrap();
    let decrypted_str = String::from_utf8(decrypted).unwrap();
    assert_eq!(original, decrypted_str);
}
```

### Manual Verification

1. Add several secrets across projects and categories
2. Export each format and verify output is correct
3. Verify `.env` export can be sourced by bash: `source exported.env && echo $DATABASE_URL`
4. Verify JSON export is valid JSON: `cat exported.json | python -m json.tool`
5. Verify K8s export is valid: `kubectl apply --dry-run=client -f k8s-secret.yaml`
6. Verify file permissions are 0600

## Example Usage

```bash
# Export as .env
$ pqvault export --project webapp --format env
DATABASE_URL=postgres://user:pass@host:5432/prod
REDIS_URL=redis://cache:6379
STRIPE_SECRET_KEY=sk_live_abc123def456
JWT_SECRET=super-secret-key

# Export as JSON with metadata
$ pqvault export --project webapp --format json --metadata
{
  "DATABASE_URL": {
    "value": "postgres://user:pass@host:5432/prod",
    "category": "database",
    "created": "2025-01-01T00:00:00Z",
    "project": "webapp"
  },
  ...
}

# Export as Kubernetes Secret
$ pqvault export --project webapp --format k8s --output k8s-secret.yaml
Exported 4 secrets to k8s-secret.yaml

$ cat k8s-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: webapp
  labels:
    managed-by: pqvault
type: Opaque
data:
  DATABASE_URL: cG9zdGdyZXM6Ly91c2VyOnBhc3NAaG9zdDo1NDMyL3Byb2Q=
  ...

# Export encrypted for secure sharing
$ pqvault export --project webapp --format json --encrypt --output secrets.json.enc
Exported 4 secrets (encrypted) to secrets.json.enc
```
