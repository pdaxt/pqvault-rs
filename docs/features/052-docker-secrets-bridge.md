# Feature 052: Docker Secrets Bridge

## Status: Planned
## Phase: 6 (v2.6)
## Priority: High

## Problem

Docker workflows require a separate secret management approach. Docker Compose uses `.env` files with plaintext secrets, Docker Swarm has its own secrets system, and container builds may need secrets at build time. PQVault keys are not accessible to Docker without manual export, creating a gap in the secret management chain. Developers often hardcode secrets in `docker-compose.yml` or commit `.env` files.

## Solution

Add a `pqvault docker-secrets` CLI command that generates Docker-compatible secrets from PQVault. The command supports multiple output formats: `.env` file (for Compose), Docker Swarm secrets (via `docker secret create`), BuildKit secrets (for build-time injection), and Kubernetes-style secret manifests. Secrets are fetched, decrypted, and written to ephemeral files or piped directly into Docker commands. Temporary files are created in a tmpfs mount and auto-cleaned after use.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/docker.rs` — Docker secrets bridge CLI commands
- `crates/pqvault-cli/src/docker/env.rs` — .env file generation
- `crates/pqvault-cli/src/docker/swarm.rs` — Docker Swarm secrets integration
- `crates/pqvault-cli/src/docker/buildkit.rs` — BuildKit secret mount generation

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Docker secrets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSecretsConfig {
    pub project: String,
    pub keys: Vec<DockerKeyMapping>,
    pub output_format: DockerOutputFormat,
    pub env_file_path: Option<PathBuf>,
    pub tmpfs_path: Option<PathBuf>,
    pub auto_cleanup: bool,
}

/// Mapping from vault key to Docker env var
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerKeyMapping {
    pub vault_key: String,
    pub env_name: Option<String>,  // Override the env var name
    pub file_name: Option<String>, // Override the secret file name
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DockerOutputFormat {
    EnvFile,           // KEY=value format
    DockerSwarm,       // docker secret create
    BuildKit,          // --secret id=...,src=...
    ComposeSecrets,    // docker-compose secrets section
    Stdout,            // Print to stdout for piping
}

/// Generated Docker secrets output
pub struct DockerSecretsOutput {
    pub format: DockerOutputFormat,
    pub env_pairs: Vec<(String, String)>,
    pub temp_files: Vec<PathBuf>,
}

impl DockerSecretsOutput {
    /// Render as .env file content
    pub fn as_env_file(&self) -> String {
        self.env_pairs.iter()
            .map(|(k, v)| format!("{}={}", k, shell_escape(v)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate docker secret create commands
    pub fn as_swarm_commands(&self) -> Vec<String> {
        self.env_pairs.iter()
            .map(|(k, v)| {
                format!("echo '{}' | docker secret create {} -", v, k.to_lowercase())
            })
            .collect()
    }

    /// Generate BuildKit --secret flags
    pub fn as_buildkit_flags(&self) -> String {
        self.temp_files.iter()
            .zip(&self.env_pairs)
            .map(|(path, (name, _))| {
                format!("--secret id={},src={}", name.to_lowercase(), path.display())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Generate docker-compose secrets section
    pub fn as_compose_yaml(&self) -> String {
        let mut yaml = String::from("secrets:\n");
        for (name, _) in &self.env_pairs {
            let lower = name.to_lowercase();
            yaml.push_str(&format!("  {}:\n    file: ./secrets/{}\n", lower, lower));
        }
        yaml
    }

    /// Cleanup temporary files
    pub fn cleanup(&self) {
        for path in &self.temp_files {
            if path.exists() {
                // Overwrite with zeros before deleting
                if let Ok(mut file) = std::fs::File::create(path) {
                    use std::io::Write;
                    let _ = file.write_all(&vec![0u8; 4096]);
                }
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') || s.contains('$') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}
```

### CLI Commands

```bash
# Generate .env file for docker-compose
pqvault docker-secrets --project myapp --format env > .env
# DATABASE_URL=postgres://user:pass@host:5432/db
# REDIS_URL=redis://host:6379
# STRIPE_KEY=sk_live_...

# Generate with key mapping
pqvault docker-secrets --project myapp --format env \
  --map "PROD_DATABASE_URL:DATABASE_URL" \
  --map "PROD_REDIS_URL:REDIS_URL"

# Docker Swarm secrets
pqvault docker-secrets --project myapp --format swarm | bash
# echo 'sk_live_...' | docker secret create stripe_key -
# echo 'postgres://...' | docker secret create database_url -

# BuildKit build-time secrets
docker build \
  $(pqvault docker-secrets --project myapp --format buildkit) \
  -t myapp .
# Expands to: --secret id=database_url,src=/tmp/pqvault/xyz123 ...

# Docker Compose with file-based secrets
pqvault docker-secrets --project myapp --format compose-files \
  --output-dir ./secrets
# Creates ./secrets/database_url, ./secrets/redis_url, etc.

# Auto-cleanup after Docker run
pqvault docker-secrets --project myapp --format env --exec \
  docker-compose up -d
# Secrets injected, compose starts, temp files cleaned up

# Use project config file
pqvault docker-secrets --config docker-secrets.toml
```

### Configuration File

```toml
# docker-secrets.toml
[project]
name = "myapp"

[[keys]]
vault_key = "PROD_DATABASE_URL"
env_name = "DATABASE_URL"

[[keys]]
vault_key = "PROD_REDIS_URL"
env_name = "REDIS_URL"

[[keys]]
vault_key = "STRIPE_SECRET_KEY"
env_name = "STRIPE_KEY"

[output]
format = "env"
auto_cleanup = true
```

### MCP Tools

```rust
/// Generate Docker secrets from vault
#[tool(name = "docker_secrets")]
async fn docker_secrets(
    &self,
    #[arg(description = "Project name or tag filter")] project: String,
    #[arg(description = "Output format: env, swarm, buildkit, compose")] format: Option<String>,
    #[arg(description = "Key mappings (vault_key:env_name, comma-separated)")] mappings: Option<String>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

### Web UI Changes

- Docker integration setup page with format selector
- Copy-to-clipboard for generated .env content
- Project secret configuration editor
- Docker Compose snippet generator

## Dependencies

- `tempfile = "3"` — Secure temporary file creation (existing or new)
- `clap = "4"` (existing) — CLI argument parsing
- `pqvault-core` (existing) — Vault access

## Testing

### Unit Tests

```rust
#[test]
fn env_file_format() {
    let output = DockerSecretsOutput {
        format: DockerOutputFormat::EnvFile,
        env_pairs: vec![
            ("DATABASE_URL".into(), "postgres://host/db".into()),
            ("API_KEY".into(), "sk-123".into()),
        ],
        temp_files: vec![],
    };
    let content = output.as_env_file();
    assert!(content.contains("DATABASE_URL=postgres://host/db"));
    assert!(content.contains("API_KEY=sk-123"));
}

#[test]
fn env_file_escapes_special_chars() {
    let output = DockerSecretsOutput {
        format: DockerOutputFormat::EnvFile,
        env_pairs: vec![
            ("PASSWORD".into(), "p@ss'w$rd".into()),
        ],
        temp_files: vec![],
    };
    let content = output.as_env_file();
    assert!(content.contains("'p@ss'\\''w$rd'"));
}

#[test]
fn swarm_commands_generated() {
    let output = DockerSecretsOutput {
        format: DockerOutputFormat::DockerSwarm,
        env_pairs: vec![("STRIPE_KEY".into(), "sk-123".into())],
        temp_files: vec![],
    };
    let cmds = output.as_swarm_commands();
    assert!(cmds[0].contains("docker secret create stripe_key"));
}

#[test]
fn buildkit_flags_generated() {
    let output = DockerSecretsOutput {
        format: DockerOutputFormat::BuildKit,
        env_pairs: vec![("DB_URL".into(), "postgres://".into())],
        temp_files: vec![PathBuf::from("/tmp/pqvault/abc123")],
    };
    let flags = output.as_buildkit_flags();
    assert!(flags.contains("--secret id=db_url,src=/tmp/pqvault/abc123"));
}

#[test]
fn cleanup_removes_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    std::fs::write(&path, "secret_value").unwrap();

    let output = DockerSecretsOutput {
        format: DockerOutputFormat::EnvFile,
        env_pairs: vec![],
        temp_files: vec![path.clone()],
    };
    output.cleanup();
    assert!(!path.exists());
}
```

### Integration Tests

```rust
#[tokio::test]
async fn docker_env_file_generation() {
    let cli = test_cli().await;
    cli.vault.store("PROD_DB", "postgres://localhost/mydb").await.unwrap();
    cli.vault.store("PROD_REDIS", "redis://localhost:6379").await.unwrap();

    let output = cli.docker_secrets("myapp", Some("env"), None).await.unwrap();
    assert!(output.contains("PROD_DB=postgres://localhost/mydb"));
    assert!(output.contains("PROD_REDIS=redis://localhost:6379"));
}
```

### Manual Verification

1. Generate .env file, use with `docker-compose up`
2. Generate BuildKit secrets, use in `docker build`
3. Verify temp files are cleaned up after use
4. Check that secrets are not visible in container inspect
5. Verify audit log records Docker secrets access

## Example Usage

```bash
# Development workflow:
pqvault docker-secrets --project myapp --format env > .env
docker-compose up -d

# Production workflow with auto-cleanup:
pqvault docker-secrets --project myapp --format env --exec \
  docker-compose -f docker-compose.prod.yml up -d

# Build with secrets (never committed to image layer):
docker build \
  $(pqvault docker-secrets --project myapp --format buildkit) \
  --no-cache -t myapp:latest .

# In Dockerfile:
# RUN --mount=type=secret,id=database_url \
#     cat /run/secrets/database_url | ./init-db.sh
```
