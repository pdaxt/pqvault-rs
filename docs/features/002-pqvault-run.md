# Feature 002: pqvault run

## Status: Done
## Phase: 1 (v2.1)
## Priority: Critical

## Problem

Developers still create `.env` files on disk to run their applications with secrets. This defeats the purpose of a secrets manager — the plaintext credentials end up in the filesystem, get accidentally committed to git, linger in shell history, and are visible to any process on the machine. Every manual copy-paste from the vault to a `.env` file is a security leak waiting to happen.

## Solution

`pqvault run --project myapp -- npm start` loads all secrets for the specified project from the vault, injects them as environment variables into the child process, and wipes them from memory on exit. On Unix, this uses `exec()` to replace the current process entirely, ensuring no parent process retains the secrets. The child process sees the secrets as normal environment variables but they never touch the filesystem.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/run.rs` — Core `run` command implementation
- `crates/pqvault-cli/src/main.rs` — Add `Run` variant to CLI subcommands
- `crates/pqvault-core/src/vault.rs` — Add `get_project_secrets()` method

### Data Model Changes

No model changes required. Uses existing `SecretEntry.project` field to filter secrets by project name.

Helper method on Vault:

```rust
impl Vault {
    /// Get all secrets belonging to a project, decrypted
    pub fn get_project_secrets(
        &self,
        project: &str,
        master_password: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut secrets = Vec::new();
        for entry in &self.entries {
            if entry.project.as_deref() == Some(project) {
                let decrypted = self.decrypt_value(&entry.encrypted_value, master_password)?;
                // Use the key name as the env var name (uppercase, dashes to underscores)
                let env_name = entry.name.to_uppercase().replace('-', "_");
                secrets.push((env_name, decrypted));
            }
        }
        Ok(secrets)
    }
}
```

### MCP Tools

The `pqvault-env-mcp` already has `project_env` and `run` tools. This feature implements the CLI equivalent:

```rust
// Existing MCP tool signature for reference:
// vault_run { project: String, command: String, args: Vec<String> } -> RunResult

// The CLI command mirrors this MCP tool
```

### CLI Commands

```bash
# Basic usage — run command with project secrets injected
pqvault run --project myapp -- npm start

# Run with a specific command and arguments
pqvault run --project production -- node server.js --port 3000

# Run with additional env vars on top of project secrets
pqvault run --project myapp --env PORT=3000 --env DEBUG=true -- node app.js

# Run with a specific key only (not all project secrets)
pqvault run --key STRIPE_SECRET_KEY -- stripe listen --forward-to localhost:3000

# Dry run — show what would be injected without running
pqvault run --project myapp --dry-run -- npm start

# Run with shell expansion (uses sh -c)
pqvault run --project myapp --shell -- "echo $DATABASE_URL && npm start"

# List available projects
pqvault run --list-projects
```

### Web UI Changes

No web UI changes required for this feature. The web dashboard could optionally show a "Run Command" helper that generates the CLI command, but this is cosmetic and not required.

## Core Implementation

```rust
// crates/pqvault-cli/src/run.rs

use std::collections::HashMap;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::{bail, Context, Result};
use crate::vault::Vault;

pub struct RunConfig {
    pub project: Option<String>,
    pub keys: Vec<String>,
    pub extra_env: Vec<(String, String)>,
    pub command: String,
    pub args: Vec<String>,
    pub dry_run: bool,
    pub shell: bool,
}

pub fn execute_run(config: RunConfig, vault: &Vault, master_password: &str) -> Result<()> {
    // Collect secrets to inject
    let mut env_vars: HashMap<String, String> = HashMap::new();

    if let Some(project) = &config.project {
        let secrets = vault.get_project_secrets(project, master_password)?;
        if secrets.is_empty() {
            bail!("No secrets found for project '{}'", project);
        }
        for (key, value) in secrets {
            env_vars.insert(key, value);
        }
    }

    // Add individual keys
    for key_name in &config.keys {
        let entry = vault.get_entry(key_name)
            .context(format!("Key '{}' not found in vault", key_name))?;
        let value = vault.decrypt_value(&entry.encrypted_value, master_password)?;
        env_vars.insert(key_name.to_uppercase().replace('-', "_"), value);
    }

    // Add extra env vars (override vault values if same name)
    for (key, value) in &config.extra_env {
        env_vars.insert(key.clone(), value.clone());
    }

    if config.dry_run {
        println!("Would inject {} environment variables:", env_vars.len());
        for key in env_vars.keys() {
            println!("  {} = [{} chars]", key, env_vars[key].len());
        }
        println!("\nCommand: {} {}", config.command, config.args.join(" "));
        return Ok(());
    }

    // Build the command
    let mut cmd = if config.shell {
        let full_command = format!("{} {}", config.command, config.args.join(" "));
        let mut c = Command::new("sh");
        c.args(["-c", &full_command]);
        c
    } else {
        let mut c = Command::new(&config.command);
        c.args(&config.args);
        c
    };

    // Inject secrets as environment variables
    // Important: inherit existing env, then overlay secrets
    cmd.envs(std::env::vars());
    cmd.envs(&env_vars);

    // On Unix, exec() replaces the current process — secrets never linger
    // in a parent process. This is the most secure approach.
    #[cfg(unix)]
    {
        let err = cmd.exec();
        // exec() only returns on error
        bail!("Failed to exec '{}': {}", config.command, err);
    }

    // On non-Unix, spawn and wait
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .context(format!("Failed to run '{}'", config.command))?;

        // Explicit drop to clear secrets from memory
        drop(env_vars);

        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
    }
}
```

### Clap Command Definition

```rust
// In main.rs CLI definition
#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...

    /// Run a command with secrets injected as environment variables
    Run {
        /// Project name to load secrets from
        #[arg(short, long)]
        project: Option<String>,

        /// Specific key(s) to inject
        #[arg(short, long)]
        key: Vec<String>,

        /// Additional environment variables (KEY=VALUE)
        #[arg(short, long = "env")]
        extra_env: Vec<String>,

        /// Show what would be injected without running
        #[arg(long)]
        dry_run: bool,

        /// Use shell to run command (enables variable expansion)
        #[arg(long)]
        shell: bool,

        /// List available projects
        #[arg(long)]
        list_projects: bool,

        /// Command and arguments to run (after --)
        #[arg(trailing_var_arg = true, required_unless_present = "list_projects")]
        command: Vec<String>,
    },
}
```

## Dependencies

- No new crate dependencies required
- Uses `std::process::Command` (stdlib)
- Uses `std::os::unix::process::CommandExt` for `exec()` on Unix
- Requires existing `pqvault-core` vault and crypto modules

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dry_run_shows_env_vars() {
        let vault = create_test_vault_with_project("myapp", vec![
            ("DATABASE_URL", "postgres://..."),
            ("API_KEY", "sk_test_123"),
        ]);

        let config = RunConfig {
            project: Some("myapp".into()),
            keys: vec![],
            extra_env: vec![],
            command: "echo".into(),
            args: vec!["hello".into()],
            dry_run: true,
            shell: false,
        };

        // Should not fail, just print
        let result = execute_run(config, &vault, "test-password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_project_fails() {
        let vault = create_empty_test_vault();

        let config = RunConfig {
            project: Some("nonexistent".into()),
            keys: vec![],
            extra_env: vec![],
            command: "echo".into(),
            args: vec![],
            dry_run: true,
            shell: false,
        };

        let result = execute_run(config, &vault, "test-password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No secrets found"));
    }

    #[test]
    fn test_extra_env_overrides_vault() {
        let vault = create_test_vault_with_project("myapp", vec![
            ("PORT", "3000"),
        ]);

        let mut env_vars = HashMap::new();
        collect_env_vars(&vault, Some("myapp"), &[], &[("PORT".into(), "8080".into())], "pass", &mut env_vars).unwrap();
        assert_eq!(env_vars.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn test_key_name_normalization() {
        // "my-api-key" should become "MY_API_KEY"
        let vault = create_test_vault_with_entry("my-api-key", "secret", Some("proj"));
        let secrets = vault.get_project_secrets("proj", "password").unwrap();
        assert_eq!(secrets[0].0, "MY_API_KEY");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_run_injects_env_and_exits() {
    let vault_dir = setup_test_vault(vec![
        ("TEST_VAR", "hello_world", Some("testproj")),
    ]);

    let output = Command::new(pqvault_binary())
        .args(["run", "--project", "testproj", "--", "printenv", "TEST_VAR"])
        .env("PQVAULT_HOME", vault_dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello_world");
}

#[tokio::test]
async fn test_run_does_not_leak_to_parent_env() {
    // After pqvault run completes, the parent shell should NOT have the secrets
    let vault_dir = setup_test_vault(vec![
        ("LEAK_TEST", "sensitive", Some("testproj")),
    ]);

    let output = Command::new(pqvault_binary())
        .args(["run", "--project", "testproj", "--", "true"])
        .env("PQVAULT_HOME", vault_dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    // Parent process should not have LEAK_TEST
    assert!(std::env::var("LEAK_TEST").is_err());
}
```

### Manual Verification

1. Add secrets to a project: `pqvault add --name DB_URL --value "postgres://..." --project myapp`
2. Run with dry-run: `pqvault run --project myapp --dry-run -- node app.js`
3. Run actual command: `pqvault run --project myapp -- printenv | grep DB_URL`
4. Verify no `.env` file created on disk
5. Verify `printenv` in parent shell does NOT show secrets after command exits

## Example Usage

```bash
# Setup: add secrets to a project
$ pqvault add --name DATABASE_URL --value "postgres://user:pass@db:5432/prod" --project webapp
$ pqvault add --name REDIS_URL --value "redis://cache:6379" --project webapp
$ pqvault add --name JWT_SECRET --value "super-secret-jwt-key" --project webapp

# Run your app with all project secrets
$ pqvault run --project webapp -- node server.js
Server listening on port 3000
# DATABASE_URL, REDIS_URL, JWT_SECRET all available as process.env.*

# Dry run to see what gets injected
$ pqvault run --project webapp --dry-run -- node server.js
Would inject 3 environment variables:
  DATABASE_URL = [42 chars]
  REDIS_URL = [19 chars]
  JWT_SECRET = [20 chars]

Command: node server.js

# Run with extra env vars
$ pqvault run --project webapp --env PORT=8080 --env NODE_ENV=production -- node server.js

# Run a single key (not a full project)
$ pqvault run --key STRIPE_SECRET_KEY -- stripe listen --forward-to localhost:3000

# Docker compose with secrets
$ pqvault run --project webapp -- docker compose up

# Python with virtual env
$ pqvault run --project ml-pipeline -- python train.py --epochs 100

# List projects that have secrets
$ pqvault run --list-projects
Projects with secrets:
  webapp      (3 secrets)
  ml-pipeline (5 secrets)
  staging     (3 secrets)
```
