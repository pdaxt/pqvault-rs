# Feature 070: Config File Support

## Status: Done
## Phase: 7 (v2.7)
## Priority: Low

## Problem

PQVault has no persistent configuration. Users must pass flags repeatedly for common
settings: `--vault-path`, `--format json`, `--no-color`. Default behaviors like
auto-rotation intervals, backup frequency, and preferred editor cannot be customized
without environment variables or shell aliases that are fragile and non-portable.

## Solution

Support a `~/.pqvault/config.toml` configuration file for persistent defaults. The
config uses TOML format for readability and supports per-project overrides via a
`.pqvault.toml` file in the project root (similar to `.cargo/config.toml`). CLI flags
always override config file values.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    config/
      mod.rs           # Config module root
      schema.rs        # Config struct definitions
      loader.rs        # Config file discovery and loading
      merge.rs         # Merge logic: CLI > project > user > defaults
      validate.rs      # Configuration validation
```

### Data Model Changes

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct PqvaultConfig {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// Display and formatting
    #[serde(default)]
    pub display: DisplayConfig,

    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,

    /// Sync platform configurations
    #[serde(default)]
    pub sync: SyncConfig,

    /// Rotation defaults
    #[serde(default)]
    pub rotation: RotationConfig,

    /// Backup settings
    #[serde(default)]
    pub backup: BackupConfig,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GeneralConfig {
    /// Default vault path
    #[serde(default = "default_vault_path")]
    pub vault_path: PathBuf,

    /// Preferred editor for `pqvault edit`
    pub editor: Option<String>,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Default output format: text, json, yaml
    #[serde(default = "default_format")]
    pub format: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DisplayConfig {
    /// Disable colors in output
    #[serde(default)]
    pub no_color: bool,

    /// Date format string
    #[serde(default = "default_date_format")]
    pub date_format: String,

    /// Show secret values masked by default
    #[serde(default = "default_true")]
    pub mask_values: bool,

    /// Number of mask characters
    #[serde(default = "default_mask_len")]
    pub mask_length: usize,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecurityConfig {
    /// Auto-lock vault after N seconds of inactivity
    pub auto_lock_seconds: Option<u64>,

    /// Clipboard auto-clear after N seconds
    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_seconds: u64,

    /// Require confirmation for destructive operations
    #[serde(default = "default_true")]
    pub confirm_destructive: bool,

    /// Minimum key entropy threshold
    #[serde(default = "default_min_entropy")]
    pub min_entropy_bits: u32,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct SyncConfig {
    /// Vercel API token
    pub vercel_token: Option<String>,
    /// Netlify API token
    pub netlify_token: Option<String>,
    /// Railway API token
    pub railway_token: Option<String>,
    /// Default sync direction
    #[serde(default)]
    pub default_direction: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RotationConfig {
    /// Default rotation interval in days
    #[serde(default = "default_rotation_days")]
    pub default_interval_days: u32,
    /// Auto-rotation enabled
    #[serde(default)]
    pub auto_rotate: bool,
    /// Notify N days before expiry
    #[serde(default = "default_notify_days")]
    pub notify_before_days: u32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BackupConfig {
    /// Backup directory
    pub backup_dir: Option<PathBuf>,
    /// Keep N most recent backups
    #[serde(default = "default_backup_count")]
    pub keep_count: usize,
    /// Auto-backup before destructive operations
    #[serde(default = "default_true")]
    pub auto_backup: bool,
}

fn default_vault_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".pqvault")
}
fn default_format() -> String { "text".into() }
fn default_date_format() -> String { "%Y-%m-%d %H:%M".into() }
fn default_true() -> bool { true }
fn default_mask_len() -> usize { 8 }
fn default_clipboard_clear() -> u64 { 30 }
fn default_min_entropy() -> u32 { 64 }
fn default_rotation_days() -> u32 { 90 }
fn default_notify_days() -> u32 { 14 }
fn default_backup_count() -> usize { 10 }
```

Config loading with precedence:

```rust
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load config with precedence: CLI flags > project > user > defaults
    pub fn load(cli_overrides: &CliOverrides) -> Result<PqvaultConfig> {
        let mut config = PqvaultConfig::default();

        // 1. User-level config
        let user_config_path = dirs::home_dir()
            .unwrap_or_default()
            .join(".pqvault")
            .join("config.toml");
        if user_config_path.exists() {
            let user_config: PqvaultConfig = toml::from_str(
                &std::fs::read_to_string(&user_config_path)?
            )?;
            config = merge_config(config, user_config);
        }

        // 2. Project-level config (walk up from cwd)
        if let Some(project_path) = find_project_config() {
            let project_config: PqvaultConfig = toml::from_str(
                &std::fs::read_to_string(&project_path)?
            )?;
            config = merge_config(config, project_config);
        }

        // 3. CLI overrides (highest precedence)
        config = apply_cli_overrides(config, cli_overrides);

        validate_config(&config)?;
        Ok(config)
    }

    fn find_project_config() -> Option<PathBuf> {
        let mut dir = std::env::current_dir().ok()?;
        loop {
            let config_path = dir.join(".pqvault.toml");
            if config_path.exists() {
                return Some(config_path);
            }
            if !dir.pop() {
                return None;
            }
        }
    }
}
```

### MCP Tools

No new MCP tools. Configuration is a CLI/core concern.

### CLI Commands

```bash
# Show current effective config
pqvault config show

# Show where config is loaded from
pqvault config path

# Set a config value
pqvault config set general.editor "code --wait"

# Get a config value
pqvault config get security.auto_lock_seconds

# Initialize config file with defaults
pqvault config init

# Validate config file
pqvault config validate
```

### Web UI Changes

None. Web UI has its own preferences system.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `toml` | 0.8 | TOML parsing and serialization |
| `dirs` | 5 | Cross-platform home directory detection |

Add to `pqvault-core/Cargo.toml`:

```toml
[dependencies]
toml = "0.8"
dirs = "5"
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PqvaultConfig::default();
        assert_eq!(config.display.mask_values, true);
        assert_eq!(config.security.clipboard_clear_seconds, 30);
        assert_eq!(config.rotation.default_interval_days, 90);
    }

    #[test]
    fn test_parse_config_toml() {
        let toml = r#"
[general]
vault_path = "/custom/vault"
editor = "nano"
format = "json"

[display]
no_color = true
date_format = "%d/%m/%Y"

[security]
auto_lock_seconds = 300
clipboard_clear_seconds = 10

[rotation]
default_interval_days = 30
auto_rotate = true
"#;
        let config: PqvaultConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.general.vault_path, PathBuf::from("/custom/vault"));
        assert_eq!(config.general.editor, Some("nano".into()));
        assert!(config.display.no_color);
        assert_eq!(config.security.auto_lock_seconds, Some(300));
        assert_eq!(config.rotation.default_interval_days, 30);
    }

    #[test]
    fn test_config_merge_precedence() {
        let base = PqvaultConfig {
            general: GeneralConfig { format: "text".into(), ..Default::default() },
            ..Default::default()
        };
        let override_cfg = PqvaultConfig {
            general: GeneralConfig { format: "json".into(), ..Default::default() },
            ..Default::default()
        };
        let merged = merge_config(base, override_cfg);
        assert_eq!(merged.general.format, "json");
    }

    #[test]
    fn test_find_project_config() {
        let tmpdir = tempdir().unwrap();
        let config_path = tmpdir.path().join(".pqvault.toml");
        std::fs::write(&config_path, "[general]\nformat = \"yaml\"").unwrap();
        std::env::set_current_dir(tmpdir.path()).unwrap();
        let found = ConfigLoader::find_project_config();
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn test_validate_config_invalid_format() {
        let config = PqvaultConfig {
            general: GeneralConfig { format: "invalid".into(), ..Default::default() },
            ..Default::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err());
    }
}
```

## Example Usage

```toml
# ~/.pqvault/config.toml

[general]
vault_path = "~/.pqvault"
editor = "code --wait"
format = "text"

[display]
no_color = false
date_format = "%Y-%m-%d %H:%M"
mask_values = true
mask_length = 8

[security]
auto_lock_seconds = 600
clipboard_clear_seconds = 15
confirm_destructive = true
min_entropy_bits = 80

[sync]
vercel_token = "pqvault:vercel-token"  # Reference to vault key
default_direction = "push"

[rotation]
default_interval_days = 60
auto_rotate = false
notify_before_days = 7

[backup]
backup_dir = "~/.pqvault/backups"
keep_count = 20
auto_backup = true
```

```
$ pqvault config show

  Effective Configuration
  ────────────────────────

  Source: ~/.pqvault/config.toml (user)
  Override: ./.pqvault.toml (project)

  general.vault_path         ~/.pqvault          (user)
  general.editor             code --wait         (user)
  general.format             json                (project override)
  display.no_color           false               (default)
  security.auto_lock_seconds 600                 (user)
  rotation.default_interval  60                  (user)
```
