# Feature 007: Shell Completions

## Status: Done
## Phase: 1 (v2.1)
## Priority: Medium

## Problem

The PQVault CLI has a growing number of commands, subcommands, and flags. Without tab-completion, users must memorize exact command names and flags, or repeatedly reference `--help` output. This increases friction and slows down daily usage. Every modern CLI tool (kubectl, gh, cargo, docker) ships shell completions.

## Solution

`pqvault completions bash|zsh|fish` generates shell completion scripts using `clap_complete`. Users source the generated script in their shell profile. Completions cover all subcommands, flags, and where possible, dynamic values like key names and project names.

## Implementation

### Files to Create/Modify

- `crates/pqvault-cli/src/completions.rs` — Completion generation logic
- `crates/pqvault-cli/src/main.rs` — Add `Completions` subcommand and wire up clap_complete
- `crates/pqvault-cli/src/cli.rs` — Extract CLI definition to allow reuse by clap_complete

### Data Model Changes

No data model changes. This is purely a CLI UX feature.

### MCP Tools

Not applicable — shell completions are a CLI-only feature.

### CLI Commands

```bash
# Generate completions for your shell
pqvault completions bash    # Bash completions
pqvault completions zsh     # Zsh completions
pqvault completions fish    # Fish completions

# Install for bash (add to ~/.bashrc)
pqvault completions bash >> ~/.bashrc
# Or to a system-wide location
pqvault completions bash > /etc/bash_completion.d/pqvault

# Install for zsh (add to ~/.zshrc)
pqvault completions zsh > "${fpath[1]}/_pqvault"
# Or inline
echo 'eval "$(pqvault completions zsh)"' >> ~/.zshrc

# Install for fish
pqvault completions fish > ~/.config/fish/completions/pqvault.fish
```

### Web UI Changes

Not applicable.

## Core Implementation

```rust
// crates/pqvault-cli/src/completions.rs

use clap::Command;
use clap_complete::{generate, Shell};
use std::io;

/// Generate shell completion script to stdout
pub fn generate_completions(shell: Shell, cmd: &mut Command) {
    let name = cmd.get_name().to_string();
    generate(shell, cmd, &name, &mut io::stdout());
}
```

### CLI Definition (extracting for reuse)

```rust
// crates/pqvault-cli/src/cli.rs

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "pqvault", version, about = "Quantum-proof secrets manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Add a new secret to the vault
    Add {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        value: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },

    /// Get a secret value
    Get {
        /// Secret name
        name: String,
        /// Copy to clipboard instead of printing
        #[arg(short, long)]
        clipboard: bool,
    },

    /// List all secrets
    List {
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
        #[arg(long)]
        format: Option<OutputFormat>,
    },

    /// Delete a secret
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },

    /// Search secrets
    Search {
        query: String,
    },

    /// Import secrets from .env file
    Import {
        file: String,
        #[arg(short, long)]
        project: Option<String>,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        shred: bool,
    },

    /// Export secrets
    Export {
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        format: ExportFormat,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Run command with secrets as env vars
    Run {
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        key: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Scan directory for hardcoded secrets
    Scan {
        directory: String,
        #[arg(long)]
        format: Option<OutputFormat>,
        #[arg(long)]
        pre_commit: bool,
    },

    /// Rotate secrets
    Rotate {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        all: bool,
    },

    /// Show vault status and health
    Status,

    /// Start web dashboard
    Web {
        #[arg(short, long, default_value = "3000")]
        port: u16,
        #[arg(long)]
        setup_auth: bool,
        #[arg(long)]
        disable_auth: bool,
    },

    /// View audit log
    Audit {
        #[arg(long)]
        tail: Option<usize>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[command(subcommand)]
        subcommand: Option<AuditSubcommand>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(ValueEnum, Clone)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(ValueEnum, Clone)]
pub enum ExportFormat {
    Env,
    Json,
    Yaml,
    Docker,
}

#[derive(Subcommand)]
pub enum AuditSubcommand {
    Migrate,
    Rotate,
    Export {
        #[arg(long)]
        format: OutputFormat,
        #[arg(short, long)]
        output: String,
    },
}
```

### Main integration

```rust
// crates/pqvault-cli/src/main.rs

use clap::Parser;
use cli::{Cli, Commands};

mod cli;
mod completions;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            completions::generate_completions(shell, &mut cmd);
        }
        // ... other commands
    }
}
```

## Dependencies

- `clap_complete = "4"` — Shell completion generation for clap-based CLIs
- Uses existing `clap = "4"` dependency

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses_completions_bash() {
        let cli = Cli::try_parse_from(["pqvault", "completions", "bash"]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::Completions { shell } => assert_eq!(shell, Shell::Bash),
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_cli_parses_completions_zsh() {
        let cli = Cli::try_parse_from(["pqvault", "completions", "zsh"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parses_completions_fish() {
        let cli = Cli::try_parse_from(["pqvault", "completions", "fish"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_completions_generates_output() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        clap_complete::generate(Shell::Bash, &mut cmd, "pqvault", &mut output);
        let script = String::from_utf8(output).unwrap();
        assert!(script.contains("pqvault"));
        assert!(script.contains("completions"));
        assert!(script.contains("add"));
        assert!(script.contains("get"));
    }

    #[test]
    fn test_cli_definition_valid() {
        // Verify the CLI definition doesn't have conflicts
        Cli::command().debug_assert();
    }
}
```

### Integration Tests

```rust
#[test]
fn test_completions_binary_output() {
    let output = Command::new(pqvault_binary())
        .args(["completions", "bash"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete"));
    assert!(stdout.contains("pqvault"));
}

#[test]
fn test_completions_zsh_output() {
    let output = Command::new(pqvault_binary())
        .args(["completions", "zsh"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("compdef") || stdout.contains("_pqvault"));
}
```

### Manual Verification

1. Generate bash completions: `pqvault completions bash > /tmp/pqvault.bash`
2. Source it: `source /tmp/pqvault.bash`
3. Type `pqvault <TAB>` — should show all subcommands
4. Type `pqvault add --<TAB>` — should show `--name`, `--value`, `--category`, `--project`
5. Repeat for zsh and fish

## Example Usage

```bash
# Generate and install bash completions
$ pqvault completions bash >> ~/.bashrc
$ source ~/.bashrc

# Now tab completion works:
$ pqvault <TAB>
add     completions  delete  export  get     import  list
rotate  run          scan    search  status  web     audit

$ pqvault add --<TAB>
--name      --value     --category  --project

$ pqvault run --<TAB>
--project   --key       --dry-run   --shell

$ pqvault export --format <TAB>
env    json   yaml   docker

# For zsh users (one-time setup)
$ mkdir -p ~/.zsh/completions
$ pqvault completions zsh > ~/.zsh/completions/_pqvault
$ echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
$ echo 'autoload -Uz compinit && compinit' >> ~/.zshrc
$ source ~/.zshrc

# For fish users
$ pqvault completions fish > ~/.config/fish/completions/pqvault.fish
```
