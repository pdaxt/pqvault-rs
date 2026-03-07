use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

use pqvault_core::env_gen::get_project_secrets;
use pqvault_core::health::check_health;
use pqvault_core::models::{self, auto_categorize, SecretEntry};
use pqvault_core::vault;

#[derive(Parser)]
#[command(name = "pqvault", version = "2.1.0")]
#[command(about = "Quantum-proof centralized secrets management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init,
    /// Show vault status
    Status,
    /// List all secrets
    List {
        /// Filter by project
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Get a secret value
    Get {
        /// Key name
        key: String,
    },
    /// Add a secret
    Add {
        /// Key name
        key: String,
        /// Secret value
        value: String,
        /// Category
        #[arg(short, long)]
        category: Option<String>,
        /// Project to associate with
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Key name
        key: String,
    },
    /// Check vault health
    Health,
    /// Run a command with project secrets injected as environment variables
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
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Import secrets from a .env file
    Import {
        /// Path to .env file (use - for stdin)
        file: PathBuf,
        /// Project to associate imported secrets with
        #[arg(short, long)]
        project: Option<String>,
        /// Overwrite existing keys
        #[arg(long)]
        overwrite: bool,
        /// Show what would be imported without actually importing
        #[arg(long)]
        dry_run: bool,
        /// Shred (securely delete) the source file after import
        #[arg(long)]
        shred: bool,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Scan a directory for leaked secrets
    Scan {
        /// Directory to scan (defaults to current directory)
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Only show findings (no summary)
        #[arg(long)]
        quiet: bool,
    },
    /// Change key lifecycle state (deprecate, disable, archive, restore)
    Lifecycle {
        /// Key name
        key: String,
        /// Target state: deprecate, disable, archive, restore
        action: String,
        /// Reason for the change
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Rotate a secret (store old value in version history)
    Rotate {
        /// Key name
        key: String,
        /// New secret value
        value: String,
        /// Reason for rotation
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Show version history for a secret
    History {
        /// Key name
        key: String,
        /// Show full values (default: masked)
        #[arg(long)]
        full: bool,
    },
    /// Check which keys need rotation
    CheckRotation {
        /// Show all keys, not just those needing rotation
        #[arg(long)]
        all: bool,
    },
    /// Set rotation policy for a key
    SetPolicy {
        /// Key name
        key: String,
        /// Rotation interval in days
        #[arg(short, long)]
        days: i64,
        /// Enable auto-rotation (requires provider support)
        #[arg(long)]
        auto: bool,
        /// Notify this many days before due
        #[arg(long, default_value_t = 7)]
        notify_before: i64,
    },
    /// Rollback a key to a previous version
    Rollback {
        /// Key name
        key: String,
        /// Version number to rollback to (from `pqvault history`)
        #[arg(short, long)]
        version: Option<usize>,
    },
    /// Create an agent token with scoped access
    AgentCreate {
        /// Agent name
        name: String,
        /// Allowed key names (comma-separated, * for all)
        #[arg(short = 'k', long)]
        keys: Option<String>,
        /// Allowed categories (comma-separated, * for all)
        #[arg(short = 'c', long)]
        categories: Option<String>,
        /// Token expiry in hours
        #[arg(short, long)]
        expires: Option<i64>,
        /// Monthly budget cap in USD
        #[arg(short, long)]
        budget: Option<f64>,
        /// Max requests per hour
        #[arg(long)]
        rate_limit: Option<u32>,
    },
    /// List agent tokens
    AgentList,
    /// Revoke an agent token
    AgentRevoke {
        /// Agent ID
        id: String,
    },
    /// Search secrets using natural language (fuzzy matching)
    Search {
        /// Search query (e.g., "stripe production key")
        query: String,
        /// Minimum relevance score (default: 1.0)
        #[arg(long, default_value_t = 1.0)]
        min_score: f64,
        /// Maximum results (default: 10)
        #[arg(short, long, default_value_t = 10)]
        limit: usize,
    },
    /// Compare secrets between two projects
    Diff {
        /// First project
        project_a: String,
        /// Second project
        project_b: String,
    },
    /// Show secret tree organized by category and project
    Tree,
    /// Analyze entropy of all secret values
    Entropy,
    /// Tag a secret
    Tag {
        /// Key name
        key: String,
        /// Tags to add (comma-separated)
        #[arg(short, long)]
        add: Option<String>,
        /// Tags to remove (comma-separated)
        #[arg(short, long)]
        remove: Option<String>,
    },
    /// Comprehensive vault health check
    Doctor,
    /// Export secrets for a project
    Export {
        /// Project name
        #[arg(short, long)]
        project: Option<String>,
        /// Output format: env, json, docker
        #[arg(short, long, default_value = "env")]
        format: String,
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn require_vault() -> Result<models::VaultData> {
    if !vault::vault_exists() {
        bail!("No vault found. Run 'pqvault init' first.");
    }
    Ok(vault::open_vault()?)
}

/// Calculate Shannon entropy of a string (bits per character)
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    let len = s.len() as f64;
    for c in s.chars() {
        *freq.entry(c).or_insert(0u64) += 1;
    }
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn parse_env_content(content: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let (key, raw_value) = match trimmed.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.to_string()),
            None => continue,
        };
        if !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let value = parse_env_value(&raw_value);
        entries.push((key, value));
    }
    entries
}

fn parse_env_value(raw: &str) -> String {
    let trimmed = raw.trim();
    // Double-quoted
    if trimmed.starts_with('"') {
        let inner = &trimmed[1..];
        if let Some(end) = inner.find('"') {
            return inner[..end]
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
        return inner
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
    // Single-quoted
    if trimmed.starts_with('\'') {
        let inner = &trimmed[1..];
        if let Some(end) = inner.find('\'') {
            return inner[..end].to_string();
        }
        return inner.to_string();
    }
    // Unquoted: strip inline comments
    if let Some(comment_start) = trimmed.find(" #") {
        trimmed[..comment_start].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

/// Secret patterns for scanning
fn secret_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        // API Keys
        (r"sk_live_[a-zA-Z0-9]{20,}", "Stripe Secret Key"),
        (r"sk_test_[a-zA-Z0-9]{20,}", "Stripe Test Key"),
        (r"pk_live_[a-zA-Z0-9]{20,}", "Stripe Publishable Key"),
        (r"rk_live_[a-zA-Z0-9]{20,}", "Stripe Restricted Key"),
        (r"whsec_[a-zA-Z0-9]{20,}", "Stripe Webhook Secret"),
        // AWS
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r#"(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#, "AWS Secret Access Key"),
        // GitHub
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
        (r"ghs_[a-zA-Z0-9]{36}", "GitHub App Token"),
        (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token"),
        (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub Fine-Grained PAT"),
        // Google
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        // Anthropic
        (r"sk-ant-[a-zA-Z0-9\-_]{40,}", "Anthropic API Key"),
        // OpenAI
        (r"sk-[a-zA-Z0-9]{48,}", "OpenAI API Key"),
        // Slack
        (r"xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}", "Slack Bot Token"),
        (r"xoxp-[0-9]{10,}-[a-zA-Z0-9]{20,}", "Slack User Token"),
        (r"xapp-[0-9]{1,}-[a-zA-Z0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}", "Slack App Token"),
        // SendGrid / Resend
        (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "SendGrid API Key"),
        (r"re_[a-zA-Z0-9]{20,}", "Resend API Key"),
        // Twilio
        (r"SK[0-9a-fA-F]{32}", "Twilio API Key"),
        // Database URLs with passwords
        (r"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@[^\s]+", "Database URL with Password"),
        // Generic high-entropy secrets
        (r#"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"][a-zA-Z0-9+/=_\-]{20,}['"]"#, "Generic API Key/Secret"),
        // Private keys
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
        // JWT
        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JSON Web Token"),
    ]
}

/// Directories to always skip
fn skip_dirs() -> Vec<&'static str> {
    vec![
        ".git", "node_modules", "target", ".next", "__pycache__",
        "venv", ".venv", "dist", "build", ".cargo", ".rustup",
        "vendor", "bower_components", ".tox", ".mypy_cache",
    ]
}

/// File extensions to skip (binary files)
fn skip_extensions() -> Vec<&'static str> {
    vec![
        "png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "bmp",
        "mp3", "mp4", "avi", "mov", "mkv", "wav", "flac",
        "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        "woff", "woff2", "ttf", "eot", "otf",
        "pdf", "doc", "docx", "xls", "xlsx",
        "exe", "dll", "so", "dylib", "o", "a",
        "pyc", "pyo", "class", "jar",
        "enc", "bin", "dat",
    ]
}

fn scan_directory(dir: &std::path::Path, quiet: bool) -> Result<()> {
    use regex::Regex;
    use std::fs;

    if !dir.exists() {
        bail!("Directory not found: {}", dir.display());
    }

    let patterns: Vec<(Regex, &str)> = secret_patterns()
        .into_iter()
        .filter_map(|(pat, name)| Regex::new(pat).ok().map(|r| (r, name)))
        .collect();

    let skip_d: Vec<&str> = skip_dirs();
    let skip_ext: Vec<&str> = skip_extensions();

    let mut findings: Vec<(String, usize, String, String)> = Vec::new(); // (file, line, type, match)
    let mut files_scanned = 0usize;

    fn walk(
        path: &std::path::Path,
        patterns: &[(Regex, &str)],
        skip_d: &[&str],
        skip_ext: &[&str],
        findings: &mut Vec<(String, usize, String, String)>,
        files_scanned: &mut usize,
    ) {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if skip_d.contains(&name.as_str()) || name.starts_with('.') {
                    continue;
                }
                walk(&path, patterns, skip_d, skip_ext, findings, files_scanned);
                continue;
            }

            // Skip binary/media files
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if skip_ext.contains(&ext.to_lowercase().as_str()) {
                    continue;
                }
            }

            // Skip large files (>1MB)
            if let Ok(meta) = fs::metadata(&path) {
                if meta.len() > 1_048_576 {
                    continue;
                }
            }

            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue, // Skip non-UTF8 files
            };

            *files_scanned += 1;

            for (line_num, line) in content.lines().enumerate() {
                for (regex, label) in patterns {
                    if let Some(m) = regex.find(line) {
                        let matched = m.as_str();
                        // Mask the match for display
                        let display = if matched.len() > 12 {
                            format!("{}...{}", &matched[..6], &matched[matched.len()-4..])
                        } else {
                            "*".repeat(matched.len())
                        };
                        findings.push((
                            path.display().to_string(),
                            line_num + 1,
                            label.to_string(),
                            display,
                        ));
                    }
                }
            }
        }
    }

    walk(dir, &patterns, &skip_d, &skip_ext, &mut findings, &mut files_scanned);

    if findings.is_empty() {
        if !quiet {
            println!("No secrets found in {} ({} files scanned)", dir.display(), files_scanned);
        }
        return Ok(());
    }

    // Sort by file then line
    findings.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    for (file, line, label, matched) in &findings {
        println!("{}:{} [{}] {}", file, line, label, matched);
    }

    if !quiet {
        // Summary by type
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for (_, _, label, _) in &findings {
            *by_type.entry(label.clone()).or_insert(0) += 1;
        }
        println!("\n--- Scan Summary ---");
        println!("Files scanned: {}", files_scanned);
        println!("Secrets found: {}", findings.len());
        let mut sorted: Vec<_> = by_type.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (label, count) in sorted {
            println!("  {}: {}", label, count);
        }
    }

    // Exit with code 1 if findings (useful for CI)
    std::process::exit(1);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if vault::vault_exists() {
                eprintln!("Vault already exists at ~/.pqvault/");
                return Ok(());
            }
            let pw = vault::init_vault()?;
            eprintln!("Vault initialized. Master password stored in macOS Keychain.");
            eprintln!("Backup password: {}", pw);
            Ok(())
        }
        Commands::Status => {
            let data = require_vault()?;
            let report = check_health(&data);
            println!("Total Secrets: {}", report.total_secrets);
            println!("Projects: {}", data.projects.len());
            println!(
                "Health: {}",
                if report.is_healthy() {
                    "HEALTHY"
                } else {
                    "ISSUES FOUND"
                }
            );
            if !report.expired.is_empty() {
                println!("Expired: {}", report.expired.join(", "));
            }
            if !report.needs_rotation.is_empty() {
                println!("Needs Rotation: {}", report.needs_rotation.join(", "));
            }
            Ok(())
        }
        Commands::List { project } => {
            let data = require_vault()?;
            let mut keys: Vec<&String> = data.secrets.keys().collect();
            keys.sort();
            for k in keys {
                let s = &data.secrets[k];
                if let Some(ref proj) = project {
                    if !s.projects.contains(proj) {
                        // Also check ProjectEntry.keys
                        let in_project_entry = data
                            .projects
                            .get(proj)
                            .map_or(false, |p| p.keys.contains(k));
                        if !in_project_entry {
                            continue;
                        }
                    }
                }
                let lifecycle_tag = if s.lifecycle != "active" {
                    format!(" ({})", s.lifecycle)
                } else {
                    String::new()
                };
                println!(
                    "{} [{}] projects={} rotated={}{}",
                    k,
                    s.category,
                    s.projects.join(","),
                    s.rotated,
                    lifecycle_tag
                );
            }
            Ok(())
        }
        Commands::Get { key } => {
            let data = require_vault()?;
            match data.secrets.get(&key) {
                Some(s) => println!("{}", s.value),
                None => eprintln!("Key not found: {}", key),
            }
            Ok(())
        }
        Commands::Add {
            key,
            value,
            category,
            project,
        } => {
            let mut data = require_vault()?;
            let cat = category.unwrap_or_else(|| auto_categorize(&key));
            let projects = match project {
                Some(ref p) => vec![p.clone()],
                None => vec![],
            };
            data.secrets.insert(
                key.clone(),
                SecretEntry {
                    value,
                    category: cat.clone(),
                    description: String::new(),
                    created: chrono::Local::now().format("%Y-%m-%d").to_string(),
                    rotated: chrono::Local::now().format("%Y-%m-%d").to_string(),
                    expires: None,
                    rotation_days: 90,
                    projects,
                    tags: vec![],
                    account: None,
                    environment: None,
                    related_keys: vec![],
                    last_verified: None,
                    last_error: None,
                    key_status: "unknown".to_string(),
                    lifecycle: "active".to_string(),
                    lifecycle_reason: None,
                    lifecycle_changed: None,
                    versions: vec![],
                    max_versions: 10,
                    rotation_policy: None,
                },
            );
            vault::save_vault(&data)?;
            println!("Added: {} [{}]", key, cat);
            Ok(())
        }
        Commands::Delete { key } => {
            let mut data = require_vault()?;
            if data.secrets.remove(&key).is_some() {
                for proj in data.projects.values_mut() {
                    proj.keys.retain(|k| k != &key);
                }
                vault::save_vault(&data)?;
                println!("Deleted: {}", key);
            } else {
                eprintln!("Key not found: {}", key);
            }
            Ok(())
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "pqvault", &mut std::io::stdout());
            Ok(())
        }
        Commands::Scan { dir, quiet } => {
            scan_directory(&dir, quiet)
        }
        Commands::Health => {
            let data = require_vault()?;
            let report = check_health(&data);
            println!("Total: {} secrets", report.total_secrets);
            if report.is_healthy() {
                println!("Status: HEALTHY");
            } else {
                if !report.expired.is_empty() {
                    println!("EXPIRED: {}", report.expired.join(", "));
                }
                if !report.needs_rotation.is_empty() {
                    println!("NEEDS ROTATION: {}", report.needs_rotation.join(", "));
                }
            }
            Ok(())
        }
        Commands::Run {
            project,
            key,
            extra_env,
            dry_run,
            shell,
            list_projects,
            command,
        } => {
            let data = require_vault()?;

            if list_projects {
                // Collect projects from project entries and secret.projects fields
                let mut project_counts: HashMap<String, usize> = HashMap::new();
                for proj_name in data.projects.keys() {
                    let count = get_project_secrets(&data, proj_name).len();
                    if count > 0 {
                        project_counts.insert(proj_name.clone(), count);
                    }
                }
                // Also check secrets with project fields
                for (_k, s) in &data.secrets {
                    for p in &s.projects {
                        project_counts.entry(p.clone()).or_insert(0);
                        *project_counts.get_mut(p).unwrap() += 0; // just ensure entry exists
                    }
                }
                if project_counts.is_empty() {
                    println!("No projects with secrets found.");
                } else {
                    println!("Projects with secrets:");
                    let mut sorted: Vec<_> = project_counts.iter().collect();
                    sorted.sort_by_key(|(name, _)| name.to_string());
                    for (name, count) in sorted {
                        println!("  {:20} ({} secrets)", name, count);
                    }
                }
                return Ok(());
            }

            if command.is_empty() {
                bail!("No command specified. Usage: pqvault run --project myapp -- npm start");
            }

            let mut env_vars: HashMap<String, String> = HashMap::new();

            // Load project secrets
            if let Some(ref proj) = project {
                let secrets = get_project_secrets(&data, proj);
                if secrets.is_empty() {
                    bail!("No secrets found for project '{}'", proj);
                }
                for (k, v) in secrets {
                    env_vars.insert(k, v);
                }
            }

            // Load individual keys
            for key_name in &key {
                match data.secrets.get(key_name) {
                    Some(s) => {
                        env_vars.insert(key_name.clone(), s.value.clone());
                    }
                    None => bail!("Key '{}' not found in vault", key_name),
                }
            }

            // Parse extra env vars
            for kv in &extra_env {
                if let Some((k, v)) = kv.split_once('=') {
                    env_vars.insert(k.to_string(), v.to_string());
                }
            }

            if env_vars.is_empty() {
                bail!("No secrets to inject. Specify --project or --key.");
            }

            if dry_run {
                println!("Would inject {} environment variables:", env_vars.len());
                let mut sorted_keys: Vec<&String> = env_vars.keys().collect();
                sorted_keys.sort();
                for k in sorted_keys {
                    println!("  {} = [{} chars]", k, env_vars[k].len());
                }
                println!(
                    "\nCommand: {}",
                    command.join(" ")
                );
                return Ok(());
            }

            // Build and execute the command
            let (cmd_name, cmd_args) = if shell {
                ("sh".to_string(), vec!["-c".to_string(), command.join(" ")])
            } else {
                (command[0].clone(), command[1..].to_vec())
            };

            let mut cmd = std::process::Command::new(&cmd_name);
            cmd.args(&cmd_args);
            cmd.envs(std::env::vars());
            cmd.envs(&env_vars);

            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = cmd.exec();
                bail!("Failed to exec '{}': {}", cmd_name, err);
            }

            #[cfg(not(unix))]
            {
                let status = cmd.status()?;
                drop(env_vars);
                if !status.success() {
                    std::process::exit(status.code().unwrap_or(1));
                }
                Ok(())
            }
        }
        Commands::Import {
            file,
            project,
            overwrite,
            dry_run,
            shred,
        } => {
            let mut data = require_vault()?;

            let content = if file.to_string_lossy() == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&file)?
            };

            let entries = parse_env_content(&content);
            if entries.is_empty() {
                println!("No entries found.");
                return Ok(());
            }

            let mut added = 0usize;
            let mut skipped = 0usize;
            let mut updated = 0usize;

            for (key, value) in &entries {
                let exists = data.secrets.contains_key(key);
                let cat = auto_categorize(key);

                if exists && !overwrite {
                    if dry_run {
                        println!("  SKIP {} (already exists)", key);
                    }
                    skipped += 1;
                    continue;
                }

                if dry_run {
                    let action = if exists { "OVERWRITE" } else { "ADD" };
                    println!("  {} {} [{}] ({} chars)", action, key, cat, value.len());
                    if exists {
                        updated += 1;
                    } else {
                        added += 1;
                    }
                    continue;
                }

                if exists {
                    // Update existing
                    if let Some(s) = data.secrets.get_mut(key) {
                        s.value = value.clone();
                        s.rotated = chrono::Local::now().format("%Y-%m-%d").to_string();
                    }
                    updated += 1;
                } else {
                    let projects = match project {
                        Some(ref p) => vec![p.clone()],
                        None => vec![],
                    };
                    data.secrets.insert(
                        key.clone(),
                        SecretEntry {
                            value: value.clone(),
                            category: cat.clone(),
                            description: String::new(),
                            created: chrono::Local::now().format("%Y-%m-%d").to_string(),
                            rotated: chrono::Local::now().format("%Y-%m-%d").to_string(),
                            expires: None,
                            rotation_days: 90,
                            projects,
                            tags: vec![],
                            account: None,
                            environment: None,
                            related_keys: vec![],
                            last_verified: None,
                            last_error: None,
                            key_status: "unknown".to_string(),
                            lifecycle: "active".to_string(),
                            lifecycle_reason: None,
                            lifecycle_changed: None,
                            versions: vec![],
                            max_versions: 10,
                            rotation_policy: None,
                        },
                    );
                    added += 1;
                }
            }

            if !dry_run {
                vault::save_vault(&data)?;
            }

            if dry_run {
                println!(
                    "\nDry run: {} would be added, {} updated, {} skipped",
                    added, updated, skipped
                );
            } else {
                println!(
                    "Imported: {} added, {} updated, {} skipped",
                    added, updated, skipped
                );

                if shred && file.to_string_lossy() != "-" && file.exists() {
                    // Overwrite file content before deleting
                    let len = std::fs::metadata(&file)?.len() as usize;
                    let zeros = vec![0u8; len];
                    std::fs::write(&file, &zeros)?;
                    std::fs::remove_file(&file)?;
                    println!("Source file shredded: {}", file.display());
                }
            }

            Ok(())
        }
        Commands::Export {
            project,
            format,
            output,
        } => {
            let data = require_vault()?;

            let secrets: Vec<(String, &SecretEntry)> = if let Some(ref proj) = project {
                let proj_secrets = get_project_secrets(&data, proj);
                if proj_secrets.is_empty() {
                    // Fall back to filtering by secret.projects field
                    let mut result: Vec<_> = data
                        .secrets
                        .iter()
                        .filter(|(_, s)| s.projects.contains(proj))
                        .map(|(k, s)| (k.clone(), s))
                        .collect();
                    result.sort_by(|a, b| a.0.cmp(&b.0));
                    result
                } else {
                    proj_secrets
                        .iter()
                        .filter_map(|(k, _)| data.secrets.get(k).map(|s| (k.clone(), s)))
                        .collect()
                }
            } else {
                let mut all: Vec<_> = data
                    .secrets
                    .iter()
                    .map(|(k, s)| (k.clone(), s))
                    .collect();
                all.sort_by(|a, b| a.0.cmp(&b.0));
                all
            };

            if secrets.is_empty() {
                eprintln!("No secrets found.");
                return Ok(());
            }

            let content = match format.as_str() {
                "env" => {
                    let mut lines = Vec::new();
                    lines.push(format!(
                        "# Exported from PQVault{}",
                        project
                            .as_ref()
                            .map(|p| format!(" (project: {})", p))
                            .unwrap_or_default()
                    ));
                    lines.push(String::new());
                    for (k, s) in &secrets {
                        lines.push(format!("{}={}", k, s.value));
                    }
                    lines.push(String::new());
                    lines.join("\n")
                }
                "json" => {
                    let map: serde_json::Map<String, serde_json::Value> = secrets
                        .iter()
                        .map(|(k, s)| (k.clone(), serde_json::Value::String(s.value.clone())))
                        .collect();
                    serde_json::to_string_pretty(&map)?
                }
                "docker" => {
                    // Docker secrets format: one file per secret
                    let mut lines = Vec::new();
                    lines.push("# Docker secrets format".to_string());
                    lines.push(
                        "# Use: echo '<value>' | docker secret create <name> -".to_string(),
                    );
                    lines.push(String::new());
                    for (k, s) in &secrets {
                        lines.push(format!(
                            "echo '{}' | docker secret create {} -",
                            s.value.replace('\'', "'\"'\"'"),
                            k.to_lowercase()
                        ));
                    }
                    lines.join("\n")
                }
                _ => bail!("Unknown format: {}. Use: env, json, docker", format),
            };

            if let Some(ref path) = output {
                std::fs::write(path, &content)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                println!(
                    "Exported {} secrets to {}",
                    secrets.len(),
                    path.display()
                );
            } else {
                print!("{}", content);
            }

            Ok(())
        }
        Commands::CheckRotation { all } => {
            let data = require_vault()?;
            let now = chrono::Local::now();
            let mut needs_rotation = Vec::new();
            let mut up_to_date = Vec::new();

            for (key, secret) in &data.secrets {
                if secret.lifecycle != "active" {
                    continue;
                }
                let rotation_days = secret
                    .rotation_policy
                    .as_ref()
                    .map(|p| p.interval_days)
                    .unwrap_or(secret.rotation_days);

                let rotated = chrono::NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d")
                    .unwrap_or_else(|_| now.date_naive());
                let days_since = (now.date_naive() - rotated).num_days();
                let days_until = rotation_days - days_since;

                let notify_before = secret
                    .rotation_policy
                    .as_ref()
                    .map(|p| p.notify_before_days)
                    .unwrap_or(7);

                if days_until <= 0 {
                    needs_rotation.push((key.clone(), days_since, rotation_days, "OVERDUE"));
                } else if days_until <= notify_before {
                    needs_rotation.push((key.clone(), days_since, rotation_days, "DUE SOON"));
                } else if all {
                    up_to_date.push((key.clone(), days_since, rotation_days, days_until));
                }
            }

            if needs_rotation.is_empty() && !all {
                println!("All keys are within rotation policy.");
                return Ok(());
            }

            if !needs_rotation.is_empty() {
                println!("Keys needing rotation:");
                needs_rotation.sort_by(|a, b| b.1.cmp(&a.1));
                for (key, days, policy, status) in &needs_rotation {
                    println!(
                        "  {} - {} ({} days since rotation, policy: {} days)",
                        status, key, days, policy
                    );
                }
            }

            if all && !up_to_date.is_empty() {
                println!("\nUp to date:");
                up_to_date.sort_by(|a, b| a.3.cmp(&b.3));
                for (key, days, policy, until) in &up_to_date {
                    println!(
                        "  OK {} ({}/{} days, {} days remaining)",
                        key, days, policy, until
                    );
                }
            }
            Ok(())
        }
        Commands::SetPolicy {
            key,
            days,
            auto,
            notify_before,
        } => {
            let mut data = require_vault()?;
            let secret = match data.secrets.get_mut(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            secret.rotation_policy = Some(models::RotationPolicy {
                interval_days: days,
                auto_rotate: auto,
                notify_before_days: notify_before,
                last_auto_rotation: None,
            });

            vault::save_vault(&data)?;
            println!(
                "Policy set for {}: rotate every {} days{}{}",
                key,
                days,
                if auto { ", auto-rotate enabled" } else { "" },
                if notify_before != 7 {
                    format!(", notify {} days before", notify_before)
                } else {
                    String::new()
                }
            );
            Ok(())
        }
        Commands::Rollback { key, version } => {
            let mut data = require_vault()?;
            let secret = match data.secrets.get_mut(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            if secret.versions.is_empty() {
                bail!("No previous versions for '{}'", key);
            }

            let ver_idx = match version {
                Some(v) => {
                    if v == 0 || v > secret.versions.len() {
                        bail!(
                            "Invalid version {}. Valid range: 1-{}",
                            v,
                            secret.versions.len()
                        );
                    }
                    v - 1
                }
                None => secret.versions.len() - 1, // latest previous version
            };

            let old_version = &secret.versions[ver_idx];
            let rollback_value = old_version.value.clone();
            let rollback_from = old_version.rotated_at.clone();

            // Store current value as a version before rolling back
            secret.versions.push(models::SecretVersion {
                value: secret.value.clone(),
                rotated_at: chrono::Local::now().to_rfc3339(),
                rotated_by: "cli".to_string(),
                reason: format!("pre-rollback (rolling back to v{})", ver_idx + 1),
            });

            // Trim if needed
            if secret.max_versions > 0 && secret.versions.len() > secret.max_versions {
                let excess = secret.versions.len() - secret.max_versions;
                secret.versions.drain(0..excess);
            }

            secret.value = rollback_value;
            secret.rotated = chrono::Local::now().format("%Y-%m-%d").to_string();
            secret.key_status = "unknown".to_string();
            secret.last_verified = None;

            vault::save_vault(&data)?;
            pqvault_core::audit::log_access(
                &format!("rollback:v{}", ver_idx + 1),
                &key,
                "",
                "cli",
            );

            println!(
                "Rolled back '{}' to v{} (from {})",
                key,
                ver_idx + 1,
                rollback_from
            );
            Ok(())
        }
        Commands::AgentCreate {
            name,
            keys,
            categories,
            expires,
            budget,
            rate_limit,
        } => {
            let _ = require_vault()?; // ensure vault exists

            let allowed_keys: Vec<String> = keys
                .map(|k| k.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            let allowed_categories: Vec<String> = categories
                .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let agent = pqvault_core::agent::create_agent(
                &name,
                allowed_keys.clone(),
                allowed_categories.clone(),
                expires,
                budget,
                rate_limit,
            );

            println!("Agent created: {}", agent.name);
            println!("  ID:    {}", agent.id);
            println!("  Token: {}", agent.token);
            if !allowed_keys.is_empty() {
                println!("  Keys:  {}", allowed_keys.join(", "));
            }
            if !allowed_categories.is_empty() {
                println!("  Categories: {}", allowed_categories.join(", "));
            }
            if let Some(ref exp) = agent.expires {
                println!("  Expires: {}", exp);
            }
            if let Some(ref b) = agent.budget {
                println!("  Budget: ${:.2}/month", b.max_monthly_usd);
                if let Some(rph) = b.max_requests_per_hour {
                    println!("  Rate:   {}/hour", rph);
                }
            }
            println!("\nUse this token in agent requests to access scoped secrets.");
            Ok(())
        }
        Commands::AgentList => {
            let _ = require_vault()?;
            let agents = pqvault_core::agent::list_agents();

            if agents.is_empty() {
                println!("No agent tokens configured.");
                return Ok(());
            }

            println!(
                "{:<12} {:<20} {:<8} {:<8} {:<10} {}",
                "ID", "Name", "Active", "Requests", "Budget", "Expires"
            );
            println!("{}", "-".repeat(75));

            for a in &agents {
                let budget_str = a
                    .budget
                    .as_ref()
                    .map(|b| {
                        if b.circuit_breaker_triggered {
                            format!("${:.0} TRIPPED", b.max_monthly_usd)
                        } else {
                            format!("${:.0}/${:.0}", b.current_monthly_usd, b.max_monthly_usd)
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());

                let expires_str = a
                    .expires
                    .as_ref()
                    .map(|e| {
                        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(e) {
                            if chrono::Local::now() > exp {
                                "EXPIRED".to_string()
                            } else {
                                let remaining = exp.signed_duration_since(chrono::Local::now());
                                format!("{}h", remaining.num_hours())
                            }
                        } else {
                            e.clone()
                        }
                    })
                    .unwrap_or_else(|| "never".to_string());

                println!(
                    "{:<12} {:<20} {:<8} {:<8} {:<10} {}",
                    a.id,
                    a.name,
                    if a.active { "yes" } else { "REVOKED" },
                    a.total_requests,
                    budget_str,
                    expires_str
                );
            }
            Ok(())
        }
        Commands::AgentRevoke { id } => {
            let _ = require_vault()?;
            match pqvault_core::agent::revoke_agent(&id) {
                Some(name) => println!("Revoked agent '{}' ({})", name, id),
                None => eprintln!("Agent not found: {}", id),
            }
            Ok(())
        }
        Commands::Search { query, min_score, limit } => {
            let data = require_vault()?;
            let results = pqvault_core::search::search_secrets(
                &data.secrets, &query, min_score, limit,
            );

            if results.is_empty() {
                println!("No results for \"{}\" (min_score: {:.1})", query, min_score);
                return Ok(());
            }

            println!("Search: \"{}\" ({} results)\n", query, results.len());
            for (i, r) in results.iter().enumerate() {
                let proj = if r.projects.is_empty() {
                    "-".to_string()
                } else {
                    r.projects.join(", ")
                };
                let lifecycle_tag = if r.lifecycle != "active" {
                    format!(" [{}]", r.lifecycle.to_uppercase())
                } else {
                    String::new()
                };
                println!(
                    "  {}. {} (score: {:.1}){}\n     Category: {} | Project: {}\n     Matched: {}",
                    i + 1,
                    r.key_name,
                    r.score,
                    lifecycle_tag,
                    r.category,
                    proj,
                    r.match_reasons.join(", "),
                );
                if i < results.len() - 1 {
                    println!();
                }
            }
            Ok(())
        }
        Commands::Diff { project_a, project_b } => {
            let data = require_vault()?;

            let keys_a: Vec<&String> = data.secrets.iter()
                .filter(|(_, s)| s.projects.contains(&project_a))
                .map(|(name, _)| name)
                .collect();
            let keys_b: Vec<&String> = data.secrets.iter()
                .filter(|(_, s)| s.projects.contains(&project_b))
                .map(|(name, _)| name)
                .collect();

            let set_a: std::collections::HashSet<&String> = keys_a.iter().copied().collect();
            let set_b: std::collections::HashSet<&String> = keys_b.iter().copied().collect();

            let only_a: Vec<&&String> = set_a.difference(&set_b).collect();
            let only_b: Vec<&&String> = set_b.difference(&set_a).collect();
            let both: Vec<&&String> = set_a.intersection(&set_b).collect();

            println!("Diff: {} vs {}\n", project_a, project_b);
            println!("  Shared:        {}", both.len());
            println!("  Only in {}:  {}", project_a, only_a.len());
            println!("  Only in {}:  {}", project_b, only_b.len());

            if !only_a.is_empty() {
                println!("\nOnly in {}:", project_a);
                for k in &only_a {
                    println!("  + {}", k);
                }
            }
            if !only_b.is_empty() {
                println!("\nOnly in {}:", project_b);
                for k in &only_b {
                    println!("  + {}", k);
                }
            }
            if !both.is_empty() {
                println!("\nShared keys:");
                for k in &both {
                    println!("  = {}", k);
                }
            }
            Ok(())
        }
        Commands::Tree => {
            let data = require_vault()?;

            // Group by category, then by project
            let mut tree: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> =
                std::collections::BTreeMap::new();

            for (name, secret) in &data.secrets {
                let cat = &secret.category;
                let projs = if secret.projects.is_empty() {
                    vec!["(unassigned)".to_string()]
                } else {
                    secret.projects.clone()
                };

                for proj in &projs {
                    tree.entry(cat.clone())
                        .or_default()
                        .entry(proj.clone())
                        .or_default()
                        .push(name.clone());
                }
            }

            println!("Vault Tree ({} secrets)\n", data.secrets.len());
            for (cat, projects) in &tree {
                let cat_count: usize = projects.values().map(|v| v.len()).sum();
                println!("{} ({})", cat, cat_count);
                let proj_count = projects.len();
                for (i, (proj, keys)) in projects.iter().enumerate() {
                    let is_last_proj = i == proj_count - 1;
                    let proj_prefix = if is_last_proj { "└── " } else { "├── " };
                    println!("  {}{} ({})", proj_prefix, proj, keys.len());
                    let key_prefix = if is_last_proj { "    " } else { "│   " };
                    for (j, key) in keys.iter().enumerate() {
                        let is_last_key = j == keys.len() - 1;
                        let key_branch = if is_last_key { "└── " } else { "├── " };
                        println!("  {}{}{}", key_prefix, key_branch, key);
                    }
                }
                println!();
            }
            Ok(())
        }
        Commands::Entropy => {
            let data = require_vault()?;

            println!("{:<40} {:>8} {:>8} {}", "KEY", "LENGTH", "ENTROPY", "RATING");
            println!("{}", "-".repeat(72));

            let mut entries: Vec<_> = data.secrets.iter().collect();
            entries.sort_by_key(|(name, _)| name.to_string());

            for (name, secret) in &entries {
                let val = &secret.value;
                let len = val.len();
                let entropy = shannon_entropy(val);
                let rating = if entropy > 4.5 {
                    "HIGH"
                } else if entropy > 3.0 {
                    "MEDIUM"
                } else if len < 8 {
                    "WEAK"
                } else {
                    "LOW"
                };
                println!("{:<40} {:>8} {:>7.2} {}", name, len, entropy, rating);
            }
            Ok(())
        }
        Commands::Tag { key, add, remove } => {
            let mut data = require_vault()?;
            let secret = match data.secrets.get_mut(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            if let Some(tags) = add {
                for tag in tags.split(',').map(|s| s.trim().to_string()) {
                    if !secret.tags.contains(&tag) {
                        secret.tags.push(tag.clone());
                        println!("  Added tag: {}", tag);
                    }
                }
            }

            if let Some(tags) = remove {
                for tag in tags.split(',').map(|s| s.trim()) {
                    if let Some(pos) = secret.tags.iter().position(|t| t == tag) {
                        secret.tags.remove(pos);
                        println!("  Removed tag: {}", tag);
                    }
                }
            }

            println!("Tags for {}: [{}]", key, secret.tags.join(", "));
            vault::save_vault(&data)?;
            Ok(())
        }
        Commands::Doctor => {
            let data = require_vault()?;
            let report = check_health(&data);

            println!("=== PQVault Health Report ===\n");
            println!("Total secrets: {}", report.total_secrets);

            // Lifecycle breakdown
            if !report.by_lifecycle.is_empty() {
                let mut lifecycle: Vec<_> = report.by_lifecycle.iter().collect();
                lifecycle.sort_by_key(|(k, _)| k.to_string());
                let parts: Vec<String> = lifecycle
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                println!("Lifecycle: {}", parts.join(", "));
            }

            // Category breakdown
            if !report.by_category.is_empty() {
                let mut cats: Vec<_> = report.by_category.iter().collect();
                cats.sort_by(|a, b| b.1.cmp(a.1));
                println!("\nCategories:");
                for (cat, count) in &cats {
                    println!("  {:15} {}", cat, count);
                }
            }

            // Issues
            let mut issues = 0;

            if !report.expired.is_empty() {
                issues += report.expired.len();
                println!("\nEXPIRED ({}):", report.expired.len());
                for k in &report.expired {
                    println!("  {}", k);
                }
            }

            if !report.expiring_soon.is_empty() {
                println!("\nEXPIRING SOON ({}):", report.expiring_soon.len());
                let mut sorted = report.expiring_soon.clone();
                sorted.sort_by_key(|(_, d)| *d);
                for (k, days) in &sorted {
                    println!("  {} ({} days)", k, days);
                }
            }

            if !report.needs_rotation.is_empty() {
                issues += report.needs_rotation.len();
                println!("\nNEEDS ROTATION ({}):", report.needs_rotation.len());
                for k in &report.needs_rotation {
                    println!("  {}", k);
                }
            }

            if !report.error_keys.is_empty() {
                issues += report.error_keys.len();
                println!("\nERROR STATUS ({}):", report.error_keys.len());
                for k in &report.error_keys {
                    println!("  {}", k);
                }
            }

            if !report.deprecated.is_empty() {
                println!("\nDEPRECATED ({}):", report.deprecated.len());
                for k in &report.deprecated {
                    println!("  {}", k);
                }
            }

            if !report.disabled.is_empty() {
                println!("\nDISABLED ({}):", report.disabled.len());
                for k in &report.disabled {
                    println!("  {}", k);
                }
            }

            // Dead keys
            if !report.dead_keys.is_empty() {
                issues += report.dead_keys.len();
                println!("\nDEAD KEYS ({}):", report.dead_keys.len());
                for dk in &report.dead_keys {
                    println!(
                        "  {} [{}] — {} days inactive\n    {}",
                        dk.name, dk.category, dk.days_unused, dk.recommendation
                    );
                }
            }

            // Duplicates
            if !report.duplicates.is_empty() {
                issues += report.duplicates.len();
                println!("\nDUPLICATE VALUES ({} groups):", report.duplicates.len());
                for dup in &report.duplicates {
                    println!(
                        "  Hash {}...: {}",
                        &dup.value_hash,
                        dup.keys.join(", ")
                    );
                }
            }

            // Key health scores (show worst 10)
            let worst: Vec<_> = report
                .key_scores
                .iter()
                .filter(|k| k.score < 80)
                .take(10)
                .collect();
            if !worst.is_empty() {
                println!("\nLOW HEALTH SCORES ({} keys below 80):", worst.len());
                for ks in &worst {
                    println!(
                        "  {:40} score: {:>3}  issues: {}",
                        ks.name,
                        ks.score,
                        ks.issues.join(", ")
                    );
                }
            }

            // Vault file checks
            println!("\n=== Vault Files ===");
            let vault_path = pqvault_core::vault::vault_file();
            if vault_path.exists() {
                let meta = std::fs::metadata(&vault_path)?;
                println!(
                    "vault.enc: {} bytes",
                    meta.len()
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        println!("  WARNING: permissions are {:o} (should be 600)", mode);
                        issues += 1;
                    } else {
                        println!("  permissions: 600 (OK)");
                    }
                }
            }

            let keychain_ok = pqvault_core::keychain::has_master_password();
            println!(
                "Keychain: {}",
                if keychain_ok { "OK" } else { "NOT FOUND" }
            );
            if !keychain_ok {
                issues += 1;
            }

            println!(
                "\n=== Result: {} ===",
                if issues == 0 {
                    "HEALTHY"
                } else {
                    "ISSUES FOUND"
                }
            );
            if issues > 0 {
                println!("{} issue(s) detected", issues);
            }

            Ok(())
        }
        Commands::Lifecycle {
            key,
            action,
            reason,
        } => {
            let mut data = require_vault()?;
            let secret = match data.secrets.get_mut(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            let target = match action.as_str() {
                "deprecate" => "deprecated",
                "disable" => "disabled",
                "archive" => "archived",
                "restore" | "activate" => "active",
                other => bail!(
                    "Unknown action: '{}'. Use: deprecate, disable, archive, restore",
                    other
                ),
            };

            if !models::valid_lifecycle_transition(&secret.lifecycle, target) {
                bail!(
                    "Cannot transition '{}' from '{}' to '{}'. Valid transitions:\n  \
                     active → deprecated\n  \
                     deprecated → disabled | active\n  \
                     disabled → archived | active\n  \
                     archived → active",
                    key,
                    secret.lifecycle,
                    target
                );
            }

            let old_state = secret.lifecycle.clone();
            secret.lifecycle = target.to_string();
            secret.lifecycle_reason = reason.clone();
            secret.lifecycle_changed =
                Some(chrono::Local::now().to_rfc3339());

            vault::save_vault(&data)?;
            pqvault_core::audit::log_access(
                &format!("lifecycle:{}", target),
                &key,
                "",
                "cli",
            );

            println!(
                "{}: {} → {}{}",
                key,
                old_state,
                target,
                reason
                    .as_ref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default()
            );
            Ok(())
        }
        Commands::Rotate {
            key,
            value,
            reason,
        } => {
            let mut data = require_vault()?;
            let secret = match data.secrets.get_mut(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            if secret.lifecycle == "disabled" || secret.lifecycle == "archived" {
                bail!(
                    "Cannot rotate '{}': key is {} (restore it first)",
                    key,
                    secret.lifecycle
                );
            }

            // Store old value in version history
            let old_value = secret.value.clone();
            secret.versions.push(models::SecretVersion {
                value: old_value,
                rotated_at: chrono::Local::now().to_rfc3339(),
                rotated_by: "cli".to_string(),
                reason: reason.clone().unwrap_or_default(),
            });

            // Trim versions if exceeding max
            if secret.max_versions > 0 && secret.versions.len() > secret.max_versions {
                let excess = secret.versions.len() - secret.max_versions;
                secret.versions.drain(0..excess);
            }

            // Update to new value
            secret.value = value;
            secret.rotated = chrono::Local::now().format("%Y-%m-%d").to_string();
            secret.key_status = "unknown".to_string();
            secret.last_verified = None;
            secret.last_error = None;

            vault::save_vault(&data)?;
            pqvault_core::audit::log_access("rotate", &key, "", "cli");

            println!(
                "Rotated: {} (version {} stored){}",
                key,
                data.secrets[&key].versions.len(),
                reason
                    .as_ref()
                    .map(|r| format!(" reason: {}", r))
                    .unwrap_or_default()
            );
            Ok(())
        }
        Commands::History { key, full } => {
            let data = require_vault()?;
            let secret = match data.secrets.get(&key) {
                Some(s) => s,
                None => bail!("Key not found: {}", key),
            };

            println!("Key: {}", key);
            println!(
                "Current: {} [{}] lifecycle={}",
                if full {
                    secret.value.clone()
                } else {
                    models::mask_value(&secret.value)
                },
                secret.rotated,
                secret.lifecycle
            );

            if secret.versions.is_empty() {
                println!("No previous versions.");
            } else {
                println!("\nVersion history ({}):", secret.versions.len());
                for (i, ver) in secret.versions.iter().enumerate().rev() {
                    let display = if full {
                        ver.value.clone()
                    } else {
                        models::mask_value(&ver.value)
                    };
                    println!(
                        "  v{}: {} [{}]{}{}",
                        i + 1,
                        display,
                        ver.rotated_at,
                        if ver.rotated_by.is_empty() {
                            String::new()
                        } else {
                            format!(" by={}", ver.rotated_by)
                        },
                        if ver.reason.is_empty() {
                            String::new()
                        } else {
                            format!(" reason=\"{}\"", ver.reason)
                        }
                    );
                }
            }
            Ok(())
        }
    }
}
