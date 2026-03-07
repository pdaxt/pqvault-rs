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
                println!(
                    "{} [{}] projects={} rotated={}",
                    k,
                    s.category,
                    s.projects.join(","),
                    s.rotated
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
    }
}
