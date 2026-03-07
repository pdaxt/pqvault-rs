# Feature 006: Secret Scanner

## Status: Planned
## Phase: 1 (v2.1)
## Priority: High

## Problem

Developers routinely commit hardcoded API keys, database passwords, and tokens directly into source code and configuration files. These secrets end up in git history permanently. According to GitGuardian's State of Secrets Sprawl report, the average organization leaks 5.5 secrets per developer per year. PQVault can store secrets securely, but it does nothing to find the ones already embedded in codebases.

## Solution

`pqvault scan <dir>` recursively walks a directory tree, applies a library of regex patterns to detect common API key formats (Stripe, GitHub, AWS, Google, etc.), and reports findings with file path, line number, and matched pattern type. Integrates as both a CLI command and an MCP tool. Supports `.pqvaultignore` files for excluding false positives and can auto-import discovered secrets into the vault.

## Implementation

### Files to Create/Modify

- `crates/pqvault-scan-mcp/src/scanner.rs` — Core scanning engine with regex patterns
- `crates/pqvault-scan-mcp/src/patterns.rs` — Secret pattern definitions
- `crates/pqvault-scan-mcp/src/lib.rs` — MCP tool registration
- `crates/pqvault-cli/src/scan.rs` — CLI scan subcommand
- `crates/pqvault-cli/src/main.rs` — Register scan subcommand

### Data Model Changes

```rust
/// A detected secret in source code
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretFinding {
    /// File path where secret was found
    pub file_path: String,
    /// Line number (1-indexed)
    pub line_number: usize,
    /// Column range where secret appears
    pub column_start: usize,
    pub column_end: usize,
    /// The matched pattern type
    pub pattern_type: SecretPatternType,
    /// Provider name (e.g., "Stripe", "GitHub", "AWS")
    pub provider: String,
    /// Severity level
    pub severity: FindingSeverity,
    /// The actual matched text (redacted: first 4 + last 4 chars)
    pub matched_preview: String,
    /// The full line (with secret redacted)
    pub context_line: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecretPatternType {
    ApiKey,
    SecretKey,
    Token,
    Password,
    ConnectionString,
    PrivateKey,
    Certificate,
    Webhook,
    OAuth,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum FindingSeverity {
    Critical,  // Live/production keys
    High,      // Keys with broad access
    Medium,    // API keys with limited scope
    Low,       // Possibly false positive
}

/// Scan configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanConfig {
    /// Directories to skip
    pub skip_dirs: Vec<String>,
    /// File extensions to skip
    pub skip_extensions: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Custom patterns to add
    pub custom_patterns: Vec<CustomPattern>,
    /// Path to .pqvaultignore
    pub ignore_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
    pub severity: FindingSeverity,
}

/// Scan results summary
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub scan_duration_ms: u64,
    pub summary: ScanSummary,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub by_provider: HashMap<String, usize>,
}
```

### MCP Tools

```rust
// Tool: secret_scan
{
    "name": "secret_scan",
    "description": "Scan a directory for hardcoded secrets",
    "params": {
        "directory": "/path/to/project",      // required
        "recursive": true,                     // default true
        "include_low_severity": false,         // default false
        "max_results": 100                     // default 100
    },
    "returns": {
        "findings": [...],
        "files_scanned": 342,
        "summary": {
            "critical": 2,
            "high": 5,
            "medium": 3,
            "by_provider": { "Stripe": 2, "AWS": 3, "GitHub": 2, "Generic": 3 }
        }
    }
}

// Tool: secret_scan_breach
{
    "name": "secret_scan_breach",
    "description": "Check if known vault secrets appear in source code",
    "params": {
        "directory": "/path/to/project",
        "project": "myapp"                    // optional: only check project keys
    },
    "returns": {
        "leaked_keys": [
            {
                "key_name": "STRIPE_SECRET_KEY",
                "found_in": [
                    { "file": "src/payment.rs", "line": 42 },
                    { "file": "config/dev.yaml", "line": 15 }
                ]
            }
        ]
    }
}
```

### CLI Commands

```bash
# Scan current directory
pqvault scan .

# Scan specific directory
pqvault scan /path/to/project

# Scan with JSON output
pqvault scan . --format json

# Scan and auto-import found secrets
pqvault scan . --import --project myapp

# Scan only for critical/high severity
pqvault scan . --min-severity high

# Scan with custom ignore file
pqvault scan . --ignore .pqvaultignore

# Check if vault secrets are leaked in code
pqvault scan --breach-check /path/to/project

# Pre-commit hook mode (exit code 1 if secrets found)
pqvault scan --pre-commit .
```

### Web UI Changes

New section on the health dashboard showing scan results:
- "Secret Scan" card showing last scan timestamp and finding count
- Button to trigger a scan of a configured project directory
- Findings table with file, line, provider, severity

## Core Implementation

### Pattern Library

```rust
// crates/pqvault-scan-mcp/src/patterns.rs

use regex::Regex;
use lazy_static::lazy_static;

pub struct SecretPattern {
    pub name: &'static str,
    pub provider: &'static str,
    pub regex: Regex,
    pub pattern_type: SecretPatternType,
    pub severity: FindingSeverity,
}

lazy_static! {
    pub static ref SECRET_PATTERNS: Vec<SecretPattern> = vec![
        // Stripe
        SecretPattern {
            name: "Stripe Secret Key",
            provider: "Stripe",
            regex: Regex::new(r"sk_live_[a-zA-Z0-9]{24,}").unwrap(),
            pattern_type: SecretPatternType::SecretKey,
            severity: FindingSeverity::Critical,
        },
        SecretPattern {
            name: "Stripe Test Key",
            provider: "Stripe",
            regex: Regex::new(r"sk_test_[a-zA-Z0-9]{24,}").unwrap(),
            pattern_type: SecretPatternType::SecretKey,
            severity: FindingSeverity::Medium,
        },
        SecretPattern {
            name: "Stripe Webhook Secret",
            provider: "Stripe",
            regex: Regex::new(r"whsec_[a-zA-Z0-9]{24,}").unwrap(),
            pattern_type: SecretPatternType::Webhook,
            severity: FindingSeverity::High,
        },

        // AWS
        SecretPattern {
            name: "AWS Access Key ID",
            provider: "AWS",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            pattern_type: SecretPatternType::ApiKey,
            severity: FindingSeverity::Critical,
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            provider: "AWS",
            regex: Regex::new(r"(?i)aws_secret_access_key\s*[=:]\s*[a-zA-Z0-9/+=]{40}").unwrap(),
            pattern_type: SecretPatternType::SecretKey,
            severity: FindingSeverity::Critical,
        },

        // GitHub
        SecretPattern {
            name: "GitHub Personal Access Token",
            provider: "GitHub",
            regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
            pattern_type: SecretPatternType::Token,
            severity: FindingSeverity::High,
        },
        SecretPattern {
            name: "GitHub OAuth Access Token",
            provider: "GitHub",
            regex: Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap(),
            pattern_type: SecretPatternType::Token,
            severity: FindingSeverity::High,
        },
        SecretPattern {
            name: "GitHub Fine-Grained PAT",
            provider: "GitHub",
            regex: Regex::new(r"github_pat_[a-zA-Z0-9_]{82}").unwrap(),
            pattern_type: SecretPatternType::Token,
            severity: FindingSeverity::High,
        },

        // Google
        SecretPattern {
            name: "Google API Key",
            provider: "Google",
            regex: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            pattern_type: SecretPatternType::ApiKey,
            severity: FindingSeverity::High,
        },
        SecretPattern {
            name: "Google OAuth Client Secret",
            provider: "Google",
            regex: Regex::new(r"GOCSPX-[a-zA-Z0-9\-_]{28}").unwrap(),
            pattern_type: SecretPatternType::OAuth,
            severity: FindingSeverity::Critical,
        },

        // Slack
        SecretPattern {
            name: "Slack Bot Token",
            provider: "Slack",
            regex: Regex::new(r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}").unwrap(),
            pattern_type: SecretPatternType::Token,
            severity: FindingSeverity::High,
        },
        SecretPattern {
            name: "Slack Webhook URL",
            provider: "Slack",
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").unwrap(),
            pattern_type: SecretPatternType::Webhook,
            severity: FindingSeverity::High,
        },

        // SendGrid / Resend
        SecretPattern {
            name: "SendGrid API Key",
            provider: "SendGrid",
            regex: Regex::new(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}").unwrap(),
            pattern_type: SecretPatternType::ApiKey,
            severity: FindingSeverity::High,
        },
        SecretPattern {
            name: "Resend API Key",
            provider: "Resend",
            regex: Regex::new(r"re_[a-zA-Z0-9]{20,}").unwrap(),
            pattern_type: SecretPatternType::ApiKey,
            severity: FindingSeverity::High,
        },

        // Database connection strings
        SecretPattern {
            name: "Database Connection String",
            provider: "Database",
            regex: Regex::new(r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+").unwrap(),
            pattern_type: SecretPatternType::ConnectionString,
            severity: FindingSeverity::Critical,
        },

        // Private keys
        SecretPattern {
            name: "RSA Private Key",
            provider: "Generic",
            regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            pattern_type: SecretPatternType::PrivateKey,
            severity: FindingSeverity::Critical,
        },
        SecretPattern {
            name: "Generic Private Key",
            provider: "Generic",
            regex: Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap(),
            pattern_type: SecretPatternType::PrivateKey,
            severity: FindingSeverity::Critical,
        },

        // Generic patterns
        SecretPattern {
            name: "Generic API Key Assignment",
            provider: "Generic",
            regex: Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key)\s*[=:]\s*["'][a-zA-Z0-9_\-]{20,}["']"#).unwrap(),
            pattern_type: SecretPatternType::ApiKey,
            severity: FindingSeverity::Medium,
        },
        SecretPattern {
            name: "Generic Password Assignment",
            provider: "Generic",
            regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["'][^\s'"]{8,}["']"#).unwrap(),
            pattern_type: SecretPatternType::Password,
            severity: FindingSeverity::Medium,
        },
    ];
}
```

### Scanner Engine

```rust
// crates/pqvault-scan-mcp/src/scanner.rs

use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use anyhow::Result;

const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "target", "dist", "build",
    ".next", "__pycache__", ".venv", "venv", ".tox",
    "vendor", ".cargo", ".gradle",
];

const DEFAULT_SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2",
    "ttf", "eot", "mp3", "mp4", "avi", "mov", "zip", "tar",
    "gz", "bz2", "xz", "pdf", "doc", "docx", "exe", "dll",
    "so", "dylib", "o", "a", "pyc", "class", "lock",
];

const MAX_FILE_SIZE: u64 = 1_048_576; // 1MB

pub fn scan_directory(
    dir: &Path,
    config: &ScanConfig,
) -> Result<ScanResult> {
    let start = std::time::Instant::now();
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let mut files_skipped = 0;

    let ignore_patterns = load_ignore_patterns(dir, config)?;

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e, config))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => { files_skipped += 1; continue; }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        // Skip by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let skip_exts = if config.skip_extensions.is_empty() {
                DEFAULT_SKIP_EXTENSIONS.iter().map(|s| s.to_string()).collect()
            } else {
                config.skip_extensions.clone()
            };
            if skip_exts.iter().any(|s| s == ext) {
                files_skipped += 1;
                continue;
            }
        }

        // Skip large files
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => { files_skipped += 1; continue; }
        };
        if metadata.len() > config.max_file_size.max(MAX_FILE_SIZE) {
            files_skipped += 1;
            continue;
        }

        // Skip ignored paths
        if is_ignored(path, dir, &ignore_patterns) {
            files_skipped += 1;
            continue;
        }

        // Read and scan file
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => { files_skipped += 1; continue; } // Binary file
        };

        files_scanned += 1;
        scan_file_content(path, &content, &mut findings);
    }

    let duration = start.elapsed().as_millis() as u64;

    let summary = ScanSummary {
        critical: findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count(),
        high: findings.iter().filter(|f| f.severity == FindingSeverity::High).count(),
        medium: findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count(),
        low: findings.iter().filter(|f| f.severity == FindingSeverity::Low).count(),
        by_provider: {
            let mut map = HashMap::new();
            for f in &findings {
                *map.entry(f.provider.clone()).or_insert(0) += 1;
            }
            map
        },
    };

    Ok(ScanResult {
        findings,
        files_scanned,
        files_skipped,
        scan_duration_ms: duration,
        summary,
    })
}

fn scan_file_content(path: &Path, content: &str, findings: &mut Vec<SecretFinding>) {
    for (line_idx, line) in content.lines().enumerate() {
        for pattern in SECRET_PATTERNS.iter() {
            for mat in pattern.regex.find_iter(line) {
                let matched = mat.as_str();
                let preview = redact_secret(matched);

                findings.push(SecretFinding {
                    file_path: path.display().to_string(),
                    line_number: line_idx + 1,
                    column_start: mat.start(),
                    column_end: mat.end(),
                    pattern_type: pattern.pattern_type.clone(),
                    provider: pattern.provider.to_string(),
                    severity: pattern.severity.clone(),
                    matched_preview: preview,
                    context_line: redact_line(line, mat.start(), mat.end()),
                });
            }
        }
    }
}

/// Show first 4 and last 4 chars, mask the rest
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 12 {
        return format!("{}...", &secret[..4]);
    }
    let prefix = &secret[..4];
    let suffix = &secret[secret.len()-4..];
    format!("{}...{}", prefix, suffix)
}

/// Replace the secret in the line with asterisks
fn redact_line(line: &str, start: usize, end: usize) -> String {
    let mut result = line.to_string();
    let replacement = "*".repeat(end - start);
    result.replace_range(start..end, &replacement);
    result
}

fn should_skip_dir(entry: &walkdir::DirEntry, config: &ScanConfig) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_str().unwrap_or("");
    let skip_dirs = if config.skip_dirs.is_empty() {
        DEFAULT_SKIP_DIRS.iter().map(|s| s.to_string()).collect()
    } else {
        config.skip_dirs.clone()
    };
    skip_dirs.iter().any(|d| d == name)
}
```

## Dependencies

- `walkdir = "2"` — Recursive directory traversal
- `regex = "1"` — Pattern matching for secret detection
- `lazy_static = "1"` — Compile regex patterns once at startup
- Uses existing `serde`, `serde_json`, `chrono`

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_stripe_live_key() {
        let content = r#"let key = "sk_live_abc123def456ghi789jkl012";"#;
        let mut findings = Vec::new();
        scan_file_content(Path::new("test.rs"), content, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].provider, "Stripe");
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
    }

    #[test]
    fn test_detect_aws_access_key() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let mut findings = Vec::new();
        scan_file_content(Path::new("env"), content, &mut findings);
        assert!(findings.iter().any(|f| f.provider == "AWS"));
    }

    #[test]
    fn test_detect_github_pat() {
        let content = r#"token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#;
        let mut findings = Vec::new();
        scan_file_content(Path::new("config.yaml"), content, &mut findings);
        assert!(findings.iter().any(|f| f.provider == "GitHub"));
    }

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("sk_live_abc123def456ghi789"), "sk_l...i789");
        assert_eq!(redact_secret("short"), "shor...");
    }

    #[test]
    fn test_no_false_positive_on_variable_names() {
        // The word "password" in a variable name shouldn't match
        let content = "let password_field = get_input();";
        let mut findings = Vec::new();
        scan_file_content(Path::new("test.rs"), content, &mut findings);
        assert_eq!(findings.len(), 0); // No hardcoded password value
    }

    #[test]
    fn test_detect_connection_string() {
        let content = r#"DATABASE_URL="postgres://admin:secretpass@db.example.com:5432/prod""#;
        let mut findings = Vec::new();
        scan_file_content(Path::new(".env"), content, &mut findings);
        assert!(findings.iter().any(|f| f.pattern_type == SecretPatternType::ConnectionString));
    }

    #[test]
    fn test_skip_git_directory() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), "sk_live_abc123def456ghi789jkl012").unwrap();
        fs::write(dir.path().join("src.rs"), "let x = 1;").unwrap();

        let result = scan_directory(dir.path(), &ScanConfig::default()).unwrap();
        assert_eq!(result.findings.len(), 0); // .git was skipped
        assert_eq!(result.files_scanned, 1);  // Only src.rs scanned
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_scan_real_directory() {
    let dir = tempdir().unwrap();

    // Create files with secrets
    fs::write(dir.path().join("config.py"),
        r#"STRIPE_KEY = "sk_live_abc123def456ghi789jkl012mno345""#
    ).unwrap();
    fs::write(dir.path().join("deploy.sh"),
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    ).unwrap();
    fs::write(dir.path().join("clean.rs"),
        "fn main() { println!(\"Hello\"); }"
    ).unwrap();

    let result = scan_directory(dir.path(), &ScanConfig::default()).unwrap();
    assert_eq!(result.files_scanned, 3);
    assert!(result.findings.len() >= 2);
    assert!(result.summary.critical >= 1);
}
```

### Manual Verification

1. Clone a test repo known to have leaked keys
2. Run `pqvault scan .` — verify findings list with correct file:line
3. Run with `--format json` — verify machine-readable output
4. Run with `--pre-commit` — verify exit code 1 when secrets found
5. Create `.pqvaultignore` with false positive paths — verify they're excluded

## Example Usage

```bash
# Scan a project
$ pqvault scan ~/Projects/my-webapp
Scanning /Users/dev/Projects/my-webapp...

  CRITICAL  src/payment.rs:42      Stripe Secret Key        sk_l...o345
  CRITICAL  config/prod.yaml:15    Database Connection      post...prod
  HIGH      src/github.rs:23       GitHub PAT               ghp_...wxyz
  HIGH      lib/email.ts:8         SendGrid API Key         SG.a...f456
  MEDIUM    tests/mock.py:5        Stripe Test Key          sk_t...test

Summary: 5 findings (2 critical, 2 high, 1 medium)
  Files scanned: 342 | Skipped: 28 | Duration: 89ms

# Pre-commit hook usage
$ pqvault scan --pre-commit .
CRITICAL: 2 hardcoded secrets detected. Commit blocked.

# JSON output for CI/CD
$ pqvault scan . --format json --min-severity high
{
  "findings": [...],
  "summary": { "critical": 2, "high": 2 },
  "exit_code": 1
}

# Auto-import discovered secrets
$ pqvault scan . --import --project webapp
Found 5 secrets. Import to vault?
  STRIPE_SECRET_KEY → payment [y/N] y
  DATABASE_URL → database [y/N] y
  ...
Imported 5 secrets. Remember to remove them from source code!
```
