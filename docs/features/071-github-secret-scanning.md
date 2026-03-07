# Feature 071: GitHub Secret Scanning

## Status: Done
## Phase: 8 (v2.8)
## Priority: Critical

## Problem

Developers accidentally commit secrets to public repositories despite `.gitignore`
rules and pre-commit hooks. A single leaked API key can result in unauthorized access,
financial loss, or data breaches. GitHub's built-in secret scanning only covers known
provider patterns and does not cross-reference against a user's actual vault contents.
Teams have no way to proactively monitor their repos for vault key leaks.

## Solution

Build a GitHub secret scanning MCP tool that monitors specified repositories for any
strings matching vault key values or patterns. It uses the GitHub API to scan commit
history, pull request diffs, and issue comments. When a match is found, it triggers
an alert and can auto-rotate the compromised key. The scanner runs as a periodic check
and integrates with the PQVault health system.

## Implementation

### Files to Create/Modify

```
pqvault-scan-mcp/
  src/
    lib.rs               # MCP tool registration
    scanning/
      mod.rs             # Scanning engine module root
      github.rs          # GitHub API client for repo scanning
      matcher.rs         # Pattern matcher against vault values
      alerter.rs         # Alert generation and notification
      scheduler.rs       # Periodic scan scheduling
    tools/
      scan_repos.rs      # MCP tool: scan repos for leaked secrets
      scan_status.rs     # MCP tool: scan status and history
      scan_config.rs     # MCP tool: configure repos to monitor
```

### Data Model Changes

```rust
use reqwest::Client;
use chrono::{DateTime, Utc};

pub struct GitHubScanner {
    client: Client,
    github_token: String,
    vault_fingerprints: Vec<SecretFingerprint>,
}

/// Fingerprint for matching without exposing the full value
pub struct SecretFingerprint {
    pub key_name: String,
    /// First 4 and last 4 chars of the value
    pub prefix: String,
    pub suffix: String,
    /// Full SHA-256 hash of the value
    pub value_hash: String,
    /// Length of the value
    pub value_length: usize,
    /// Regex pattern derived from the value format
    pub pattern: Option<String>,
    /// Provider-specific patterns (e.g., sk_live_ for Stripe)
    pub provider_pattern: Option<String>,
}

pub struct ScanTarget {
    pub owner: String,
    pub repo: String,
    pub branch: Option<String>,
    pub scan_depth: ScanDepth,
}

pub enum ScanDepth {
    /// Only latest commit
    Latest,
    /// Last N commits
    Recent(usize),
    /// Full history
    Full,
    /// Since a specific date
    Since(DateTime<Utc>),
}

pub struct ScanResult {
    pub target: ScanTarget,
    pub findings: Vec<ScanFinding>,
    pub scanned_commits: usize,
    pub scanned_files: usize,
    pub duration: Duration,
    pub completed_at: DateTime<Utc>,
}

pub struct ScanFinding {
    pub key_name: String,
    pub severity: FindingSeverity,
    pub location: LeakLocation,
    pub confidence: f64,         // 0.0 - 1.0
    pub recommended_action: Action,
}

pub enum FindingSeverity {
    Critical,   // Exact value match
    High,       // Provider pattern match
    Medium,     // Partial match / high entropy string
    Low,        // Possible false positive
}

pub struct LeakLocation {
    pub repo: String,
    pub file_path: String,
    pub commit_sha: String,
    pub commit_date: DateTime<Utc>,
    pub line_number: usize,
    pub author: String,
    pub url: String,  // GitHub permalink
}

pub enum Action {
    RotateImmediately,
    Investigate,
    FalsePositive,
}
```

### MCP Tools

```rust
#[tool(description = "Scan GitHub repositories for leaked vault secrets")]
async fn scan_repos(
    /// GitHub repos to scan (owner/repo format, comma-separated)
    repos: String,
    /// Scan depth: latest, recent, full, or since:YYYY-MM-DD
    #[arg(default = "recent")]
    depth: String,
    /// Auto-rotate any found leaked keys
    #[arg(default = false)]
    auto_rotate: bool,
) -> Result<CallToolResult> {
    let targets: Vec<ScanTarget> = repos.split(',')
        .map(|r| parse_scan_target(r.trim(), &depth))
        .collect::<Result<Vec<_>>>()?;

    let scanner = GitHubScanner::new(&config).await?;
    let mut all_findings = Vec::new();

    for target in &targets {
        let result = scanner.scan_repository(target).await?;
        all_findings.extend(result.findings);
    }

    if auto_rotate {
        for finding in all_findings.iter().filter(|f| f.confidence > 0.9) {
            rotate_key(&finding.key_name).await?;
        }
    }

    Ok(format_scan_results(&all_findings))
}

#[tool(description = "Get status of previous scans and configured repos")]
async fn scan_status() -> Result<CallToolResult> { /* ... */ }

#[tool(description = "Configure repositories to monitor for secret leaks")]
async fn scan_config(
    /// Action: add, remove, list
    action: String,
    /// Repository in owner/repo format
    repo: Option<String>,
    /// Scan frequency: hourly, daily, weekly
    frequency: Option<String>,
) -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# Scan specific repos
pqvault scan github myorg/api-server,myorg/frontend

# Scan all repos in an org
pqvault scan github --org myorg

# Full history scan (slower)
pqvault scan github myorg/api-server --depth full

# Auto-rotate compromised keys
pqvault scan github myorg/api-server --auto-rotate

# Configure periodic scanning
pqvault scan config add myorg/api-server --frequency daily

# View scan history
pqvault scan status
```

### Web UI Changes

None in this phase. Scan results feed into the health dashboard.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reqwest` | 0.12 | GitHub API HTTP client (already in workspace) |
| `octocrab` | 0.38 | GitHub API client library |
| `regex` | 1 | Pattern matching for secret formats |

Add to `pqvault-scan-mcp/Cargo.toml`:

```toml
[dependencies]
octocrab = "0.38"
regex = "1"
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_generation() {
        let fp = SecretFingerprint::from_value("API_KEY", "sk_live_51NqOz7abc123xyz");
        assert_eq!(fp.prefix, "sk_l");
        assert_eq!(fp.suffix, "3xyz");
        assert_eq!(fp.value_length, 22);
        assert!(fp.provider_pattern.is_some());
    }

    #[test]
    fn test_pattern_matching_stripe() {
        let fp = SecretFingerprint::from_value("STRIPE_KEY", "sk_live_51NqOz7abc123xyz");
        let code_line = "const key = \"sk_live_51NqOz7abc123xyz\";";
        let result = fp.matches(code_line);
        assert!(result.is_some());
        assert_eq!(result.unwrap().confidence, 1.0);
    }

    #[test]
    fn test_pattern_no_false_positive() {
        let fp = SecretFingerprint::from_value("STRIPE_KEY", "sk_live_51NqOz7abc123xyz");
        let code_line = "const key = \"sk_test_different_key\";";
        let result = fp.matches(code_line);
        assert!(result.is_none() || result.unwrap().confidence < 0.5);
    }

    #[test]
    fn test_severity_classification() {
        let finding = ScanFinding {
            confidence: 1.0,
            key_name: "STRIPE_SECRET".into(),
            ..mock_finding()
        };
        assert!(matches!(finding.severity, FindingSeverity::Critical));
    }

    #[test]
    fn test_scan_target_parsing() {
        let target = parse_scan_target("myorg/api-server", "recent").unwrap();
        assert_eq!(target.owner, "myorg");
        assert_eq!(target.repo, "api-server");
        assert!(matches!(target.scan_depth, ScanDepth::Recent(_)));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_scan_mock_repo() {
    let scanner = GitHubScanner::with_mock_client(vec![
        mock_commit("abc123", "config.js", "const key = \"sk_live_test123\";"),
    ]);
    let vault_fps = vec![
        SecretFingerprint::from_value("STRIPE_KEY", "sk_live_test123"),
    ];
    scanner.set_fingerprints(vault_fps);
    let result = scanner.scan_repository(&ScanTarget {
        owner: "testorg".into(),
        repo: "testrepo".into(),
        branch: None,
        scan_depth: ScanDepth::Latest,
    }).await.unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].key_name, "STRIPE_KEY");
}
```

## Example Usage

```
$ pqvault scan github myorg/api-server --depth recent

  GitHub Secret Scan: myorg/api-server
  ════════════════════════════════════════════════

  Scanned: 47 commits, 312 files
  Duration: 8.3s

  FINDINGS (2):

  [CRITICAL] STRIPE_SECRET_KEY
    File:   src/payments/config.ts:14
    Commit: abc1234 (2025-03-10 by alice@team.com)
    URL:    https://github.com/myorg/api-server/blob/abc1234/src/payments/config.ts#L14
    Match:  sk_live_51N████████████████████xyz (exact match)
    Action: ROTATE IMMEDIATELY

  [HIGH] DATABASE_URL
    File:   docker-compose.yml:22
    Commit: def5678 (2025-03-08 by bob@team.com)
    URL:    https://github.com/myorg/api-server/blob/def5678/docker-compose.yml#L22
    Match:  postgres://user:████@db.internal:5432/app (pattern match)
    Action: Investigate — may be dev credentials

  ════════════════════════════════════════════════
  Run `pqvault scan github myorg/api-server --auto-rotate` to rotate compromised keys.
```
