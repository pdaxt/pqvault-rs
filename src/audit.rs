use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

fn vault_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault")
}

fn audit_log_path() -> PathBuf {
    vault_dir().join("audit.log")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub action: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub agent: String,
}

const MAX_LOG_LINES: usize = 10_000;
const MAX_ROTATED_FILES: usize = 3;

pub fn log_access(action: &str, key: &str, project: &str, agent: &str) {
    let dir = vault_dir();
    let _ = fs::create_dir_all(&dir);

    let entry = AuditEntry {
        ts: Local::now().to_rfc3339(),
        action: action.to_string(),
        key: key.to_string(),
        project: project.to_string(),
        agent: agent.to_string(),
    };

    let path = audit_log_path();

    // Rotate if needed
    if let Ok(content) = fs::read_to_string(&path) {
        let line_count = content.lines().count();
        if line_count >= MAX_LOG_LINES {
            rotate_logs();
        }
    }

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = writeln!(f, "{}", json);
        }
    }
}

fn rotate_logs() {
    let base = audit_log_path();

    // Remove oldest rotated file
    let oldest = vault_dir().join(format!("audit.log.{}", MAX_ROTATED_FILES));
    let _ = fs::remove_file(&oldest);

    // Shift existing rotated files: .2 → .3, .1 → .2
    for i in (1..MAX_ROTATED_FILES).rev() {
        let from = vault_dir().join(format!("audit.log.{}", i));
        let to = vault_dir().join(format!("audit.log.{}", i + 1));
        if from.exists() {
            let _ = fs::rename(&from, &to);
        }
    }

    // Current log → .1
    let rotated = vault_dir().join("audit.log.1");
    let _ = fs::rename(&base, &rotated);
}

pub fn read_log(key_filter: &str, limit: usize) -> Vec<AuditEntry> {
    let path = audit_log_path();
    if !path.exists() {
        return vec![];
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let entries: Vec<AuditEntry> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &AuditEntry| key_filter.is_empty() || e.key == key_filter)
        .collect();

    let start = if entries.len() > limit {
        entries.len() - limit
    } else {
        0
    };
    entries[start..].to_vec()
}
