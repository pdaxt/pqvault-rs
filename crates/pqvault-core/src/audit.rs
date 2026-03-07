use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::crypto::{password_decrypt, password_encrypt};
use crate::keychain::get_master_password;

fn vault_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault")
}

fn audit_log_path() -> PathBuf {
    vault_dir().join("audit.log")
}

fn encrypted_audit_path() -> PathBuf {
    vault_dir().join("audit.enc")
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

/// Read all audit entries from encrypted storage, with fallback to plaintext
fn read_all_entries() -> Vec<AuditEntry> {
    // Try encrypted format first
    let enc_path = encrypted_audit_path();
    if enc_path.exists() {
        if let Ok(pw) = get_master_password() {
            if let Some(pw) = pw {
                if let Ok(encrypted) = fs::read(&enc_path) {
                    if let Ok(plaintext) = password_decrypt(&encrypted, &pw) {
                        if let Ok(content) = String::from_utf8(plaintext) {
                            return content
                                .lines()
                                .filter(|l| !l.trim().is_empty())
                                .filter_map(|l| serde_json::from_str(l).ok())
                                .collect();
                        }
                    }
                }
            }
        }
    }

    // Fall back to plaintext format (migration)
    let path = audit_log_path();
    if !path.exists() {
        return vec![];
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Write all audit entries to encrypted storage
fn write_all_entries(entries: &[AuditEntry]) -> bool {
    if let Ok(Some(pw)) = get_master_password() {
        let content: String = entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n");

        if let Ok(encrypted) = password_encrypt(content.as_bytes(), &pw) {
            let dir = vault_dir();
            let _ = fs::create_dir_all(&dir);
            if fs::write(encrypted_audit_path(), &encrypted).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(
                        encrypted_audit_path(),
                        fs::Permissions::from_mode(0o600),
                    );
                }
                // Remove plaintext if it exists (migration complete)
                let _ = fs::remove_file(audit_log_path());
                return true;
            }
        }
    }
    false
}

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

    // Try encrypted append
    let mut entries = read_all_entries();

    // Rotate if needed
    if entries.len() >= MAX_LOG_LINES {
        rotate_logs_encrypted(&entries);
        // Keep only the most recent half after rotation
        let start = entries.len().saturating_sub(MAX_LOG_LINES / 2);
        entries = entries[start..].to_vec();
    }

    entries.push(entry.clone());

    if write_all_entries(&entries) {
        return;
    }

    // Fallback: append to plaintext (no password available yet, e.g. during init)
    let path = audit_log_path();
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

fn rotate_logs_encrypted(entries: &[AuditEntry]) {
    // Save current entries as a rotated encrypted file
    if let Ok(Some(pw)) = get_master_password() {
        let content: String = entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n");

        // Shift existing rotated files
        let base_name = "audit.enc";
        for i in (1..MAX_ROTATED_FILES).rev() {
            let from = vault_dir().join(format!("{}.{}", base_name, i));
            let to = vault_dir().join(format!("{}.{}", base_name, i + 1));
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }
        // Remove oldest
        let oldest = vault_dir().join(format!("{}.{}", base_name, MAX_ROTATED_FILES));
        let _ = fs::remove_file(&oldest);

        // Current → .1
        if let Ok(encrypted) = password_encrypt(content.as_bytes(), &pw) {
            let rotated = vault_dir().join(format!("{}.1", base_name));
            let _ = fs::write(&rotated, &encrypted);
        }
    }
}

pub fn read_log(key_filter: &str, limit: usize) -> Vec<AuditEntry> {
    let entries = read_all_entries();
    let filtered: Vec<AuditEntry> = entries
        .into_iter()
        .filter(|e| key_filter.is_empty() || e.key == key_filter)
        .collect();

    let start = if filtered.len() > limit {
        filtered.len() - limit
    } else {
        0
    };
    filtered[start..].to_vec()
}

/// Migrate plaintext audit log to encrypted format
pub fn migrate_to_encrypted() -> anyhow::Result<usize> {
    let plaintext_path = audit_log_path();
    if !plaintext_path.exists() {
        return Ok(0);
    }

    let entries = read_all_entries();
    if entries.is_empty() {
        return Ok(0);
    }

    let count = entries.len();
    if write_all_entries(&entries) {
        // Plaintext file is removed by write_all_entries
        Ok(count)
    } else {
        anyhow::bail!("Failed to encrypt audit log. Is the vault initialized?")
    }
}
