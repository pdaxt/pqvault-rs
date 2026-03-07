use chrono::{Local, NaiveDate};
use std::collections::HashMap;

use crate::models::VaultData;

#[derive(Debug)]
pub struct HealthReport {
    pub total_secrets: usize,
    pub expired: Vec<String>,
    pub needs_rotation: Vec<String>,
    pub orphaned: Vec<String>,
    pub by_category: HashMap<String, usize>,
    pub by_lifecycle: HashMap<String, usize>,
    pub deprecated: Vec<String>,
    pub disabled: Vec<String>,
    pub error_keys: Vec<String>,
    pub expiring_soon: Vec<(String, i64)>, // key, days_until_expiry
    pub dead_keys: Vec<DeadKeyInfo>,
    pub duplicates: Vec<DuplicateGroup>,
    pub key_scores: Vec<KeyHealthScore>,
}

/// A key that hasn't been used in a long time
#[derive(Debug)]
pub struct DeadKeyInfo {
    pub name: String,
    pub category: String,
    pub days_unused: i64,
    pub recommendation: String,
}

/// A group of keys with identical values (potential duplicates)
#[derive(Debug)]
pub struct DuplicateGroup {
    pub value_hash: String,
    pub keys: Vec<String>,
}

/// Health score for a key (0-100)
#[derive(Debug)]
pub struct KeyHealthScore {
    pub name: String,
    pub score: u8,
    pub issues: Vec<String>,
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        self.expired.is_empty() && self.needs_rotation.is_empty() && self.error_keys.is_empty()
    }
}

pub fn check_health(vault: &VaultData) -> HealthReport {
    use sha2::{Digest, Sha256};

    let today = Local::now().date_naive();
    let mut report = HealthReport {
        total_secrets: 0,
        expired: vec![],
        needs_rotation: vec![],
        orphaned: vec![],
        by_category: HashMap::new(),
        by_lifecycle: HashMap::new(),
        deprecated: vec![],
        disabled: vec![],
        error_keys: vec![],
        expiring_soon: vec![],
        dead_keys: vec![],
        duplicates: vec![],
        key_scores: vec![],
    };

    // Track value hashes for duplicate detection
    let mut value_hashes: HashMap<String, Vec<String>> = HashMap::new();

    for (name, secret) in &vault.secrets {
        report.total_secrets += 1;
        *report
            .by_category
            .entry(secret.category.clone())
            .or_insert(0) += 1;
        *report
            .by_lifecycle
            .entry(secret.lifecycle.clone())
            .or_insert(0) += 1;

        // Key health scoring
        let mut score: u8 = 100;
        let mut issues = Vec::new();

        // Lifecycle checks
        if secret.lifecycle == "deprecated" {
            report.deprecated.push(name.clone());
            score = score.saturating_sub(20);
            issues.push("deprecated".to_string());
        }
        if secret.lifecycle == "disabled" {
            report.disabled.push(name.clone());
            score = score.saturating_sub(40);
            issues.push("disabled".to_string());
        }

        // Key status check
        if secret.key_status == "error" {
            report.error_keys.push(name.clone());
            score = score.saturating_sub(30);
            issues.push("key error".to_string());
        }

        // Dead key detection (created > 180 days ago with no rotation)
        if secret.lifecycle == "active" {
            if let Ok(created) = NaiveDate::parse_from_str(&secret.created, "%Y-%m-%d") {
                let age_days = (today - created).num_days();
                if let Ok(rotated) = NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d") {
                    let since_rotation = (today - rotated).num_days();
                    if since_rotation > 180 && age_days > 180 {
                        let rec = if since_rotation > 365 {
                            "Archive or delete - unused for over a year"
                        } else {
                            "Consider archiving - unused for 6+ months"
                        };
                        report.dead_keys.push(DeadKeyInfo {
                            name: name.clone(),
                            category: secret.category.clone(),
                            days_unused: since_rotation,
                            recommendation: rec.to_string(),
                        });
                        score = score.saturating_sub(15);
                        issues.push(format!("unused {}d", since_rotation));
                    }
                }
            }
        }

        // Duplicate detection via value hash
        let hash = format!("{:x}", Sha256::digest(secret.value.as_bytes()));
        let short_hash = hash[..8].to_string();
        value_hashes
            .entry(short_hash)
            .or_default()
            .push(name.clone());

        // Skip non-active keys for rotation/expiry checks
        if secret.lifecycle != "active" {
            report.key_scores.push(KeyHealthScore {
                name: name.clone(),
                score,
                issues,
            });
            continue;
        }

        // Expiry check
        if let Some(ref expires) = secret.expires {
            if let Ok(exp) = NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
                let days_until = (exp - today).num_days();
                if days_until <= 0 {
                    report.expired.push(name.clone());
                    score = score.saturating_sub(25);
                    issues.push("expired".to_string());
                } else if days_until <= 14 {
                    report.expiring_soon.push((name.clone(), days_until));
                    score = score.saturating_sub(10);
                    issues.push(format!("expires in {}d", days_until));
                }
            }
        }

        // Rotation check (use policy if set, fallback to rotation_days)
        let rotation_days = secret
            .rotation_policy
            .as_ref()
            .map(|p| p.interval_days)
            .unwrap_or(secret.rotation_days);

        if rotation_days > 0 {
            if let Ok(last_rotated) = NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d") {
                let due = last_rotated + chrono::Duration::days(rotation_days);
                if due <= today {
                    report.needs_rotation.push(name.clone());
                    score = score.saturating_sub(15);
                    issues.push("needs rotation".to_string());
                }
            }
        }

        // No description
        if secret.description.is_empty() {
            score = score.saturating_sub(5);
            issues.push("no description".to_string());
        }

        // Orphan check
        if secret.projects.is_empty() {
            report.orphaned.push(name.clone());
            score = score.saturating_sub(5);
            issues.push("no project".to_string());
        }

        report.key_scores.push(KeyHealthScore {
            name: name.clone(),
            score,
            issues,
        });
    }

    // Build duplicate groups (only groups with 2+ keys)
    for (hash, keys) in value_hashes {
        if keys.len() > 1 {
            report.duplicates.push(DuplicateGroup {
                value_hash: hash,
                keys,
            });
        }
    }

    // Sort key scores by score ascending (worst first)
    report.key_scores.sort_by(|a, b| a.score.cmp(&b.score));

    report
}
