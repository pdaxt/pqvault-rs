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
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        self.expired.is_empty() && self.needs_rotation.is_empty() && self.error_keys.is_empty()
    }
}

pub fn check_health(vault: &VaultData) -> HealthReport {
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
    };

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

        // Lifecycle checks
        if secret.lifecycle == "deprecated" {
            report.deprecated.push(name.clone());
        }
        if secret.lifecycle == "disabled" {
            report.disabled.push(name.clone());
        }

        // Key status check
        if secret.key_status == "error" {
            report.error_keys.push(name.clone());
        }

        // Skip non-active keys for rotation/expiry checks
        if secret.lifecycle != "active" {
            continue;
        }

        // Expiry check
        if let Some(ref expires) = secret.expires {
            if let Ok(exp) = NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
                let days_until = (exp - today).num_days();
                if days_until <= 0 {
                    report.expired.push(name.clone());
                } else if days_until <= 14 {
                    report.expiring_soon.push((name.clone(), days_until));
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
                }
            }
        }

        // Orphan check
        if secret.projects.is_empty() {
            report.orphaned.push(name.clone());
        }
    }

    report
}
