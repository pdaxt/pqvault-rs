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
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        self.expired.is_empty() && self.needs_rotation.is_empty()
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
    };

    for (name, secret) in &vault.secrets {
        report.total_secrets += 1;
        *report
            .by_category
            .entry(secret.category.clone())
            .or_insert(0) += 1;

        // Expiry check
        if let Some(ref expires) = secret.expires {
            if let Ok(exp) = NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
                if exp <= today {
                    report.expired.push(name.clone());
                }
            }
        }

        // Rotation check
        if secret.rotation_days > 0 {
            if let Ok(last_rotated) = NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d") {
                let due = last_rotated + chrono::Duration::days(secret.rotation_days);
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
