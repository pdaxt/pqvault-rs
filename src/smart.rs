use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::SecretEntry;
use crate::providers::{detect_provider, get_provider, PROVIDERS};

fn vault_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".pqvault")
}
fn usage_file() -> PathBuf {
    vault_dir().join("usage.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill: f64,
    pub capacity: u32,
    pub refill_rate: f64,
}

impl TokenBucket {
    pub fn from_rpm(rpm: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        Self {
            tokens: rpm as f64,
            last_refill: now,
            capacity: rpm,
            refill_rate: rpm as f64 / 60.0,
        }
    }

    pub fn try_consume(&mut self) -> (bool, f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let elapsed = now - self.last_refill;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            (true, 0.0)
        } else {
            let wait = (1.0 - self.tokens) / self.refill_rate;
            (false, wait)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyUsage {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub total_requests: u64,
    #[serde(default)]
    pub daily_counts: HashMap<String, u64>,
    #[serde(default)]
    pub monthly_counts: HashMap<String, u64>,
    #[serde(default)]
    pub last_used: Option<String>,
    #[serde(default)]
    pub first_used: Option<String>,
    #[serde(default)]
    pub estimated_cost_usd: f64,
    #[serde(default)]
    pub token_bucket: Option<TokenBucket>,
    #[serde(default)]
    pub alerts: Vec<AlertEntry>,
    #[serde(default)]
    pub recent_callers: Vec<CallerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEntry {
    #[serde(rename = "type")]
    pub alert_type: String,
    pub message: String,
    pub severity: String,
    pub ts: String,
    #[serde(default)]
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerEntry {
    pub ts: String,
    pub caller: String,
}

impl KeyUsage {
    pub fn requests_today(&self) -> u64 {
        let today = Local::now().format("%Y-%m-%d").to_string();
        *self.daily_counts.get(&today).unwrap_or(&0)
    }

    pub fn requests_this_month(&self) -> u64 {
        let month = Local::now().format("%Y-%m").to_string();
        *self.monthly_counts.get(&month).unwrap_or(&0)
    }
}

pub struct RateLimitResult {
    pub allowed: bool,
    pub reason: String,
    pub usage_pct: f64,
    pub remaining: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UsageData {
    version: u32,
    updated: String,
    keys: HashMap<String, KeyUsage>,
}

pub struct UsageTracker {
    data: HashMap<String, KeyUsage>,
}

impl UsageTracker {
    pub fn new() -> Self {
        let mut tracker = Self {
            data: HashMap::new(),
        };
        tracker.load();
        tracker
    }

    fn load(&mut self) {
        let path = usage_file();
        if !path.exists() {
            return;
        }
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(raw) = serde_json::from_str::<UsageData>(&content) {
                self.data = raw.keys;
            }
        }
    }

    pub fn save(&self) {
        let dir = vault_dir();
        let _ = fs::create_dir_all(&dir);

        // Prune daily counts older than 90 days
        let cutoff = (Local::now() - chrono::Duration::days(90))
            .format("%Y-%m-%d")
            .to_string();

        let mut keys = self.data.clone();
        for usage in keys.values_mut() {
            usage.daily_counts.retain(|d, _| d.as_str() >= cutoff.as_str());
        }

        let payload = UsageData {
            version: 1,
            updated: Local::now().to_rfc3339(),
            keys,
        };

        if let Ok(json) = serde_json::to_string_pretty(&payload) {
            let _ = fs::write(usage_file(), json);
        }
    }

    pub fn ensure_key(&mut self, key_name: &str, value: &str) -> &mut KeyUsage {
        if !self.data.contains_key(key_name) {
            let provider = detect_provider(key_name, value).unwrap_or_default();
            let mut usage = KeyUsage {
                provider: provider.clone(),
                ..Default::default()
            };

            if let Some(prov) = get_provider(&provider) {
                if let Some(rpm) = prov.requests_per_minute {
                    usage.token_bucket = Some(TokenBucket::from_rpm(rpm));
                }
            }

            self.data.insert(key_name.to_string(), usage);
        }
        self.data.get_mut(key_name).unwrap()
    }

    pub fn check_rate_limit(&mut self, key_name: &str) -> RateLimitResult {
        let usage = match self.data.get_mut(key_name) {
            Some(u) => u,
            None => {
                return RateLimitResult {
                    allowed: true,
                    reason: String::new(),
                    usage_pct: 0.0,
                    remaining: -1,
                }
            }
        };

        if usage.provider.is_empty() {
            return RateLimitResult {
                allowed: true,
                reason: String::new(),
                usage_pct: 0.0,
                remaining: -1,
            };
        }

        let prov = match get_provider(&usage.provider) {
            Some(p) => p.clone(),
            None => {
                return RateLimitResult {
                    allowed: true,
                    reason: String::new(),
                    usage_pct: 0.0,
                    remaining: -1,
                }
            }
        };

        let today = Local::now().format("%Y-%m-%d").to_string();
        let this_month = Local::now().format("%Y-%m").to_string();

        // Token bucket (per-minute)
        if let (Some(ref mut bucket), Some(rpm)) =
            (usage.token_bucket.as_mut(), prov.requests_per_minute)
        {
            let (allowed, wait) = bucket.try_consume();
            if !allowed {
                return RateLimitResult {
                    allowed: false,
                    reason: format!("Per-minute limit ({}/min). Wait {:.1}s.", rpm, wait),
                    usage_pct: 100.0,
                    remaining: 0,
                };
            }
        }

        // Daily limit
        if let Some(daily_limit) = prov.requests_per_day {
            let daily = *usage.daily_counts.get(&today).unwrap_or(&0);
            if daily >= daily_limit as u64 {
                return RateLimitResult {
                    allowed: false,
                    reason: format!("Daily limit reached: {}/{}", daily, daily_limit),
                    usage_pct: 100.0,
                    remaining: 0,
                };
            }
        }

        // Monthly limit
        if let Some(monthly_limit) = prov.requests_per_month {
            let monthly = *usage.monthly_counts.get(&this_month).unwrap_or(&0);
            if monthly >= monthly_limit as u64 {
                return RateLimitResult {
                    allowed: false,
                    reason: format!("Monthly limit reached: {}/{}", monthly, monthly_limit),
                    usage_pct: 100.0,
                    remaining: 0,
                };
            }
            let remaining = monthly_limit as i64 - monthly as i64;
            let pct = (monthly as f64 / monthly_limit as f64) * 100.0;
            return RateLimitResult {
                allowed: true,
                reason: String::new(),
                usage_pct: pct,
                remaining,
            };
        }

        RateLimitResult {
            allowed: true,
            reason: String::new(),
            usage_pct: 0.0,
            remaining: -1,
        }
    }

    pub fn record_access(&mut self, key_name: &str, caller: &str) {
        let usage = match self.data.get_mut(key_name) {
            Some(u) => u,
            None => {
                self.ensure_key(key_name, "");
                self.data.get_mut(key_name).unwrap()
            }
        };

        let now = Local::now();
        let today = now.format("%Y-%m-%d").to_string();
        let this_month = now.format("%Y-%m").to_string();

        usage.total_requests += 1;
        usage.last_used = Some(now.to_rfc3339());
        if usage.first_used.is_none() {
            usage.first_used = Some(now.to_rfc3339());
        }

        *usage.daily_counts.entry(today).or_insert(0) += 1;
        *usage.monthly_counts.entry(this_month).or_insert(0) += 1;

        usage.recent_callers.push(CallerEntry {
            ts: now.to_rfc3339(),
            caller: caller.to_string(),
        });
        if usage.recent_callers.len() > 20 {
            let start = usage.recent_callers.len() - 20;
            usage.recent_callers = usage.recent_callers[start..].to_vec();
        }

        if let Some(prov) = get_provider(&usage.provider) {
            if prov.cost_per_request > 0.0 {
                usage.estimated_cost_usd += prov.cost_per_request;
            }
        }

        self.save();
    }

    pub fn check_smart_alerts(&mut self, key_name: &str, rotated: &str, rotation_days: i64) {
        let usage = match self.data.get_mut(key_name) {
            Some(u) => u,
            None => return,
        };

        let now = Local::now();

        // Unused key (30+ days)
        if let Some(ref last) = usage.last_used {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last) {
                let days_idle = (now.signed_duration_since(dt)).num_days();
                if days_idle > 30 {
                    add_alert(
                        usage,
                        "unused_key",
                        &format!("Unused for {} days. Consider revoking.", days_idle),
                        "warning",
                    );
                }
            }
        }

        // Rotation due
        if !rotated.is_empty() {
            if let Ok(rot_date) = NaiveDate::parse_from_str(rotated, "%Y-%m-%d") {
                let key_age = (now.date_naive() - rot_date).num_days();
                let prov = get_provider(&usage.provider);
                let rot_days = prov.map_or(rotation_days, |p| p.rotation_days);
                if key_age > rot_days {
                    let severity = if key_age > rot_days * 3 / 2 {
                        "critical"
                    } else {
                        "warning"
                    };
                    add_alert(
                        usage,
                        "rotation_due",
                        &format!("Key age: {}d. Recommended: every {}d.", key_age, rot_days),
                        severity,
                    );
                }
            }
        }

        // Usage spike (>3x 7-day average)
        let daily_vals: Vec<u64> = usage.daily_counts.values().copied().collect();
        if daily_vals.len() >= 7 {
            let last_7: Vec<u64> = daily_vals.iter().rev().take(7).copied().collect();
            let avg = last_7.iter().sum::<u64>() as f64 / 7.0;
            let today_count = usage.requests_today() as f64;
            if avg > 0.0 && today_count > avg * 3.0 {
                add_alert(
                    usage,
                    "usage_spike",
                    &format!(
                        "Today ({}) is {:.1}x the 7-day avg ({:.0}).",
                        today_count,
                        today_count / avg,
                        avg
                    ),
                    "warning",
                );
            }
        }
    }

    pub fn get_usage(&self, key_name: &str) -> Option<&KeyUsage> {
        self.data.get(key_name)
    }

    pub fn get_active_alerts(&self) -> Vec<(String, AlertEntry)> {
        let mut alerts = Vec::new();
        for (key_name, usage) in &self.data {
            for a in &usage.alerts {
                if !a.acknowledged {
                    alerts.push((key_name.clone(), a.clone()));
                }
            }
        }
        alerts
    }
}

fn add_alert(usage: &mut KeyUsage, alert_type: &str, message: &str, severity: &str) {
    let now = Local::now();
    // Don't add duplicate recent alerts
    for a in &usage.alerts {
        if a.alert_type == alert_type && !a.acknowledged {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&a.ts) {
                if (now.signed_duration_since(dt)).num_seconds() < 3600 {
                    return;
                }
            }
        }
    }

    usage.alerts.push(AlertEntry {
        alert_type: alert_type.to_string(),
        message: message.to_string(),
        severity: severity.to_string(),
        ts: now.to_rfc3339(),
        acknowledged: false,
    });

    if usage.alerts.len() > 50 {
        let start = usage.alerts.len() - 50;
        usage.alerts = usage.alerts[start..].to_vec();
    }
}

pub fn generate_dashboard(
    secrets: &HashMap<String, SecretEntry>,
    tracker: &UsageTracker,
) -> String {
    let today = Local::now().format("%Y-%m-%d").to_string();

    let mut lines = vec![
        "## PQVault Smart Dashboard".to_string(),
        String::new(),
        format!(
            "**Total Keys:** {} | **Date:** {} | **Encryption:** ML-KEM-768 + X25519 + AES-256-GCM",
            secrets.len(),
            today
        ),
        String::new(),
    ];

    // Active alerts
    let alerts = tracker.get_active_alerts();
    if !alerts.is_empty() {
        lines.push("### Active Alerts".to_string());
        lines.push(String::new());
        for (key, a) in &alerts {
            let icon = match a.severity.as_str() {
                "critical" => "!!",
                "warning" => "!",
                _ => "i",
            };
            lines.push(format!("- [{}] **{}**: {}", icon, key, a.message));
        }
        lines.push(String::new());
    }

    if !secrets.is_empty() {
        lines.push("### Keys Overview".to_string());
        lines.push(String::new());
        lines.push(
            "| Key | Category | Provider | Today | Month | Limit % | Last Used | Health |"
                .to_string(),
        );
        lines.push(
            "|-----|----------|----------|-------|-------|---------|-----------|--------|"
                .to_string(),
        );

        let mut total_cost = 0.0f64;
        let mut sorted_keys: Vec<&String> = secrets.keys().collect();
        sorted_keys.sort();

        for name in &sorted_keys {
            let secret = &secrets[*name];
            let usage = tracker.get_usage(name);
            let provider_str = usage
                .and_then(|u| {
                    if u.provider.is_empty() {
                        None
                    } else {
                        PROVIDERS
                            .get(&u.provider)
                            .map(|p| p.display_name.clone())
                    }
                })
                .unwrap_or_else(|| "-".to_string());

            let today_n = usage.map_or(0, |u| u.requests_today());
            let month_n = usage.map_or(0, |u| u.requests_this_month());

            let provider_name = usage.map(|u| u.provider.as_str()).unwrap_or("");
            let prov_cfg = get_provider(provider_name);
            let limit_pct = if let Some(p) = prov_cfg {
                if let Some(monthly) = p.requests_per_month {
                    format!("{}%", (month_n as f64 / monthly as f64 * 100.0) as u32)
                } else if let Some(daily) = p.requests_per_day {
                    format!("{}%", (today_n as f64 / daily as f64 * 100.0) as u32)
                } else {
                    "-".to_string()
                }
            } else {
                "-".to_string()
            };

            let last_used = usage
                .and_then(|u| u.last_used.as_deref())
                .map(|s| time_since(s))
                .unwrap_or_else(|| "never".to_string());

            let mut health = "OK".to_string();
            if let Ok(rot_date) = NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d") {
                let key_age = (Local::now().date_naive() - rot_date).num_days();
                let rot_limit = prov_cfg.map_or(secret.rotation_days, |p| p.rotation_days);
                if key_age > rot_limit {
                    health = "ROTATE".to_string();
                }
            }

            if let Some(u) = usage {
                total_cost += u.estimated_cost_usd;
                if u.alerts.iter().any(|a| a.severity == "critical" && !a.acknowledged) {
                    health = "ALERT".to_string();
                }
            }

            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                name, secret.category, provider_str, today_n, month_n, limit_pct, last_used, health
            ));
        }

        if total_cost > 0.0 {
            lines.push(String::new());
            lines.push("### Estimated Costs".to_string());
            lines.push(String::new());
            lines.push(format!("**Total:** ${:.4}", total_cost));
        }
    } else {
        lines.push(
            "No keys stored yet. Use `vault_add` or `vault_import_claude` to get started."
                .to_string(),
        );
    }

    lines.join("\n")
}

pub fn generate_key_status(
    key_name: &str,
    secret: &SecretEntry,
    tracker: &UsageTracker,
) -> String {
    let usage = tracker.get_usage(key_name).cloned().unwrap_or_default();
    let prov = get_provider(&usage.provider);
    let prov_name = prov
        .map(|p| p.display_name.clone())
        .unwrap_or_else(|| usage.provider.clone());

    let key_age = NaiveDate::parse_from_str(&secret.rotated, "%Y-%m-%d")
        .map(|d| (Local::now().date_naive() - d).num_days())
        .unwrap_or(0);
    let rot_days = prov.map_or(secret.rotation_days, |p| p.rotation_days);

    let mut lines = vec![
        format!("## {} Status", key_name),
        String::new(),
        format!("**Provider:** {}", prov_name),
        format!("**Category:** {}", secret.category),
        format!("**Created:** {}", secret.created),
        format!("**Last Rotated:** {}", secret.rotated),
        format!(
            "**Age:** {}d (rotation recommended: {}d)",
            key_age, rot_days
        ),
        String::new(),
        "### Usage".to_string(),
        format!("- Total: {}", usage.total_requests),
        format!("- Today: {}", usage.requests_today()),
        format!("- This month: {}", usage.requests_this_month()),
        format!(
            "- Last used: {}",
            usage.last_used.as_deref().unwrap_or("never")
        ),
        format!("- Est. cost: ${:.4}", usage.estimated_cost_usd),
        String::new(),
        "### Rate Limits".to_string(),
    ];

    if let Some(p) = prov {
        if let Some(rpm) = p.requests_per_minute {
            lines.push(format!("- Per minute: {}", rpm));
        }
        if let Some(daily) = p.requests_per_day {
            lines.push(format!("- Per day: {}/{}", usage.requests_today(), daily));
        }
        if let Some(monthly) = p.requests_per_month {
            lines.push(format!(
                "- Per month: {}/{}",
                usage.requests_this_month(),
                monthly
            ));
        }
    } else {
        lines.push("- No provider-specific limits configured".to_string());
    }

    let active_alerts: Vec<&AlertEntry> = usage.alerts.iter().filter(|a| !a.acknowledged).collect();
    if !active_alerts.is_empty() {
        lines.push(String::new());
        lines.push(format!("### Alerts ({})", active_alerts.len()));
        for a in active_alerts {
            lines.push(format!("- [{}] {}", a.severity, a.message));
        }
    }

    lines.join("\n")
}

fn time_since(iso_str: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(iso_str) {
        let secs = (Local::now().signed_duration_since(dt)).num_seconds();
        if secs < 60 {
            "just now".to_string()
        } else if secs < 3600 {
            format!("{}m ago", secs / 60)
        } else if secs < 86400 {
            format!("{}h ago", secs / 3600)
        } else {
            format!("{}d ago", secs / 86400)
        }
    } else {
        iso_str.to_string()
    }
}
