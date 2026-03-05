use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "today_str")]
    pub created: String,
    #[serde(default = "today_str")]
    pub rotated: String,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default = "default_rotation_days")]
    pub rotation_days: i64,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectEntry {
    pub path: String,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default = "default_env_file")]
    pub env_file: String,
    #[serde(default)]
    pub env_extras: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "now_iso")]
    pub created: String,
    #[serde(default)]
    pub secrets: HashMap<String, SecretEntry>,
    #[serde(default)]
    pub projects: HashMap<String, ProjectEntry>,
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            created: now_iso(),
            secrets: HashMap::new(),
            projects: HashMap::new(),
        }
    }
}

fn default_category() -> String {
    "general".to_string()
}
fn today_str() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}
fn now_iso() -> String {
    Local::now().to_rfc3339()
}
fn default_rotation_days() -> i64 {
    90
}
fn default_env_file() -> String {
    ".env.local".to_string()
}
fn default_version() -> String {
    "1.0".to_string()
}

/// Category patterns for auto-detection
pub fn category_patterns() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "ai",
            vec![
                "ANTHROPIC",
                "OPENAI",
                "HF_TOKEN",
                "HUGGING",
                "REPLICATE",
                "STABILITY",
                "ELEVENLABS",
                "CLAUDE",
            ],
        ),
        ("payment", vec!["STRIPE", "PAYPAL", "RAZORPAY"]),
        (
            "cloud",
            vec![
                "AWS",
                "GCP",
                "GOOGLE_APPLICATION",
                "CLOUDFLARE",
                "VERCEL",
                "FIREBASE",
            ],
        ),
        (
            "social",
            vec![
                "TWITTER",
                "X_API",
                "X_ACCESS",
                "LINKEDIN",
                "INSTAGRAM",
                "FACEBOOK",
                "UNSPLASH",
            ],
        ),
        (
            "email",
            vec!["RESEND", "SENDGRID", "MAILGUN", "GMAIL", "SMTP", "EMAIL"],
        ),
        (
            "database",
            vec![
                "SUPABASE",
                "POSTGRES",
                "MYSQL",
                "REDIS",
                "MONGO",
                "DATABASE_URL",
                "DB",
            ],
        ),
        (
            "auth",
            vec!["SESSION_SECRET", "JWT", "OAUTH", "AUTH", "GOOGLE_CLIENT"],
        ),
        ("search", vec!["SERPER", "SERPAPI", "ALGOLIA"]),
    ]
}

/// Check if pattern appears at a word boundary in haystack.
/// Word separators: start/end of string, underscore, hyphen, non-alphanumeric.
/// "AWS" matches "AWS_KEY", "MY_AWS", "MY-AWS" but NOT "MY_AWESOME".
fn word_boundary_match(haystack: &str, needle: &str) -> bool {
    if let Some(pos) = haystack.find(needle) {
        let before_ok = pos == 0 || !haystack.as_bytes()[pos - 1].is_ascii_alphabetic();
        let after_pos = pos + needle.len();
        let after_ok =
            after_pos >= haystack.len() || !haystack.as_bytes()[after_pos].is_ascii_alphabetic();
        before_ok && after_ok
    } else {
        false
    }
}

pub fn auto_categorize(key_name: &str) -> String {
    let upper = key_name.to_uppercase();
    for (category, patterns) in category_patterns() {
        for pattern in patterns {
            if word_boundary_match(&upper, pattern) {
                return category.to_string();
            }
        }
    }
    "general".to_string()
}
