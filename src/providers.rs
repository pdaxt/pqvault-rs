use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Authorization: Bearer <key>
    BearerToken,
    /// Custom header: <header_name>: <key>
    CustomHeader { header_name: String },
    /// Authorization: Basic base64(<key>:)
    BasicAuth,
    /// ?<param_name>=<key> appended to URL
    QueryParam { param_name: String },
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub display_name: String,
    pub requests_per_minute: Option<u32>,
    pub requests_per_day: Option<u32>,
    pub requests_per_month: Option<u32>,
    pub cost_per_request: f64,
    pub key_pattern: Option<String>,
    pub rotation_days: i64,
    pub base_url: Option<String>,
    pub auth_method: Option<AuthMethod>,
    pub allowed_domains: Vec<String>,
}

pub static PROVIDERS: LazyLock<HashMap<String, ProviderConfig>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "anthropic".into(),
        ProviderConfig {
            name: "anthropic".into(),
            display_name: "Anthropic".into(),
            requests_per_minute: Some(50),
            requests_per_day: Some(10000),
            requests_per_month: None,
            cost_per_request: 0.003,
            key_pattern: Some(r"^sk-ant-".into()),
            rotation_days: 90,
            base_url: Some("https://api.anthropic.com".into()),
            auth_method: Some(AuthMethod::CustomHeader {
                header_name: "x-api-key".into(),
            }),
            allowed_domains: vec!["api.anthropic.com".into()],
        },
    );
    m.insert(
        "openai".into(),
        ProviderConfig {
            name: "openai".into(),
            display_name: "OpenAI".into(),
            requests_per_minute: Some(60),
            requests_per_day: Some(10000),
            requests_per_month: None,
            cost_per_request: 0.002,
            key_pattern: Some(r"^sk-[a-zA-Z0-9]{20,}".into()),
            rotation_days: 90,
            base_url: Some("https://api.openai.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.openai.com".into()],
        },
    );
    m.insert(
        "brave".into(),
        ProviderConfig {
            name: "brave".into(),
            display_name: "Brave Search".into(),
            requests_per_minute: Some(10),
            requests_per_day: None,
            requests_per_month: Some(2000),
            cost_per_request: 0.0,
            key_pattern: Some(r"^BSA[a-zA-Z0-9]{20,}".into()),
            rotation_days: 365,
            base_url: Some("https://api.search.brave.com".into()),
            auth_method: Some(AuthMethod::CustomHeader {
                header_name: "X-Subscription-Token".into(),
            }),
            allowed_domains: vec!["api.search.brave.com".into()],
        },
    );
    m.insert(
        "github".into(),
        ProviderConfig {
            name: "github".into(),
            display_name: "GitHub".into(),
            requests_per_minute: Some(83),
            requests_per_day: Some(5000),
            requests_per_month: None,
            cost_per_request: 0.0,
            key_pattern: Some(r"^(ghp_|gho_|github_pat_)".into()),
            rotation_days: 90,
            base_url: Some("https://api.github.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.github.com".into()],
        },
    );
    m.insert(
        "google".into(),
        ProviderConfig {
            name: "google".into(),
            display_name: "Google APIs".into(),
            requests_per_minute: Some(100),
            requests_per_day: Some(10000),
            requests_per_month: None,
            cost_per_request: 0.001,
            key_pattern: Some(r"^AIza".into()),
            rotation_days: 180,
            base_url: Some("https://www.googleapis.com".into()),
            auth_method: Some(AuthMethod::QueryParam {
                param_name: "key".into(),
            }),
            allowed_domains: vec!["*.googleapis.com".into()],
        },
    );
    m.insert(
        "serper".into(),
        ProviderConfig {
            name: "serper".into(),
            display_name: "Serper.dev".into(),
            requests_per_minute: Some(5),
            requests_per_day: None,
            requests_per_month: Some(100),
            cost_per_request: 0.0,
            key_pattern: None,
            rotation_days: 365,
            base_url: Some("https://google.serper.dev".into()),
            auth_method: Some(AuthMethod::CustomHeader {
                header_name: "X-API-KEY".into(),
            }),
            allowed_domains: vec!["google.serper.dev".into()],
        },
    );
    m.insert(
        "resend".into(),
        ProviderConfig {
            name: "resend".into(),
            display_name: "Resend".into(),
            requests_per_minute: Some(10),
            requests_per_day: Some(100),
            requests_per_month: None,
            cost_per_request: 0.0,
            key_pattern: Some(r"^re_".into()),
            rotation_days: 180,
            base_url: Some("https://api.resend.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.resend.com".into()],
        },
    );
    m.insert(
        "cloudflare".into(),
        ProviderConfig {
            name: "cloudflare".into(),
            display_name: "Cloudflare".into(),
            requests_per_minute: Some(50),
            requests_per_day: Some(10000),
            requests_per_month: None,
            cost_per_request: 0.0,
            key_pattern: None,
            rotation_days: 90,
            base_url: Some("https://api.cloudflare.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.cloudflare.com".into()],
        },
    );
    m.insert(
        "stripe".into(),
        ProviderConfig {
            name: "stripe".into(),
            display_name: "Stripe".into(),
            requests_per_minute: Some(100),
            requests_per_day: Some(10000),
            requests_per_month: None,
            cost_per_request: 0.0,
            key_pattern: Some(r"^(sk_live_|sk_test_|pk_)".into()),
            rotation_days: 30,
            base_url: Some("https://api.stripe.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.stripe.com".into()],
        },
    );
    m.insert(
        "elevenlabs".into(),
        ProviderConfig {
            name: "elevenlabs".into(),
            display_name: "ElevenLabs".into(),
            requests_per_minute: Some(20),
            requests_per_day: Some(500),
            requests_per_month: None,
            cost_per_request: 0.005,
            key_pattern: None,
            rotation_days: 180,
            base_url: Some("https://api.elevenlabs.io".into()),
            auth_method: Some(AuthMethod::CustomHeader {
                header_name: "xi-api-key".into(),
            }),
            allowed_domains: vec!["api.elevenlabs.io".into()],
        },
    );
    m
});

static NAME_TO_PROVIDER: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("ANTHROPIC", "anthropic"),
        ("OPENAI", "openai"),
        ("BRAVE", "brave"),
        ("GITHUB", "github"),
        ("GOOGLE_API", "google"),
        ("SERPER", "serper"),
        ("RESEND", "resend"),
        ("CLOUDFLARE", "cloudflare"),
        ("CF_API", "cloudflare"),
        ("STRIPE", "stripe"),
        ("ELEVENLABS", "elevenlabs"),
    ]
});

/// Check if pattern appears as a word boundary in the string.
/// Word separators: start/end of string, underscore, hyphen, non-alphabetic.
/// Matches: "ANTHROPIC_KEY", "MY_ANTHROPIC", "MY-ANTHROPIC", "ANTHROPIC" (exact)
/// Does NOT match: substring in the middle of another word
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

pub fn detect_provider(key_name: &str, value: &str) -> Option<String> {
    let upper = key_name.to_uppercase();

    // Check name patterns — sorted longest-first to avoid greedy short matches
    let mut sorted_patterns: Vec<&(&str, &str)> = NAME_TO_PROVIDER.iter().collect();
    sorted_patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    for (pattern, provider) in sorted_patterns {
        if word_boundary_match(&upper, pattern) {
            return Some(provider.to_string());
        }
    }

    // Check value patterns
    if !value.is_empty() {
        for (name, config) in PROVIDERS.iter() {
            if let Some(ref pat) = config.key_pattern {
                if let Ok(re) = Regex::new(pat) {
                    if re.is_match(value) {
                        return Some(name.clone());
                    }
                }
            }
        }
    }

    None
}

pub fn get_provider(name: &str) -> Option<&ProviderConfig> {
    PROVIDERS.get(name)
}
