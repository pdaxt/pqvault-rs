# Feature 098: Provider Marketplace

## Status: Done
## Phase: 10 (v3.0)
## Priority: Low

## Problem

PQVault ships with built-in support for common providers (Stripe, AWS, GitHub), but
teams use hundreds of different SaaS services with unique key formats, rotation APIs,
and health check endpoints. Adding support for each provider requires code changes
to PQVault core, creating a bottleneck. Community members who integrate niche
providers cannot share their work with others.

## Solution

Create a provider marketplace where community-contributed provider configurations
can be discovered, installed, and used. Provider configs are TOML files that define
key format patterns, rotation API endpoints, health check URLs, and secret templates.
A central registry hosts contributed configs, and users can install them locally or
create private configs for proprietary services.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    providers/
      mod.rs           # Provider module root
      registry.rs      # Provider config registry
      loader.rs        # Load provider configs from disk/registry
      config.rs        # Provider config schema
      marketplace.rs   # Remote marketplace client
```

### Data Model Changes

```rust
/// A provider configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct ProviderConfig {
    /// Unique provider identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Provider description
    pub description: String,
    /// Config version
    pub version: String,
    /// Author
    pub author: String,
    /// Provider website
    pub website: Option<String>,
    /// Key patterns this provider uses
    pub key_patterns: Vec<KeyPattern>,
    /// How to validate a key
    pub validation: Option<ValidationConfig>,
    /// How to rotate a key
    pub rotation: Option<RotationConfig>,
    /// Health check endpoint
    pub health_check: Option<HealthCheckConfig>,
    /// Secret template for this provider
    pub template: Option<Vec<TemplateKey>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPattern {
    /// Pattern name
    pub name: String,
    /// Regex to match the key value
    pub value_regex: String,
    /// Expected key name pattern
    pub key_name_regex: Option<String>,
    /// Example value (redacted)
    pub example: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ValidationConfig {
    /// HTTP endpoint to validate the key
    pub endpoint: String,
    /// HTTP method
    pub method: String,
    /// How to send the key
    pub auth_type: String,  // "bearer", "basic", "header:X-Api-Key"
    /// Expected success status code
    pub expected_status: u16,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RotationConfig {
    /// Rotation type
    pub rotation_type: RotationType,
    /// API endpoint for rotation
    pub endpoint: Option<String>,
    /// HTTP method
    pub method: Option<String>,
    /// Documentation URL for manual rotation
    pub docs_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum RotationType {
    /// Provider has an API for key rotation
    Api,
    /// User must rotate manually via provider dashboard
    Manual,
    /// Key is generated locally (no provider interaction)
    Local,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HealthCheckConfig {
    pub endpoint: String,
    pub method: String,
    pub auth_type: String,
    pub expected_status: u16,
    pub timeout_ms: u64,
}

/// Marketplace client for discovering and installing providers
pub struct MarketplaceClient {
    registry_url: String,
    client: reqwest::Client,
}

impl MarketplaceClient {
    pub async fn search(&self, query: &str) -> Result<Vec<ProviderSummary>> {
        let url = format!("{}/api/providers?q={}", self.registry_url, query);
        let response = self.client.get(&url).send().await?;
        Ok(response.json().await?)
    }

    pub async fn install(&self, provider_id: &str) -> Result<ProviderConfig> {
        let url = format!("{}/api/providers/{}", self.registry_url, provider_id);
        let response = self.client.get(&url).send().await?;
        let config: ProviderConfig = response.json().await?;

        // Save to local providers directory
        let path = providers_dir().join(format!("{}.toml", provider_id));
        let toml = toml::to_string_pretty(&config)?;
        std::fs::write(&path, toml)?;

        Ok(config)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub downloads: u64,
    pub rating: f32,
}
```

### MCP Tools

No new MCP tools. Provider management is a CLI operation.

### CLI Commands

```bash
# Search marketplace
pqvault provider search "email"

# Install a provider config
pqvault provider install sendgrid

# List installed providers
pqvault provider list

# Show provider details
pqvault provider info sendgrid

# Create a custom provider config
pqvault provider create my-internal-service

# Update installed providers
pqvault provider update

# Remove a provider
pqvault provider remove sendgrid

# Publish to marketplace (community)
pqvault provider publish my-provider.toml
```

### Web UI Changes

None. Provider management is CLI-only.

## Dependencies

No new Rust dependencies. Uses existing `reqwest`, `toml`, `serde`.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider_config() {
        let toml = r#"
id = "sendgrid"
name = "SendGrid"
description = "SendGrid email delivery"
version = "1.0.0"
author = "community"
website = "https://sendgrid.com"

[[key_patterns]]
name = "api_key"
value_regex = "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"
example = "SG.xxxx...xxxx"

[validation]
endpoint = "https://api.sendgrid.com/v3/user/profile"
method = "GET"
auth_type = "bearer"
expected_status = 200

[rotation]
rotation_type = "Manual"
docs_url = "https://docs.sendgrid.com/ui/account-and-settings/api-keys"
"#;
        let config: ProviderConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.id, "sendgrid");
        assert_eq!(config.key_patterns.len(), 1);
        assert!(config.validation.is_some());
    }

    #[test]
    fn test_key_pattern_matching() {
        let pattern = KeyPattern {
            name: "stripe_sk".into(),
            value_regex: "sk_(live|test)_[a-zA-Z0-9]{24}".into(),
            key_name_regex: None,
            example: "sk_live_xxxx...".into(),
        };
        let regex = regex::Regex::new(&pattern.value_regex).unwrap();
        assert!(regex.is_match("sk_live_abc123def456ghi789jkl0"));
        assert!(!regex.is_match("pk_live_abc123"));
    }

    #[test]
    fn test_provider_auto_detection() {
        let providers = vec![
            mock_provider("stripe", "sk_(live|test)_"),
            mock_provider("aws", "AKIA[A-Z0-9]{16}"),
        ];
        let value = "sk_live_abc123def456ghi789";
        let detected = detect_provider(value, &providers);
        assert_eq!(detected.unwrap().id, "stripe");
    }

    #[test]
    fn test_builtin_providers_count() {
        let builtins = builtin_providers();
        assert!(builtins.len() >= 5); // stripe, aws, github, openai, etc.
    }
}
```

## Example Usage

```
$ pqvault provider search "email"

  Marketplace Results for "email"
  ─────────────────────────────────────

  ID          Name         Version  Downloads  Rating
  ──────────  ───────────  ───────  ─────────  ──────
  sendgrid    SendGrid     1.0.0    1,245      4.8
  mailgun     Mailgun      1.0.0    892        4.6
  postmark    Postmark     0.9.0    456        4.5
  ses         Amazon SES   1.1.0    2,100      4.7
  resend      Resend       1.0.0    320        4.9

$ pqvault provider install sendgrid

  Installing provider: SendGrid v1.0.0
  Saved to: ~/.pqvault/providers/sendgrid.toml

  Capabilities:
    Key detection: SG.* pattern
    Validation:    GET /v3/user/profile
    Rotation:      Manual (dashboard)
    Health check:  GET /v3/user/profile

  Provider installed successfully.
  Keys matching SendGrid patterns will now auto-detect.

$ pqvault provider list

  Installed Providers
  ─────────────────────────────

  Provider     Version  Keys  Source
  ───────────  ───────  ────  ──────────
  stripe       built-in 3     built-in
  aws          built-in 3     built-in
  github       built-in 2     built-in
  sendgrid     1.0.0    1     marketplace
  my-internal  0.1.0    2     custom
```
