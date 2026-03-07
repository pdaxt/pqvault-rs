# Feature 093: Secret Templates

## Status: Planned
## Phase: 10 (v3.0)
## Priority: Medium

## Problem

Setting up a new integration (e.g., Stripe, AWS, SendGrid) requires creating multiple
related keys with specific naming conventions, categories, and metadata. Engineers
must remember all required keys and their formats. Forgetting a key (like
STRIPE_WEBHOOK_SECRET) causes runtime errors that are hard to debug. There is no way
to ensure consistent, complete secret provisioning for common integrations.

## Solution

Implement secret templates that define groups of related keys for common integrations.
Running `pqvault template apply stripe` creates all required Stripe keys with correct
naming, categories, providers, and rotation policies. Templates are versioned and
community-contributable. Custom templates can be defined for organization-specific
patterns.

## Implementation

### Files to Create/Modify

```
pqvault-mcp/
  src/
    templates/
      mod.rs           # Template module root
      registry.rs      # Built-in template registry
      parser.rs        # Custom template YAML parser
      executor.rs      # Template application engine
    tools/
      template_apply.rs   # MCP tool: apply template
      template_list.rs    # MCP tool: list available templates
```

### Data Model Changes

```rust
/// A secret template defining a group of related keys
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretTemplate {
    pub name: String,
    pub version: String,
    pub description: String,
    pub provider: String,
    pub documentation_url: Option<String>,
    pub keys: Vec<TemplateKey>,
    pub variables: Vec<TemplateVariable>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TemplateKey {
    pub name_pattern: String,     // "STRIPE_SECRET_KEY" or "${PREFIX}_SECRET_KEY"
    pub description: String,
    pub required: bool,
    pub format: KeyFormat,
    pub category: String,
    pub rotation_days: Option<u32>,
    pub generation: Option<KeyGeneration>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum KeyFormat {
    /// Provider API key format
    ApiKey { prefix: String, length: usize },
    /// URL format
    Url { scheme: String, example: String },
    /// JSON blob (e.g., service account)
    Json,
    /// Free-form string
    String,
    /// Generated UUID
    Uuid,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum KeyGeneration {
    /// Prompt user for value
    Prompt,
    /// Generate random value
    Random { length: usize, charset: String },
    /// Generate UUID
    Uuid,
    /// Derive from another key
    Derived { source: String, transform: String },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub default: Option<String>,
    pub required: bool,
}

/// Result of applying a template
#[derive(Serialize)]
pub struct TemplateResult {
    pub template_name: String,
    pub keys_created: Vec<String>,
    pub keys_skipped: Vec<String>,   // Already existed
    pub keys_prompted: Vec<String>,  // User provided value
}

/// Built-in templates
pub fn builtin_templates() -> Vec<SecretTemplate> {
    vec![
        SecretTemplate {
            name: "stripe".into(),
            version: "1.0".into(),
            description: "Stripe payment integration".into(),
            provider: "stripe".into(),
            documentation_url: Some("https://stripe.com/docs/keys".into()),
            keys: vec![
                TemplateKey {
                    name_pattern: "STRIPE_SECRET_KEY".into(),
                    description: "Stripe API secret key".into(),
                    required: true,
                    format: KeyFormat::ApiKey { prefix: "sk_live_".into(), length: 24 },
                    category: "payment".into(),
                    rotation_days: Some(90),
                    generation: Some(KeyGeneration::Prompt),
                },
                TemplateKey {
                    name_pattern: "STRIPE_PUBLISHABLE_KEY".into(),
                    description: "Stripe publishable key (safe for client-side)".into(),
                    required: true,
                    format: KeyFormat::ApiKey { prefix: "pk_live_".into(), length: 24 },
                    category: "payment".into(),
                    rotation_days: None,
                    generation: Some(KeyGeneration::Prompt),
                },
                TemplateKey {
                    name_pattern: "STRIPE_WEBHOOK_SECRET".into(),
                    description: "Stripe webhook signing secret".into(),
                    required: true,
                    format: KeyFormat::ApiKey { prefix: "whsec_".into(), length: 32 },
                    category: "payment".into(),
                    rotation_days: Some(180),
                    generation: Some(KeyGeneration::Prompt),
                },
            ],
            variables: vec![],
        },
        SecretTemplate {
            name: "aws".into(),
            version: "1.0".into(),
            description: "AWS IAM credentials".into(),
            provider: "aws".into(),
            documentation_url: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html".into()),
            keys: vec![
                TemplateKey {
                    name_pattern: "AWS_ACCESS_KEY_ID".into(),
                    description: "AWS IAM access key ID".into(),
                    required: true,
                    format: KeyFormat::ApiKey { prefix: "AKIA".into(), length: 16 },
                    category: "cloud".into(),
                    rotation_days: Some(90),
                    generation: Some(KeyGeneration::Prompt),
                },
                TemplateKey {
                    name_pattern: "AWS_SECRET_ACCESS_KEY".into(),
                    description: "AWS IAM secret access key".into(),
                    required: true,
                    format: KeyFormat::String,
                    category: "cloud".into(),
                    rotation_days: Some(90),
                    generation: Some(KeyGeneration::Prompt),
                },
                TemplateKey {
                    name_pattern: "AWS_REGION".into(),
                    description: "Default AWS region".into(),
                    required: false,
                    format: KeyFormat::String,
                    category: "cloud".into(),
                    rotation_days: None,
                    generation: None,
                },
            ],
            variables: vec![],
        },
    ]
}
```

### MCP Tools

```rust
#[tool(description = "Apply a secret template to create a group of related keys")]
async fn template_apply(
    /// Template name: stripe, aws, sendgrid, etc.
    template: String,
    /// Variable overrides as key=value pairs
    variables: Option<String>,
    /// Skip prompts and use defaults/generation
    #[arg(default = false)]
    non_interactive: bool,
) -> Result<CallToolResult> { /* ... */ }

#[tool(description = "List available secret templates")]
async fn template_list() -> Result<CallToolResult> { /* ... */ }
```

### CLI Commands

```bash
# List available templates
pqvault template list

# Apply Stripe template
pqvault template apply stripe

# Apply with variable overrides
pqvault template apply custom-service --var prefix=MYAPP --var env=prod

# Preview template without applying
pqvault template preview stripe

# Create custom template
pqvault template create my-service --from-file template.yaml
```

### Web UI Changes

Template selector in the "New Key" dialog on the dashboard.

## Dependencies

No new dependencies. Uses existing `serde_yaml` for custom template parsing.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_templates_exist() {
        let templates = builtin_templates();
        assert!(templates.len() >= 2);
        assert!(templates.iter().any(|t| t.name == "stripe"));
        assert!(templates.iter().any(|t| t.name == "aws"));
    }

    #[test]
    fn test_stripe_template_completeness() {
        let templates = builtin_templates();
        let stripe = templates.iter().find(|t| t.name == "stripe").unwrap();
        assert_eq!(stripe.keys.len(), 3);
        assert!(stripe.keys.iter().any(|k| k.name_pattern.contains("SECRET")));
        assert!(stripe.keys.iter().any(|k| k.name_pattern.contains("PUBLISHABLE")));
        assert!(stripe.keys.iter().any(|k| k.name_pattern.contains("WEBHOOK")));
    }

    #[test]
    fn test_variable_substitution() {
        let pattern = "${PREFIX}_SECRET_KEY";
        let vars = [("PREFIX".to_string(), "STRIPE".to_string())].into();
        let resolved = substitute_variables(pattern, &vars);
        assert_eq!(resolved, "STRIPE_SECRET_KEY");
    }

    #[test]
    fn test_key_format_validation() {
        let format = KeyFormat::ApiKey { prefix: "sk_live_".into(), length: 24 };
        assert!(validate_format("sk_live_abc123xyz789def456", &format));
        assert!(!validate_format("invalid_key", &format));
    }

    #[test]
    fn test_template_skip_existing() {
        let existing_keys = vec!["STRIPE_SECRET_KEY".to_string()];
        let template = builtin_templates().into_iter().find(|t| t.name == "stripe").unwrap();
        let to_create = template.keys.iter()
            .filter(|k| !existing_keys.contains(&k.name_pattern))
            .collect::<Vec<_>>();
        assert_eq!(to_create.len(), 2); // PUBLISHABLE and WEBHOOK
    }
}
```

## Example Usage

```
$ pqvault template list

  Available Templates
  ────────────────────────────────────────

  Name         Provider    Keys  Description
  ───────────  ──────────  ────  ─────────────────────────
  stripe       Stripe      3     Payment integration
  aws          AWS         3     IAM credentials
  sendgrid     SendGrid    2     Email delivery
  github       GitHub      2     API + webhook secret
  openai       OpenAI      2     API key + org ID
  postgres     PostgreSQL  1     Database connection URL
  redis        Redis       1     Cache connection URL
  custom       -           -     Create from YAML template

$ pqvault template apply stripe

  Applying template: stripe (Stripe payment integration)
  ──────────────────────────────────────────────────────

  STRIPE_SECRET_KEY:
    Description: Stripe API secret key
    Format: sk_live_... (24 chars)
    Enter value: ****************************

  STRIPE_PUBLISHABLE_KEY:
    Description: Stripe publishable key (safe for client-side)
    Format: pk_live_... (24 chars)
    Enter value: ****************************

  STRIPE_WEBHOOK_SECRET:
    Description: Stripe webhook signing secret
    Format: whsec_... (32 chars)
    Enter value: ************************************

  Template applied:
    Created: STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET
    Category: payment
    Provider: stripe
    Rotation: 90 days (SECRET), none (PUBLISHABLE), 180 days (WEBHOOK)
```
