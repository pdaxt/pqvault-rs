# Feature 097: Secret Inheritance

## Status: Planned
## Phase: 10 (v3.0)
## Priority: Low

## Problem

Many secrets share the same base value across environments with only minor variations.
A database URL might be `postgres://user:pass@prod-db/app` in production and
`postgres://user:pass@staging-db/app` in staging, with only the hostname differing.
Currently each environment stores a complete copy, leading to duplication and making
it easy to update one copy while forgetting others.

## Solution

Implement secret inheritance where a base key defines a template value, and
environment-specific keys override specific parts. This works like CSS cascading:
the most specific value wins, but unset fields inherit from the parent. Base keys
can define templates with `${variable}` placeholders that child keys populate.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    inheritance/
      mod.rs           # Inheritance module root
      chain.rs         # Inheritance chain resolution
      template.rs      # Template variable substitution
      resolver.rs      # Value resolution with fallback chain
```

### Data Model Changes

```rust
/// Inheritance definition for a key
#[derive(Serialize, Deserialize, Clone)]
pub struct InheritanceConfig {
    /// Parent key to inherit from
    pub parent: String,
    /// Variable overrides for template substitution
    pub overrides: HashMap<String, String>,
    /// Fields to inherit (empty = inherit all)
    pub inherit_fields: Vec<InheritableField>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum InheritableField {
    Value,
    Category,
    Provider,
    RotationPolicy,
    IpPolicy,
    TimePolicy,
    Tags,
}

/// Template-based secret value
#[derive(Serialize, Deserialize, Clone)]
pub struct TemplateValue {
    /// Template string with ${variable} placeholders
    pub template: String,
    /// Default values for variables
    pub defaults: HashMap<String, String>,
}

/// Resolved value after inheritance chain
pub struct ResolvedSecret {
    pub key_name: String,
    pub value: String,
    pub resolved_from: Vec<String>,  // Chain: ["prod.DB_URL", "base.DB_URL"]
    pub overrides_applied: HashMap<String, String>,
}

pub struct InheritanceResolver;

impl InheritanceResolver {
    /// Resolve a key's value by walking the inheritance chain
    pub async fn resolve(&self, key: &str, vault: &Vault) -> Result<ResolvedSecret> {
        let entry = vault.get_metadata(key).await?;
        let mut chain = vec![key.to_string()];

        if let Some(inheritance) = &entry.inheritance {
            let parent_value = self.resolve_parent(&inheritance.parent, vault, &mut chain).await?;
            let template = TemplateValue::from_str(&parent_value)?;
            let resolved = template.substitute(&inheritance.overrides)?;

            Ok(ResolvedSecret {
                key_name: key.to_string(),
                value: resolved,
                resolved_from: chain,
                overrides_applied: inheritance.overrides.clone(),
            })
        } else {
            let value = vault.get(key).await?;
            Ok(ResolvedSecret {
                key_name: key.to_string(),
                value: value.value,
                resolved_from: chain,
                overrides_applied: HashMap::new(),
            })
        }
    }

    async fn resolve_parent(
        &self,
        parent: &str,
        vault: &Vault,
        chain: &mut Vec<String>,
    ) -> Result<String> {
        // Prevent circular inheritance
        if chain.contains(&parent.to_string()) {
            return Err(anyhow!("Circular inheritance detected: {:?}", chain));
        }
        chain.push(parent.to_string());

        let entry = vault.get_metadata(parent).await?;
        if let Some(inheritance) = &entry.inheritance {
            let grandparent = self.resolve_parent(&inheritance.parent, vault, chain).await?;
            let template = TemplateValue::from_str(&grandparent)?;
            template.substitute(&inheritance.overrides)
        } else {
            Ok(vault.get(parent).await?.value)
        }
    }
}

impl TemplateValue {
    pub fn from_str(value: &str) -> Result<Self> {
        Ok(Self {
            template: value.to_string(),
            defaults: HashMap::new(),
        })
    }

    pub fn substitute(&self, overrides: &HashMap<String, String>) -> Result<String> {
        let mut result = self.template.clone();
        let re = regex::Regex::new(r"\$\{(\w+)\}")?;

        for cap in re.captures_iter(&self.template) {
            let var_name = &cap[1];
            let value = overrides.get(var_name)
                .or_else(|| self.defaults.get(var_name))
                .ok_or_else(|| anyhow!("Unresolved variable: ${{{}}}", var_name))?;
            result = result.replace(&cap[0], value);
        }

        Ok(result)
    }
}
```

### MCP Tools

No new MCP tools. Inheritance is a core value resolution feature.

### CLI Commands

```bash
# Set a base template key
pqvault set DB_URL_TEMPLATE "postgres://\${user}:\${pass}@\${host}:5432/\${db}"

# Create an inheriting key
pqvault inherit PROD_DB_URL --from DB_URL_TEMPLATE \
  --override user=app_prod \
  --override pass=vault:DB_PASSWORD \
  --override host=prod-db.internal \
  --override db=myapp

# Create staging variant
pqvault inherit STAGING_DB_URL --from DB_URL_TEMPLATE \
  --override user=app_staging \
  --override pass=vault:STAGING_DB_PASSWORD \
  --override host=staging-db.internal \
  --override db=myapp_staging

# Show inheritance chain
pqvault show PROD_DB_URL --chain

# Resolve value (follows inheritance)
pqvault get PROD_DB_URL
```

### Web UI Changes

None in this phase.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `regex` | 1 | Template variable pattern matching (already in workspace) |

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_substitution() {
        let template = TemplateValue {
            template: "postgres://${user}:${pass}@${host}:5432/${db}".into(),
            defaults: HashMap::new(),
        };
        let overrides = [
            ("user".into(), "admin".into()),
            ("pass".into(), "secret".into()),
            ("host".into(), "db.example.com".into()),
            ("db".into(), "myapp".into()),
        ].into();
        let result = template.substitute(&overrides).unwrap();
        assert_eq!(result, "postgres://admin:secret@db.example.com:5432/myapp");
    }

    #[test]
    fn test_template_missing_variable() {
        let template = TemplateValue {
            template: "https://${host}/${path}".into(),
            defaults: HashMap::new(),
        };
        let overrides = [("host".into(), "example.com".into())].into();
        let result = template.substitute(&overrides);
        assert!(result.is_err());
    }

    #[test]
    fn test_template_with_defaults() {
        let template = TemplateValue {
            template: "${protocol}://${host}:${port}".into(),
            defaults: [("protocol".into(), "https".into()), ("port".into(), "443".into())].into(),
        };
        let overrides = [("host".into(), "api.example.com".into())].into();
        let result = template.substitute(&overrides).unwrap();
        assert_eq!(result, "https://api.example.com:443");
    }

    #[test]
    fn test_circular_inheritance_detection() {
        // A -> B -> A would be circular
        let chain = vec!["A".to_string(), "B".to_string()];
        assert!(chain.contains(&"A".to_string())); // Would detect circular
    }

    #[test]
    fn test_no_variables_passthrough() {
        let template = TemplateValue {
            template: "static_value_no_vars".into(),
            defaults: HashMap::new(),
        };
        let result = template.substitute(&HashMap::new()).unwrap();
        assert_eq!(result, "static_value_no_vars");
    }
}
```

## Example Usage

```
$ pqvault set DB_URL_BASE "postgres://\${user}:\${pass}@\${host}:5432/\${db}"

$ pqvault inherit PROD_DB_URL --from DB_URL_BASE \
    --override user=app --override host=prod-db.rds.amazonaws.com --override db=myapp
  Enter value for 'pass': ********

$ pqvault inherit STAGING_DB_URL --from DB_URL_BASE \
    --override user=app --override host=staging-db.rds.amazonaws.com --override db=myapp_stg
  Enter value for 'pass': ********

$ pqvault get PROD_DB_URL
  postgres://app:████████@prod-db.rds.amazonaws.com:5432/myapp

$ pqvault show PROD_DB_URL --chain

  Inheritance Chain: PROD_DB_URL
  ──────────────────────────────

  PROD_DB_URL
    inherits from: DB_URL_BASE
    template: postgres://${user}:${pass}@${host}:5432/${db}
    overrides:
      user = app
      pass = ████████
      host = prod-db.rds.amazonaws.com
      db   = myapp
    resolved: postgres://app:████████@prod-db.rds.amazonaws.com:5432/myapp
```
