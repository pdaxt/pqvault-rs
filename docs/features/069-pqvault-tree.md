# Feature 069: pqvault tree

## Status: Done
## Phase: 7 (v2.7)
## Priority: Low

## Problem

A flat list of secrets (`pqvault list`) becomes unwieldy beyond 30-40 keys. Users
cannot see the organizational structure of their vault, identify clustering patterns,
or spot keys that lack proper categorization. There is no visual hierarchy showing
how secrets relate to providers, projects, or environments.

## Solution

Implement `pqvault tree` that renders a hierarchical tree view of vault contents,
grouped by configurable dimensions (provider, category, project, environment).
The output uses Unicode box-drawing characters for a clean, familiar tree structure
similar to the Unix `tree` command.

## Implementation

### Files to Create/Modify

```
pqvault-cli/
  src/
    commands/
      tree.rs          # Tree command entry point
    tree/
      mod.rs           # Tree building logic
      builder.rs       # Constructs tree from flat key list
      renderer.rs      # Unicode tree rendering
      grouping.rs      # Grouping strategies (by provider, category, etc.)
```

### Data Model Changes

```rust
/// A node in the display tree
pub struct TreeNode {
    pub label: String,
    pub node_type: NodeType,
    pub children: Vec<TreeNode>,
    pub metadata: Option<NodeMeta>,
}

pub enum NodeType {
    Root,
    Group(String),    // Category, provider, or project name
    Key,
}

pub struct NodeMeta {
    pub key_count: usize,          // For group nodes
    pub health: Option<HealthStatus>,  // For key nodes
    pub last_rotated: Option<DateTime<Utc>>,
    pub provider: Option<String>,
}

pub enum GroupBy {
    Provider,
    Category,
    Project,
    Environment,
    Prefix,       // Group by key name prefix (e.g., STRIPE_, AWS_)
    None,         // Flat list with tree formatting
}

pub struct TreeConfig {
    pub group_by: Vec<GroupBy>,   // Multi-level grouping
    pub show_metadata: bool,
    pub show_health: bool,
    pub max_depth: Option<usize>,
    pub filter: Option<String>,
}

impl TreeNode {
    pub fn build(keys: &[KeyEntry], config: &TreeConfig) -> Self {
        let mut root = TreeNode {
            label: "PQVault".into(),
            node_type: NodeType::Root,
            children: Vec::new(),
            metadata: Some(NodeMeta { key_count: keys.len(), ..Default::default() }),
        };

        let grouped = group_keys(keys, &config.group_by);
        for (group_name, group_keys) in grouped {
            let mut group_node = TreeNode {
                label: group_name,
                node_type: NodeType::Group("".into()),
                children: Vec::new(),
                metadata: Some(NodeMeta { key_count: group_keys.len(), ..Default::default() }),
            };
            for key in group_keys {
                group_node.children.push(TreeNode {
                    label: key.name.clone(),
                    node_type: NodeType::Key,
                    children: Vec::new(),
                    metadata: Some(NodeMeta {
                        key_count: 0,
                        health: key.health.clone(),
                        last_rotated: key.rotated_at,
                        provider: key.provider.clone(),
                    }),
                });
            }
            root.children.push(group_node);
        }
        root
    }
}
```

Renderer:

```rust
pub fn render_tree(node: &TreeNode, config: &TreeConfig) -> String {
    let mut output = String::new();
    render_node(&mut output, node, "", true, config);
    output
}

fn render_node(
    output: &mut String,
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    config: &TreeConfig,
) {
    let connector = if prefix.is_empty() {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let meta_str = if config.show_metadata {
        format_node_meta(&node.metadata)
    } else {
        String::new()
    };

    output.push_str(&format!("{}{}{}{}\n", prefix, connector, node.label, meta_str));

    let child_prefix = if prefix.is_empty() {
        "".to_string()
    } else if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    for (i, child) in node.children.iter().enumerate() {
        let is_last_child = i == node.children.len() - 1;
        render_node(output, child, &child_prefix, is_last_child, config);
    }
}
```

### MCP Tools

No new MCP tools. Tree is a CLI-only display feature.

### CLI Commands

```bash
# Default tree (grouped by category)
pqvault tree

# Group by provider
pqvault tree --group-by provider

# Multi-level grouping
pqvault tree --group-by category,provider

# Group by key name prefix
pqvault tree --group-by prefix

# Show health indicators
pqvault tree --health

# Filter to matching keys
pqvault tree --filter stripe

# JSON output
pqvault tree --format json
```

### Web UI Changes

None. Web UI has its own grouping in the dashboard.

## Dependencies

No new dependencies. Uses standard library string formatting with Unicode characters.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_grouping_by_category() {
        let keys = vec![
            key_entry("STRIPE_KEY", Some("payment"), Some("stripe")),
            key_entry("AWS_KEY", Some("cloud"), Some("aws")),
            key_entry("DB_URL", Some("database"), None),
        ];
        let tree = TreeNode::build(&keys, &TreeConfig { group_by: vec![GroupBy::Category], ..Default::default() });
        assert_eq!(tree.children.len(), 3); // 3 categories
    }

    #[test]
    fn test_tree_grouping_by_prefix() {
        let keys = vec![
            key_entry("STRIPE_SECRET_KEY", None, None),
            key_entry("STRIPE_PUBLISHABLE", None, None),
            key_entry("AWS_ACCESS_KEY", None, None),
        ];
        let tree = TreeNode::build(&keys, &TreeConfig { group_by: vec![GroupBy::Prefix], ..Default::default() });
        assert_eq!(tree.children.len(), 2); // STRIPE_, AWS_
    }

    #[test]
    fn test_tree_rendering() {
        let tree = TreeNode {
            label: "Vault".into(),
            node_type: NodeType::Root,
            children: vec![
                TreeNode {
                    label: "payment".into(),
                    node_type: NodeType::Group("category".into()),
                    children: vec![
                        TreeNode { label: "STRIPE_KEY".into(), node_type: NodeType::Key, children: vec![], metadata: None },
                    ],
                    metadata: None,
                },
            ],
            metadata: None,
        };
        let output = render_tree(&tree, &TreeConfig::default());
        assert!(output.contains("Vault"));
        assert!(output.contains("payment"));
        assert!(output.contains("STRIPE_KEY"));
    }

    #[test]
    fn test_tree_filter() {
        let keys = vec![
            key_entry("STRIPE_KEY", None, None),
            key_entry("AWS_KEY", None, None),
        ];
        let config = TreeConfig { filter: Some("stripe".into()), ..Default::default() };
        let tree = TreeNode::build(&keys, &config);
        let total_keys: usize = tree.children.iter().map(|c| c.children.len()).sum();
        assert_eq!(total_keys, 1);
    }
}
```

## Example Usage

```
$ pqvault tree

  PQVault (24 keys)
  ├── payment (4 keys)
  │   ├── STRIPE_SECRET_KEY
  │   ├── STRIPE_PUBLISHABLE_KEY
  │   ├── STRIPE_WEBHOOK_SECRET
  │   └── RAZORPAY_KEY_ID
  ├── cloud (5 keys)
  │   ├── AWS_ACCESS_KEY_ID
  │   ├── AWS_SECRET_ACCESS_KEY
  │   ├── AWS_REGION
  │   ├── GCP_SERVICE_ACCOUNT
  │   └── CLOUDFLARE_API_TOKEN
  ├── database (3 keys)
  │   ├── DATABASE_URL
  │   ├── REDIS_URL
  │   └── MONGODB_URI
  ├── auth (4 keys)
  │   ├── GITHUB_TOKEN
  │   ├── GOOGLE_CLIENT_ID
  │   ├── GOOGLE_CLIENT_SECRET
  │   └── JWT_SECRET
  ├── monitoring (3 keys)
  │   ├── SENTRY_DSN
  │   ├── DATADOG_API_KEY
  │   └── PAGERDUTY_KEY
  └── uncategorized (5 keys)
      ├── API_KEY
      ├── SECRET_TOKEN
      ├── WEBHOOK_URL
      ├── INTERNAL_AUTH
      └── FEATURE_FLAG_KEY

$ pqvault tree --group-by provider --health

  PQVault (24 keys)
  ├── stripe (3 keys)
  │   ├── STRIPE_SECRET_KEY       [healthy] rotated 3d ago
  │   ├── STRIPE_PUBLISHABLE_KEY  [healthy]
  │   └── STRIPE_WEBHOOK_SECRET   [warning] expires in 7d
  ├── aws (3 keys)
  │   ├── AWS_ACCESS_KEY_ID       [healthy]
  │   ├── AWS_SECRET_ACCESS_KEY   [healthy]
  │   └── AWS_REGION              [healthy]
  ├── (no provider) (18 keys)
  │   └── ...
```
