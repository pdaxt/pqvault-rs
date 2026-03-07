# Feature 077: IP Allowlisting

## Status: Planned
## Phase: 8 (v2.8)
## Priority: Medium

## Problem

Some secrets should only be accessible from specific network locations. A production
database URL should never be retrieved from a developer's home network, and a staging
API key should not be accessible from production servers. Currently PQVault applies
the same access rules regardless of where the request originates, creating unnecessary
exposure surface.

## Solution

Implement per-key IP allowlisting that restricts which IP addresses or CIDR ranges
can access specific secrets. When a request comes through the proxy MCP, it checks
the client's IP against the key's allowlist before returning the value. Requests
from disallowed IPs are blocked and logged to the audit trail.

## Implementation

### Files to Create/Modify

```
pqvault-core/
  src/
    access/
      mod.rs           # Access control module root
      ip_filter.rs     # IP/CIDR matching engine
      policy.rs        # Per-key access policy definitions
      evaluator.rs     # Policy evaluation at access time

pqvault-proxy-mcp/
  src/
    middleware/
      ip_check.rs      # IP validation middleware for proxy requests
```

### Data Model Changes

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP-based access policy for a key
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpPolicy {
    /// List of allowed IP addresses or CIDR ranges
    pub allow: Vec<IpRange>,
    /// List of explicitly denied IP addresses or CIDR ranges
    pub deny: Vec<IpRange>,
    /// What to do when no rule matches
    pub default_action: PolicyAction,
    /// Whether to log blocked attempts
    pub log_blocked: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IpRange {
    /// Single IP address
    Address(IpAddr),
    /// CIDR notation (e.g., 10.0.0.0/8)
    Cidr { network: IpAddr, prefix_len: u8 },
    /// Named range for readability
    Named { name: String, range: Box<IpRange> },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PolicyAction {
    Allow,
    Deny,
}

pub struct IpFilter;

impl IpFilter {
    /// Check if an IP address matches a CIDR range
    pub fn matches_cidr(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(*ip);
                let net_bits = u32::from(*net);
                let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(*ip);
                let net_bits = u128::from(*net);
                let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // V4/V6 mismatch
        }
    }

    /// Evaluate an IP against a policy
    pub fn evaluate(ip: &IpAddr, policy: &IpPolicy) -> PolicyDecision {
        // Check deny list first (deny takes precedence)
        for range in &policy.deny {
            if Self::matches_range(ip, range) {
                return PolicyDecision::Denied {
                    reason: format!("IP {} matches deny rule: {}", ip, range),
                };
            }
        }

        // Check allow list
        for range in &policy.allow {
            if Self::matches_range(ip, range) {
                return PolicyDecision::Allowed;
            }
        }

        // Apply default action
        match policy.default_action {
            PolicyAction::Allow => PolicyDecision::Allowed,
            PolicyAction::Deny => PolicyDecision::Denied {
                reason: format!("IP {} not in allow list, default: deny", ip),
            },
        }
    }

    fn matches_range(ip: &IpAddr, range: &IpRange) -> bool {
        match range {
            IpRange::Address(addr) => ip == addr,
            IpRange::Cidr { network, prefix_len } => Self::matches_cidr(ip, network, *prefix_len),
            IpRange::Named { range, .. } => Self::matches_range(ip, range),
        }
    }
}

pub enum PolicyDecision {
    Allowed,
    Denied { reason: String },
}
```

### MCP Tools

No new MCP tools dedicated to IP allowlisting. The existing `vault_set` and a new
`vault_set_policy` tool in `pqvault-mcp` handle policy configuration.

### CLI Commands

```bash
# Set IP allowlist for a key
pqvault policy set PROD_DB_URL --allow 10.0.0.0/8 --allow 172.16.0.0/12

# Add a named range
pqvault policy set PROD_DB_URL --allow "office=203.0.113.0/24"

# Deny specific IPs
pqvault policy set STAGING_KEY --deny 0.0.0.0/0 --allow 10.0.0.0/8

# Show policy for a key
pqvault policy show PROD_DB_URL

# Test if an IP would be allowed
pqvault policy test PROD_DB_URL --ip 10.0.1.50

# Remove all IP restrictions
pqvault policy clear PROD_DB_URL
```

### Web UI Changes

None in this phase. Web UI will show IP policies in Feature 082 (Key Detail Page).

## Dependencies

No new dependencies. IP parsing uses `std::net` from Rust standard library.

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_match_v4() {
        let ip: IpAddr = "10.0.1.50".parse().unwrap();
        let network: IpAddr = "10.0.0.0".parse().unwrap();
        assert!(IpFilter::matches_cidr(&ip, &network, 8));
        assert!(!IpFilter::matches_cidr(&ip, &network, 24));
    }

    #[test]
    fn test_cidr_match_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let network: IpAddr = "2001:db8::".parse().unwrap();
        assert!(IpFilter::matches_cidr(&ip, &network, 32));
    }

    #[test]
    fn test_exact_ip_match() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let range = IpRange::Address("192.168.1.100".parse().unwrap());
        assert!(IpFilter::matches_range(&ip, &range));
    }

    #[test]
    fn test_policy_allow() {
        let policy = IpPolicy {
            allow: vec![IpRange::Cidr {
                network: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
            }],
            deny: vec![],
            default_action: PolicyAction::Deny,
            log_blocked: true,
        };
        let ip: IpAddr = "10.0.1.50".parse().unwrap();
        assert!(matches!(IpFilter::evaluate(&ip, &policy), PolicyDecision::Allowed));
    }

    #[test]
    fn test_policy_deny_overrides_allow() {
        let policy = IpPolicy {
            allow: vec![IpRange::Cidr {
                network: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
            }],
            deny: vec![IpRange::Address("10.0.1.50".parse().unwrap())],
            default_action: PolicyAction::Allow,
            log_blocked: true,
        };
        let ip: IpAddr = "10.0.1.50".parse().unwrap();
        assert!(matches!(IpFilter::evaluate(&ip, &policy), PolicyDecision::Denied { .. }));
    }

    #[test]
    fn test_policy_default_deny() {
        let policy = IpPolicy {
            allow: vec![],
            deny: vec![],
            default_action: PolicyAction::Deny,
            log_blocked: true,
        };
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(matches!(IpFilter::evaluate(&ip, &policy), PolicyDecision::Denied { .. }));
    }

    #[test]
    fn test_v4_v6_mismatch() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let network: IpAddr = "2001:db8::".parse().unwrap();
        assert!(!IpFilter::matches_cidr(&ip, &network, 32));
    }
}
```

## Example Usage

```
$ pqvault policy set PROD_DB_URL \
    --allow "vpc=10.0.0.0/8" \
    --allow "office=203.0.113.0/24" \
    --deny "0.0.0.0/0"

  IP Policy set for PROD_DB_URL:
    Allow: vpc (10.0.0.0/8), office (203.0.113.0/24)
    Deny: 0.0.0.0/0 (all others)

$ pqvault policy test PROD_DB_URL --ip 10.0.1.50
  ALLOWED — matches rule: vpc (10.0.0.0/8)

$ pqvault policy test PROD_DB_URL --ip 8.8.8.8
  DENIED — IP 8.8.8.8 not in allow list, matches deny: 0.0.0.0/0

$ pqvault policy show PROD_DB_URL

  IP Policy: PROD_DB_URL
  ──────────────────────────

  Allow Rules:
    vpc       10.0.0.0/8
    office    203.0.113.0/24

  Deny Rules:
    (all)     0.0.0.0/0

  Default: Deny
  Logging: Enabled
```
