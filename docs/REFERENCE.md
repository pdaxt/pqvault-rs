# PQVault Reference Documentation

**Version:** 2.1.0
**Generated from source:** 2026-03-10

---

## Workspace Overview

| Crate | Type | Lines | Tests | Description |
|-------|------|------:|------:|-------------|
| `pqvault-core` | Library | 3,488 | 37 | Shared crypto, vault ops, proxy, models, providers |
| `pqvault-cli` | Binary | 1,806 | 0 | Terminal CLI (`pqvault init`, `add`, `get`, etc.) |
| `pqvault-web` | Binary | 1,237 | 0 | Web dashboard at `:9876` |
| `pqvault-mcp` | Binary | 522 | 0 | Core MCP server (7 tools) |
| `pqvault-proxy-mcp` | Binary | 212 | 0 | Zero-knowledge API proxy (1 tool) |
| `pqvault-health-mcp` | Binary | 175 | 0 | Health monitoring (3 tools) |
| `pqvault-env-mcp` | Binary | 224 | 0 | Environment management (3 tools) |
| `pqvault-unified` | Binary | 831 | 0 | All-in-one MCP (14 tools combined) |
| **Total** | | **8,495** | **37** | |

Legacy `src/` directory: 4,915 lines (original monolith, being migrated to crates)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AI Agents / Claude Code                          │
└────────┬──────────┬──────────┬──────────┬──────────┬─────────────────┘
         │ stdio    │ stdio    │ stdio    │ stdio    │ stdio
┌────────▼───┐ ┌────▼─────┐ ┌─▼────────┐ ┌▼────────┐ ┌▼───────────┐
│ pqvault-mcp│ │proxy-mcp │ │health-mcp│ │env-mcp  │ │unified-mcp │
│ 7 tools    │ │1 tool    │ │3 tools   │ │3 tools  │ │14 tools    │
└────────┬───┘ └────┬─────┘ └─┬────────┘ └┬────────┘ └┬───────────┘
         │          │         │           │           │
         └──────────┴─────────┴───────────┴───────────┘
                              │
                    ┌─────────▼──────────┐
                    │   pqvault-core     │
                    │                    │
                    │  crypto   vault    │
                    │  proxy    models   │
                    │  providers search  │
                    │  keychain audit    │
                    │  health   env_gen  │
                    │  agent    smart    │
                    └─────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ~/.pqvault/     macOS Keychain   ~/.pqvault/
        vault.enc       (master pw)      usage.json
        *.bin/*.enc     + file cache     audit.log
```

---

## MCP Tools Reference

### pqvault-mcp (Core Vault)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_status` | none | Vault health summary: encryption info, key count, health status |
| `vault_get` | `key: String`, `requester?: String` | Get a secret value by key name. Rate-limited and usage-tracked |
| `vault_list` | `category?: String`, `tag?: String` | List all secrets with metadata and usage stats (no values) |
| `vault_search` | `query: String` | Search secrets by name, tag, or description |
| `vault_add` | `key: String`, `value: String`, `description?: String`, `tags?: Vec<String>` | Add a new secret with auto-detected provider and rate limits |
| `vault_delete` | `key: String` | Delete a secret and remove all usage data |
| `vault_import_claude` | none | Import API keys from `~/.claude.json` env blocks |

### pqvault-proxy-mcp (Zero-Knowledge Proxy)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_proxy` | `key_name: String`, `url: String`, `method?: String`, `body?: String`, `headers?: Map` | Make API calls through vault. Key never exposed to agent |

### pqvault-health-mcp (Monitoring)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_health` | none | Rotation/expiry warnings, stale key detection |
| `vault_dashboard` | none | Full usage overview with cost estimates |
| `vault_usage` | `key_name: String` | Per-key usage statistics |

### pqvault-env-mcp (Environment)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_project_env` | `project: String` | Get `.env` content for a project |
| `vault_write_env` | `project: String`, `path?: String` | Write `.env` file to disk |
| `vault_rotate` | `key_name: String`, `new_value: String` | Update a secret value |

### pqvault-unified (All-in-One)

All 14 tools from above in a single binary. Use when you want one MCP registration instead of four.

---

## Core Library API (pqvault-core)

### crypto module

| Function | Signature | Description |
|----------|----------|-------------|
| `generate_keypair` | `() -> Result<HybridKeypair>` | Generate ML-KEM-768 + X25519 keypair |
| `hybrid_encrypt` | `(plaintext, public_keys) -> Result<Vec<u8>>` | Encrypt with dual PQ + classical |
| `hybrid_decrypt` | `(ciphertext, private_keys) -> Result<Vec<u8>>` | Decrypt hybrid ciphertext |
| `password_encrypt` | `(plaintext, password) -> Result<Vec<u8>>` | Scrypt + AES-256-GCM encryption |
| `password_decrypt` | `(data, password) -> Result<Vec<u8>>` | Scrypt + AES-256-GCM decryption |

### vault module

| Function | Signature | Description |
|----------|----------|-------------|
| `vault_exists` | `() -> bool` | Check if vault is initialized |
| `init_vault` | `() -> Result<String>` | Create new vault with keypairs |
| `open_vault` | `() -> Result<VaultData>` | Decrypt and load vault |
| `save_vault` | `(data) -> Result<()>` | Encrypt and save vault |
| `backup_vault` | `() -> Result<Option<PathBuf>>` | Create timestamped backup |

### proxy module

| Function | Signature | Description |
|----------|----------|-------------|
| `execute_proxy` | `async (key, url, method, body, headers) -> Result` | Execute proxied API call |
| `validate_url` | `(url, allowed_domains) -> Result<()>` | SSRF protection |
| `inject_auth` | `(headers, url, key, method) -> Result<()>` | Inject auth into request |
| `resolve_url` | `(url, base_url) -> Result<Url>` | Resolve relative URLs |

### providers module

Auto-detects provider from key patterns:

| Provider | Key Pattern | Auth Method | Verification Endpoint |
|----------|------------|-------------|----------------------|
| Anthropic | `sk-ant-*` | Bearer token | `/v1/messages` |
| OpenAI | `sk-*` (20+ chars) | Bearer token | `/v1/models` |
| Stripe | `sk_live_*`, `sk_test_*` | Basic auth | `/v1/balance` |
| Resend | `re_*` | Bearer token | `/emails` |
| Google | `AIza*` | Query param | N/A |
| Cloudflare | 37-char hex | Bearer token | `/zones` |

---

## Data Models

### SecretEntry

```rust
pub struct SecretEntry {
    pub value: String,           // The actual secret value
    pub description: String,     // Human-readable description
    pub provider: String,        // Auto-detected: "anthropic", "openai", etc.
    pub tags: Vec<String>,       // User-defined tags
    pub created_at: String,      // ISO 8601 timestamp
    pub updated_at: String,      // ISO 8601 timestamp
    pub rate_limit: RateLimit,   // Per-key rate limiting config
    pub usage: UsageStats,       // Access count, last used, cost estimate
}
```

### VaultData

```rust
pub struct VaultData {
    pub secrets: HashMap<String, SecretEntry>,
    pub version: String,
    pub created_at: String,
}
```

---

## Storage Layout

```
~/.pqvault/
├── vault.enc              # Encrypted vault (hybrid PQ + classical)
├── vault.meta.json        # Unencrypted metadata (key count, last modified)
├── pq_public.bin          # ML-KEM-768 public key
├── pq_private.enc         # ML-KEM-768 private key (password-encrypted)
├── x25519_public.bin      # X25519 public key
├── x25519_private.enc     # X25519 private key (password-encrypted)
├── usage.json             # Per-key usage statistics
├── audit.log              # Access audit trail
└── backups/               # Timestamped vault backups
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PQVAULT_HOME` | `~/.pqvault` | Vault storage directory |
| `PQVAULT_WEB_PORT` | `9876` | Web dashboard port |
| `RUST_LOG` | `info` | Log level (trace/debug/info/warn/error) |

### Claude Code Integration

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "/path/to/pqvault-mcp",
      "args": []
    },
    "pqvault-proxy": {
      "command": "/path/to/pqvault-proxy-mcp",
      "args": []
    },
    "pqvault-health": {
      "command": "/path/to/pqvault-health-mcp",
      "args": []
    },
    "pqvault-env": {
      "command": "/path/to/pqvault-env-mcp",
      "args": []
    }
  }
}
```

Or use the unified server:

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "/path/to/pqvault-unified",
      "args": []
    }
  }
}
```

---

## Dependencies

| Category | Crate | Version | Purpose |
|----------|-------|---------|---------|
| **Crypto** | `ml-kem` | 0.2 | Post-quantum KEM (FIPS 203) |
| | `x25519-dalek` | 2 | Classical key exchange |
| | `aes-gcm` | 0.10 | Symmetric encryption |
| | `hkdf` + `sha2` | 0.12 | Key derivation |
| | `scrypt` | 0.11 | Password hashing |
| **MCP** | `rmcp` | 1.1 | Anthropic's Rust MCP SDK |
| **Runtime** | `tokio` | 1 | Async runtime |
| **Web** | `axum` | 0.8 | Web framework |
| **CLI** | `clap` | 4 | Argument parsing |
| **Keychain** | `keyring` | 3 | macOS Keychain access |
| **HTTP** | `reqwest` | 0.12 | Outbound API calls (proxy) |
