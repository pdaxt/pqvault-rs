# PQVault

Post-quantum secrets management vault with MCP server integration. All secrets are encrypted using a hybrid ML-KEM-768 + X25519 + AES-256-GCM scheme — an attacker must break **both** post-quantum and classical cryptography to access any secret.

## What It Does

PQVault is a centralized API key / secrets vault designed for AI agent workflows (Claude Code, MCP tools). It stores secrets encrypted on disk (`~/.pqvault/vault.enc`), with the master password in macOS Keychain, and exposes 12 tools over the Model Context Protocol (MCP) via stdio.

**Core flow:** Claude (or any MCP client) → calls `vault_get("ANTHROPIC_API_KEY")` → PQVault decrypts vault, checks rate limits, records usage, returns value → Claude uses the key → usage stats tracked automatically.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Claude Code / MCP Client                            │
│   calls vault_get, vault_add, vault_dashboard, ...  │
└──────────────────┬──────────────────────────────────┘
                   │ stdio JSON-RPC (MCP protocol)
                   ▼
┌─────────────────────────────────────────────────────┐
│ PQVault MCP Server (Rust, rmcp 1.1)                 │
│                                                     │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │ 12 Tools │  │ Rate      │  │ Usage Tracker    │ │
│  │ (MCP)    │  │ Limiter   │  │ (per-key stats)  │ │
│  └────┬─────┘  └─────┬─────┘  └────────┬─────────┘ │
│       │              │                  │           │
│  ┌────▼──────────────▼──────────────────▼─────────┐ │
│  │ Vault Engine                                   │ │
│  │  open_vault() → decrypt → VaultData → encrypt  │ │
│  └────────────────────┬───────────────────────────┘ │
│                       │                             │
│  ┌────────────────────▼───────────────────────────┐ │
│  │ Hybrid Crypto                                  │ │
│  │  ML-KEM-768 (PQ) + X25519 (classical)          │ │
│  │  → HKDF-SHA256 → AES-256-GCM                   │ │
│  └────────────────────┬───────────────────────────┘ │
└───────────────────────┼─────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ~/.pqvault/     macOS Keychain   ~/.pqvault/
   vault.enc       (master pw)     usage.json
   keys/                           audit.log
```

## Encryption

**Hybrid post-quantum + classical encryption:**

1. **Key Encapsulation (PQ):** ML-KEM-768 (FIPS 203) generates a shared secret via KEM
2. **Key Exchange (Classical):** X25519 ephemeral Diffie-Hellman generates a second shared secret
3. **Key Derivation:** Both shared secrets combined via HKDF-SHA256 into a 256-bit DEK
4. **Symmetric Encryption:** AES-256-GCM with random nonce and AAD (`pqvault-v1`)

**Key-at-rest protection:** Private keys encrypted with scrypt (N=2^17, r=8, p=1) + AES-256-GCM, master password stored in macOS Keychain.

**Why hybrid:** If ML-KEM-768 is broken (unlikely, it's NIST standardized), X25519 still protects. If quantum computers break X25519, ML-KEM-768 still protects. Both must be broken simultaneously.

## MCP Tools (12)

| Tool | Description |
|------|-------------|
| `vault_status` | Vault health summary: encryption info, key count, health status |
| `vault_get` | Get a secret value (rate-limited, usage-tracked, audit-logged) |
| `vault_list` | List all secrets with metadata (no values shown) |
| `vault_search` | Search secrets by name, category, or description |
| `vault_health` | Rotation warnings, expired keys, orphaned keys, smart alerts |
| `vault_project_env` | Generate .env file content for a registered project |
| `vault_add` | Add a new secret with auto-detected provider and rate limits |
| `vault_rotate` | Rotate a secret (update value + reset rotation timer) |
| `vault_dashboard` | Full dashboard: all keys with usage stats, costs, alerts |
| `vault_usage` | Detailed per-key usage: requests, rate limit %, cost estimate |
| `vault_import_claude` | Import API keys from `~/.claude.json` env blocks |
| `vault_delete` | Delete a secret and clean up project references |

## Provider Auto-Detection (10 providers)

When adding a key, PQVault auto-detects the provider from key name or value pattern and applies rate limits:

| Provider | Key Pattern | Rate Limits | Rotation |
|----------|-------------|-------------|----------|
| Anthropic | `sk-ant-*` or name contains `ANTHROPIC` | 50/min, 10k/day | 90 days |
| OpenAI | `sk-*` or name contains `OPENAI` | 60/min, 10k/day | 90 days |
| GitHub | `ghp_*`, `gho_*`, `github_pat_*` | 83/min, 5k/day | 90 days |
| Stripe | `sk_live_*`, `sk_test_*`, `pk_*` | 100/min, 10k/day | 30 days |
| Google | `AIza*` | 100/min, 10k/day | 180 days |
| Brave Search | `BSA*` | 10/min, 2k/month | 365 days |
| Resend | `re_*` | 10/min, 100/day | 180 days |
| Cloudflare | name contains `CLOUDFLARE`/`CF_API` | 50/min, 10k/day | 90 days |
| ElevenLabs | name contains `ELEVENLABS` | 20/min, 500/day | 180 days |
| Serper | name contains `SERPER` | 5/min, 100/month | 365 days |

## Smart Features

- **Token Bucket Rate Limiting:** Per-minute rate limiting prevents accidental API abuse
- **Daily/Monthly Quotas:** Tracks usage against provider limits, blocks when exceeded
- **Usage Spike Detection:** Alerts when today's usage exceeds 3x the 7-day average
- **Rotation Reminders:** Alerts when keys exceed their recommended rotation period
- **Unused Key Detection:** Flags keys unused for 30+ days
- **Cost Estimation:** Tracks estimated API costs per-key
- **Audit Log:** Append-only JSONL log of all vault access (get, add, rotate, delete)
- **Auto Backup:** Creates timestamped backups before destructive operations

## Use Cases

### 1. Centralized API Key Management for AI Agents
Multiple Claude Code instances share the same vault. Each `vault_get` call is rate-limited and tracked, preventing any single agent from burning through API quotas.

### 2. Secure .env Generation
Register projects with their required keys, then `vault_project_env("my-app")` generates a complete `.env` file without copying secrets manually.

### 3. Key Rotation Tracking
Every key has a rotation timer. `vault_health` shows which keys are overdue. `vault_rotate` updates the value and resets the timer.

### 4. API Cost Monitoring
`vault_dashboard` shows estimated costs per key, total spend, and usage trends across all providers.

### 5. Import from Claude Config
`vault_import_claude` scans `~/.claude.json` for API keys in MCP server env blocks and imports them into the encrypted vault.

### 6. Audit Trail
Every access is logged with timestamp, action, key name, project, and caller. Useful for debugging which agent accessed which key and when.

## Installation

```bash
cd /Users/pran/Projects/tools/pqvault-rs
cargo build --release
```

### MCP Configuration

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "/Users/pran/Projects/tools/pqvault-rs/target/release/pqvault",
      "args": ["serve"]
    }
  }
}
```

### CLI Usage

```bash
# Initialize vault (first time only)
pqvault init

# Start MCP server
pqvault serve

# CLI commands
pqvault status
pqvault list
pqvault get MY_API_KEY
pqvault add MY_API_KEY sk-ant-xxx123
pqvault health
```

## File Layout

```
~/.pqvault/
├── vault.enc           # Encrypted vault (hybrid PQ+classical)
├── vault.meta.json     # Encryption metadata (algorithm info)
├── pq_public.bin       # ML-KEM-768 public key
├── pq_private.enc      # ML-KEM-768 private key (scrypt-encrypted)
├── x25519_public.bin   # X25519 public key
├── x25519_private.enc  # X25519 private key (scrypt-encrypted)
├── usage.json          # Per-key usage stats (not encrypted)
├── audit.log           # Access audit trail (JSONL, not encrypted)
└── backups/
    └── vault.YYYY-MM-DD.enc
```

## Known Edge Cases & Limitations

### Crypto
- Empty plaintext encrypts successfully (valid use case)
- Very large secrets (>100MB) may cause OOM — all in-memory
- Binary payload format uses u32 lengths — max component size 4GB

### Vault
- `dirs::home_dir().unwrap()` — panics if no home directory
- No file locking — concurrent access from multiple processes can corrupt vault
- Partial write on disk-full could corrupt `vault.enc`
- Unix permissions (0o600) — not portable to Windows

### MCP Server
- `vault_import_claude` acquires tracker lock while vault lock is held — potential deadlock path with concurrent calls
- `vault_get` appends usage stats to the secret value — callers that parse the value must handle the `\n--- Usage:` suffix
- `vault_search` doesn't search tags despite the tool description mentioning tags
- No length/format validation on key names — newlines or null bytes in names could cause issues

### Smart Tracker
- Usage spike detection uses `HashMap::values()` which has non-deterministic ordering — the "last 7 days" may not be chronologically last
- `usage.json` stores key names in plaintext (not values) — leaks which services you use
- Token bucket uses f64 timestamps — precision loss after long uptimes
- Alerts accumulate without acknowledgment mechanism via MCP

### Audit
- Audit log grows unbounded — no rotation/compaction
- Audit log stores key names in plaintext — same metadata leak as usage.json
- No MCP tool to query or search the audit log

### Health
- `rotation_days = 0` skips rotation check (by design) but could confuse users
- Date parsing failures silently skip checks — no warning

### Provider Detection
- Greedy pattern matching: a key named "OPENAI_ANTHROPIC_KEY" matches `ANTHROPIC` first
- `auto_categorize` uses `contains()`: "MY_AWESOME_VAR" matches "AWS" category

## What's Missing (Future Work)

| Feature | Priority | Notes |
|---------|----------|-------|
| File locking (flock) | High | Prevents concurrent vault corruption |
| Encrypt usage.json | Medium | Leaks key names currently |
| Encrypt audit.log | Medium | Leaks access patterns |
| Tag management tool | Medium | Tags field exists in model but no MCP tool |
| Alert acknowledgment tool | Medium | Alerts accumulate with no dismiss mechanism |
| Project registration tool | Medium | No MCP tool to register/manage projects |
| Audit log query tool | Low | Log exists but no search via MCP |
| Backup management | Low | No list/restore/prune backups via MCP |
| Bulk operations | Low | No bulk add/delete/rotate |
| Integration tests | High | Only crypto unit tests exist |
| Cross-platform | Low | macOS-only due to Keychain + Unix perms |
| Key strength validation | Low | Could validate API key format per provider |
| Vault format migration | Low | No version migration path |

## Tests

```bash
# Run crypto unit tests
cargo test

# Manual MCP protocol test
echo '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | ./target/release/pqvault serve
```

4 crypto unit tests:
- `test_password_encrypt_decrypt` — scrypt + AES-256-GCM roundtrip
- `test_password_decrypt_wrong_password` — wrong password fails
- `test_hybrid_encrypt_decrypt` — full ML-KEM-768 + X25519 roundtrip
- `test_payload_serialize_deserialize` — binary format roundtrip

## Source Structure

```
src/
├── main.rs       # CLI entry + MCP server launcher
├── lib.rs        # Module re-exports
├── crypto.rs     # Hybrid PQ+classical encryption (297 lines)
├── vault.rs      # Vault file operations (150 lines)
├── keychain.rs   # macOS Keychain access (42 lines)
├── models.rs     # Data types: SecretEntry, ProjectEntry, VaultData (154 lines)
├── providers.rs  # 10 provider configs + auto-detection (197 lines)
├── smart.rs      # Usage tracking, rate limiting, dashboard (651 lines)
├── health.rs     # Expiry, rotation, orphan checks (65 lines)
├── audit.rs      # Append-only audit log (74 lines)
├── env_gen.rs    # .env file generation (40 lines)
└── mcp.rs        # MCP server: 12 tools via rmcp (626 lines)
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rmcp` | 1.1 | MCP server (stdio JSON-RPC) |
| `ml-kem` | 0.2 | ML-KEM-768 post-quantum KEM (FIPS 203) |
| `kem` | 0.3.0-pre.0 | KEM traits (Encapsulate/Decapsulate) |
| `x25519-dalek` | 2 | X25519 Diffie-Hellman |
| `aes-gcm` | 0.10 | AES-256-GCM symmetric encryption |
| `hkdf` | 0.12 | HKDF-SHA256 key derivation |
| `sha2` | 0.10 | SHA-256 hash |
| `scrypt` | 0.11 | Password-based key derivation |
| `keyring` | 3 | macOS Keychain (apple-native) |
| `clap` | 4 | CLI argument parsing |
| `tokio` | 1 | Async runtime |
| `serde` / `serde_json` | 1.0 | JSON serialization |
| `schemars` | 1.0 | JSON Schema generation for MCP |
| `chrono` | 0.4 | Date/time handling |
| `regex` | 1 | Provider key pattern matching |
| `rand` | 0.8 | Cryptographic RNG |
| `thiserror` | 1 | Error types |
| `anyhow` | 1 | Error handling |
| `tracing` | 0.1 | Structured logging |
