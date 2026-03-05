# PQVault

**Post-quantum secrets management for AI agent workflows.**

A centralized, encrypted vault for API keys and secrets. Designed for environments where multiple AI agents (Claude Code, MCP tools) need controlled access to credentials — with per-key rate limiting, usage tracking, cost estimation, and a full audit trail.

All secrets encrypted with hybrid **ML-KEM-768 + X25519 + AES-256-GCM**. An attacker must break both post-quantum *and* classical cryptography simultaneously to access any secret.

---

## Why PQVault Exists

**Problem:** AI agents need API keys. Developers scatter them across `.env` files, `~/.claude.json` env blocks, shell history, and plaintext configs. Keys get leaked, forgotten, over-used, never rotated. One agent can burn through an entire monthly quota in minutes with no visibility.

**Solution:** One encrypted vault. Every key access is rate-limited, usage-tracked, and audit-logged. AI agents get keys through MCP — the vault controls *which* keys, *how often*, and *who asked*.

**Why post-quantum:** NIST standardized ML-KEM in 2024 (FIPS 203). Harvest-now-decrypt-later attacks mean data encrypted today with classical-only crypto may be readable by quantum computers in 5-15 years. API keys rotate faster than that, but the vault's master key and private keys protect *all* secrets — those deserve quantum-resistant protection now.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Claude Code / MCP Client                            │
│   vault_get, vault_add, vault_dashboard, ...        │
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
   *.bin/*.enc                     audit.log
```

---

## Encryption Deep-Dive

### Hybrid Encryption Scheme

Every vault save performs:

1. **ML-KEM-768 Encapsulation** (post-quantum): Generate a 32-byte shared secret `pq_ss` and ciphertext `pq_ct` from the recipient's encapsulation key. Uses FIPS 203 / NIST standard. Key size: 1184 bytes (public), 2400 bytes (private).

2. **X25519 Diffie-Hellman** (classical): Generate an ephemeral X25519 keypair. Compute shared secret `x25519_ss` = ECDH(ephemeral_private, recipient_public). 32-byte shared secret.

3. **Key Derivation**: `dek = HKDF-SHA256(salt=random_32_bytes, ikm=pq_ss || x25519_ss, info="pqvault-hybrid-dek-v1")`. 256-bit data encryption key.

4. **Symmetric Encryption**: `ciphertext = AES-256-GCM(key=dek, nonce=random_12_bytes, plaintext, aad="pqvault-v1")`.

### Binary Payload Format

```
Bytes 0-3:   u32 BE — length of pq_ciphertext (1088 for ML-KEM-768)
Bytes 4-7:   u32 BE — length of x25519_ephemeral (32)
Bytes 8-11:  u32 BE — length of salt (32)
Bytes 12-15: u32 BE — length of nonce (12)
Bytes 16-19: u32 BE — length of ciphertext (varies)
Byte  20+:   pq_ciphertext || x25519_ephemeral || salt || nonce || ciphertext
```

### Key-at-Rest Protection

Private keys (`pq_private.enc`, `x25519_private.enc`) are encrypted with:
- **KDF**: scrypt(N=131072, r=8, p=1) — 128MB memory-hard
- **Cipher**: AES-256-GCM with random salt (32 bytes) + nonce (12 bytes)
- **AAD**: `pqvault-pw-v1`
- **File permissions**: `0o600` (owner read/write only)

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Quantum resistance | ML-KEM-768 (FIPS 203) |
| Classical resistance | X25519 + AES-256-GCM |
| Hybrid binding | Both shared secrets must be known for DEK derivation |
| Forward secrecy | Ephemeral X25519 keypair per encryption |
| Authentication | AES-GCM authenticated encryption with AAD |
| Key-at-rest | scrypt (128MB) + AES-256-GCM |
| Master password | macOS Keychain (Secure Enclave on Apple Silicon) |
| Nonce reuse prevention | Random 12-byte nonce per encryption (collision probability negligible) |

---

## MCP Tools (12)

### Read Operations

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_status` | none | Encryption info, key count, project count, health status, active alerts |
| `vault_get` | `key`, `caller?` | Get secret value. Rate-limited per provider. Usage tracked. Returns value in first content block, usage stats in second. |
| `vault_list` | `category?` | List all secrets with metadata (name, category, provider, usage count, rotation date). No values shown. |
| `vault_search` | `pattern` | Case-insensitive search across key names, descriptions, categories, and tags |
| `vault_health` | none | Expired keys, rotation-due keys, orphaned keys (no project), smart alerts (usage spikes, idle keys) |
| `vault_usage` | `key` | Detailed per-key report: total/daily/monthly requests, rate limit %, estimated cost, recent callers, alerts |
| `vault_dashboard` | none | Full markdown dashboard: all keys with usage, costs, limits, health status in a table |
| `vault_project_env` | `project` | Generate `.env` file content for a registered project (sorted, with extras) |

### Write Operations

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_add` | `key`, `value`, `category?`, `description?` | Add secret. Auto-detects provider from name/value pattern. Sets up rate limits and usage tracking. |
| `vault_rotate` | `key`, `new_value` | Update secret value and reset rotation timestamp. Clears rotation alerts. |
| `vault_delete` | `key` | Remove secret and clean up all project references |
| `vault_import_claude` | none | Scan `~/.claude.json` for API keys in MCP server env blocks. Import with auto-detection. |

---

## Provider System

### Auto-Detection

When a key is added, PQVault detects the provider by:

1. **Name matching** (word-boundary aware): Key name checked against provider patterns. Uses word boundaries — `AWESOME_VAR` does NOT match `AWS`, but `AWS_KEY` does.
2. **Value pattern matching**: Key value checked against regex patterns (e.g., `^sk-ant-` for Anthropic).
3. **Longest match first**: If multiple patterns could match, longer patterns take priority to avoid false positives.

### Provider Configs

| Provider | Name Pattern | Value Pattern | RPM | Daily | Monthly | Cost/req | Rotation |
|----------|-------------|---------------|-----|-------|---------|----------|----------|
| Anthropic | `ANTHROPIC` | `^sk-ant-` | 50 | 10,000 | - | $0.003 | 90d |
| OpenAI | `OPENAI` | `^sk-[a-zA-Z0-9]{20,}` | 60 | 10,000 | - | $0.002 | 90d |
| GitHub | `GITHUB` | `^(ghp_\|gho_\|github_pat_)` | 83 | 5,000 | - | $0.000 | 90d |
| Stripe | `STRIPE` | `^(sk_live_\|sk_test_\|pk_)` | 100 | 10,000 | - | $0.000 | 30d |
| Google | `GOOGLE_API` | `^AIza` | 100 | 10,000 | - | $0.001 | 180d |
| Brave | `BRAVE` | `^BSA[a-zA-Z0-9]{20,}` | 10 | - | 2,000 | $0.000 | 365d |
| Resend | `RESEND` | `^re_` | 10 | 100 | - | $0.000 | 180d |
| Cloudflare | `CLOUDFLARE`, `CF_API` | - | 50 | 10,000 | - | $0.000 | 90d |
| ElevenLabs | `ELEVENLABS` | - | 20 | 500 | - | $0.005 | 180d |
| Serper | `SERPER` | - | 5 | - | 100 | $0.000 | 365d |

### Rate Limiting

Three-tier rate limiting:

1. **Token Bucket** (per-minute): Smooth rate limiting. Tokens refill at `rpm/60` per second. Prevents burst abuse.
2. **Daily Counter**: Hard cap per calendar day. Resets at midnight local time.
3. **Monthly Counter**: Hard cap per calendar month. Used for providers with monthly quotas (Brave, Serper).

When rate limited, `vault_get` returns `RATE LIMITED: <reason>` instead of the secret value.

### Smart Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `unused_key` | No access for 30+ days | warning |
| `rotation_due` | Key age > provider's rotation_days | warning/critical |
| `usage_spike` | Today's requests > 3x 7-day chronological average | warning |

Alerts are deduplicated (same type within 1 hour) and capped at 50 per key.

---

## Category System

Keys are auto-categorized by name pattern (word-boundary matching):

| Category | Matching Patterns |
|----------|------------------|
| `ai` | ANTHROPIC, OPENAI, HF_TOKEN, HUGGING, REPLICATE, STABILITY, ELEVENLABS, CLAUDE |
| `payment` | STRIPE, PAYPAL, RAZORPAY |
| `cloud` | AWS, GCP, GOOGLE_APPLICATION, CLOUDFLARE, VERCEL, FIREBASE |
| `social` | TWITTER, X_API, X_ACCESS, LINKEDIN, INSTAGRAM, FACEBOOK, UNSPLASH |
| `email` | RESEND, SENDGRID, MAILGUN, GMAIL, SMTP, EMAIL |
| `database` | SUPABASE, POSTGRES, MYSQL, REDIS, MONGO, DATABASE_URL, DB |
| `auth` | SESSION_SECRET, JWT, OAUTH, AUTH, GOOGLE_CLIENT |
| `search` | SERPER, SERPAPI, ALGOLIA |
| `general` | (default — no pattern matched) |

Word-boundary matching prevents false positives: `MY_AWESOME_VAR` does NOT match `AWS`.

---

## Data Model

### SecretEntry

```rust
struct SecretEntry {
    value: String,           // The secret value
    category: String,        // Auto-detected or manual (ai, payment, cloud, ...)
    description: String,     // Human description
    created: String,         // YYYY-MM-DD
    rotated: String,         // YYYY-MM-DD (last rotation date)
    expires: Option<String>, // YYYY-MM-DD (optional hard expiry)
    rotation_days: i64,      // Recommended rotation interval (0 = never)
    projects: Vec<String>,   // Which projects use this key
    tags: Vec<String>,       // Searchable tags
}
```

### ProjectEntry

```rust
struct ProjectEntry {
    path: String,                        // Project filesystem path
    keys: Vec<String>,                   // Keys this project needs
    env_file: String,                    // Target .env file name
    env_extras: HashMap<String, String>, // Non-secret env vars (PORT, NODE_ENV, etc.)
}
```

### VaultData

```rust
struct VaultData {
    version: String,                          // "1.0"
    created: String,                          // ISO 8601
    secrets: HashMap<String, SecretEntry>,     // key_name → secret
    projects: HashMap<String, ProjectEntry>,   // project_name → config
}
```

---

## File Layout

```
~/.pqvault/
├── vault.enc             # Encrypted vault data (hybrid PQ+classical)
├── vault.meta.json       # Algorithm metadata (not encrypted, no secrets)
├── pq_public.bin         # ML-KEM-768 encapsulation key (1184 bytes)
├── pq_private.enc        # ML-KEM-768 decapsulation key (encrypted, 2400+ bytes)
├── x25519_public.bin     # X25519 public key (32 bytes)
├── x25519_private.enc    # X25519 private key (encrypted, 32+ bytes)
├── usage.json            # Per-key usage stats, rate limit state, alerts
├── audit.log             # JSONL access log (rotates at 10k lines)
├── audit.log.1           # Rotated log (max 3 rotated files)
├── audit.log.2
├── audit.log.3
└── backups/
    └── vault.YYYY-MM-DD.enc
```

### vault.meta.json

```json
{
  "version": "1.0",
  "encryption": "hybrid-mlkem768-x25519-aes256gcm",
  "kdf": "scrypt-n131072-r8-p1",
  "pq_algorithm": "ML-KEM-768 (FIPS 203)",
  "classical_algorithm": "X25519",
  "symmetric_algorithm": "AES-256-GCM"
}
```

---

## Installation

```bash
git clone https://github.com/pdaxt/pqvault-rs.git
cd pqvault-rs
cargo build --release
```

### MCP Configuration

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "/path/to/pqvault-rs/target/release/pqvault",
      "args": ["serve"]
    }
  }
}
```

### CLI

```bash
pqvault init          # Initialize vault (generates keys, stores master pw in Keychain)
pqvault serve         # Start MCP server (stdio JSON-RPC)
pqvault status        # Show vault health summary
pqvault list          # List all secrets (no values)
pqvault get MY_KEY    # Print secret value
pqvault add KEY val   # Add secret (auto-categorizes)
pqvault health        # Show rotation/expiry/orphan warnings
```

---

## Test Coverage

**91 tests** across 8 test modules:

```
cargo test                     # Run all 91 tests
cargo test --test stress_tests # Run 87 stress/edge-case tests
cargo test --lib               # Run 4 crypto unit tests
```

### Test Breakdown

| Module | Tests | Coverage |
|--------|-------|----------|
| **crypto** | 23 | Empty/single-byte/1MB/binary/unicode plaintext, wrong keys (PQ, X25519, both), corrupted ciphertext/nonce/salt, truncated/empty/garbage payloads, overflow lengths, encryption uniqueness, keypair independence, wrong key sizes, password encrypt/decrypt edge cases |
| **models** | 10 | Auto-categorize exact/false-positive/case/empty/special-char, serde defaults, JSON roundtrip, unicode values, 1000-secret vault, category completeness |
| **providers** | 11 | Detect by name, detect by value pattern, unknown provider, no false positives, case insensitivity, config validation, regex validity |
| **health** | 10 | Empty vault, fresh key, expired key, rotation due, rotation_days=0, orphaned key, category counting, invalid dates, expiry-today, 10k secret performance |
| **env_gen** | 7 | Basic generation, unknown project, extras, key sorting, missing secrets, values with equals, empty project |
| **smart** | 14 | Token bucket allow/exhaust, usage defaults, record access, caller cap (20), rate limit unknown key/provider, dashboard empty/populated, key status, alert dedup |
| **audit** | 5 | Empty log, filtered read, limit, serialization, special characters |
| **serialization** | 3 | Multi-size roundtrip (0-64k), complex vault JSON, full encrypt-decrypt-vault pipeline (100 secrets) |

---

## Security Roadmap (v3)

### Current Limitations

The vault files and master password are accessible to any process running as the same OS user. An AI agent with shell access can:

1. Read `~/.pqvault/usage.json` (key names in plaintext)
2. Query macOS Keychain for the master password
3. Decrypt the vault directly, bypassing rate limits and audit

### Planned: Daemon + Web Portal + Token-Gated Access

```
           HUMAN (Browser)
                │
         localhost:7700
         TOTP + password auth
                │
    ┌───────────┴───────────────────────────┐
    │  PQVault Daemon                       │
    │                                       │
    │  Web Portal (axum)                    │
    │  Token Manager (SQLite)               │
    │  Approval Queue (SSE push)            │
    │  Vault Engine (existing crypto)       │
    │                                       │
    │  Listens: localhost:7700 (HTTP)        │
    │           /tmp/pqvault.sock (Unix)     │
    └────────────┬──────────────────────────┘
                 │ Unix socket + token
        ┌────────┼────────┐
        ▼        ▼        ▼
    MCP Proxy   CLI     Other tools
```

**Key changes:**

1. **Master password removed from Keychain** — entered via web portal (TOTP-gated), held only in daemon memory
2. **usage.json + audit.log encrypted** — key names no longer leak
3. **Every vault_get requires a session token** — tokens created only via web portal with TOTP
4. **Hybrid approval model**: low-risk keys (ai, search, social) auto-approve with valid token. High-risk keys (payment, auth, database) require per-request human approval via web portal notification.
5. **Token scoping**: each token specifies which keys/categories it can access and has a TTL (1h/4h/8h/24h)
6. **Instant revocation**: compromised token revoked from web portal, all subsequent requests fail

---

## Source Structure

```
src/
├── main.rs        # CLI + MCP server entry (199 lines)
├── lib.rs         # Module re-exports (11 lines)
├── crypto.rs      # Hybrid PQ+classical encryption (341 lines)
├── vault.rs       # Vault file operations (150 lines)
├── keychain.rs    # macOS Keychain access (42 lines)
├── models.rs      # Data types + auto-categorize (170 lines)
├── providers.rs   # 10 provider configs + detection (213 lines)
├── smart.rs       # Usage tracking, rate limiting, dashboard (651 lines)
├── health.rs      # Expiry, rotation, orphan checks (65 lines)
├── audit.rs       # Append-only audit log + rotation (108 lines)
├── env_gen.rs     # .env file generation (40 lines)
└── mcp.rs         # MCP server: 12 tools via rmcp (631 lines)

tests/
└── stress_tests.rs  # 87 edge-case tests across all modules (1010 lines)
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rmcp` | 1.1 | MCP server framework (stdio JSON-RPC, tool routing) |
| `ml-kem` | 0.2 | ML-KEM-768 post-quantum KEM (FIPS 203) |
| `kem` | 0.3.0-pre.0 | KEM traits (Encapsulate/Decapsulate) |
| `x25519-dalek` | 2 | X25519 Diffie-Hellman key exchange |
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption |
| `hkdf` | 0.12 | HKDF-SHA256 key derivation |
| `sha2` | 0.10 | SHA-256 hash function |
| `scrypt` | 0.11 | Memory-hard password KDF |
| `keyring` | 3 | macOS Keychain (apple-native feature) |
| `clap` | 4 | CLI argument parsing |
| `tokio` | 1 | Async runtime (multi-thread) |
| `serde` / `serde_json` | 1.0 | JSON serialization |
| `schemars` | 1.0 | JSON Schema generation for MCP tool parameters |
| `chrono` | 0.4 | Date/time handling |
| `regex` | 1 | Provider key pattern matching |
| `rand` | 0.8 | Cryptographic RNG (OsRng) |
| `thiserror` | 1 | Error type derivation |
| `anyhow` | 1 | Error context propagation |
| `tracing` | 0.1 | Structured logging (stderr) |
| `dirs` | 5 | Cross-platform home directory |
