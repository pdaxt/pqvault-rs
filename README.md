# PQVault

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://rust-lang.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen)](https://modelcontextprotocol.io)

**Post-quantum secrets management for AI agent workflows.**

A centralized, encrypted vault for API keys and secrets. Designed for environments where multiple AI agents need controlled access to credentials — with per-key rate limiting, usage tracking, cost estimation, key verification, and a full audit trail.

Built by [Pranjal Gupta](https://github.com/pdaxt) at [DataXLR8](https://dataxlr8.ai) — part of the DataXLR8 AI infrastructure ecosystem.

All secrets encrypted with hybrid **ML-KEM-768 + X25519 + AES-256-GCM**. An attacker must break both post-quantum *and* classical cryptography simultaneously to access any secret.

---

## Why PQVault Exists

**Problem:** AI agents need API keys. Developers scatter them across `.env` files, MCP config env blocks, shell history, and plaintext configs. Keys get leaked, forgotten, over-used, never rotated. One agent can burn through an entire monthly quota in minutes with no visibility.

**Solution:** One encrypted vault. Every key access is rate-limited, usage-tracked, and audit-logged. AI agents get keys through MCP — the vault controls *which* keys, *how often*, and *who asked*.

**Why post-quantum:** NIST standardized ML-KEM in 2024 (FIPS 203). Harvest-now-decrypt-later attacks mean data encrypted today with classical-only crypto may be readable by quantum computers in 5-15 years. API keys rotate faster than that, but the vault's master key and private keys protect *all* secrets — those deserve quantum-resistant protection now.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ MCP Client (AI Agent)                                │
│   vault_get, vault_proxy, vault_dashboard, ...          │
└──────────────────┬──────────────────────────────────────┘
                   │ stdio JSON-RPC (MCP protocol)
                   ▼
┌─────────────────────────────────────────────────────────┐
│ PQVault MCP Server (Rust, rmcp 1.1)                     │
│                                                         │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────────┐ │
│  │ 14 Tools │  │ Rate      │  │ Usage Tracker        │ │
│  │ (MCP)    │  │ Limiter   │  │ (per-key stats)      │ │
│  └────┬─────┘  └─────┬─────┘  └────────┬─────────────┘ │
│       │              │                  │               │
│  ┌────▼──────────────▼──────────────────▼─────────────┐ │
│  │ Vault Engine                                       │ │
│  │  open_vault() → decrypt → VaultData → encrypt      │ │
│  └────────────────────┬───────────────────────────────┘ │
│                       │                                 │
│  ┌────────────────────▼───────────────────────────────┐ │
│  │ Hybrid Crypto                                      │ │
│  │  ML-KEM-768 (PQ) + X25519 (classical)              │ │
│  │  → HKDF-SHA256 → AES-256-GCM                       │ │
│  └────────────────────┬───────────────────────────────┘ │
└───────────────────────┼─────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ~/.pqvault/     macOS Keychain   ~/.pqvault/
   vault.enc       (master pw)     usage.json
   *.bin/*.enc     + file cache    audit.log
```

### Interfaces

| Interface | Port | Purpose |
|-----------|------|---------|
| **MCP Server** | stdio | AI agent access via JSON-RPC (14 tools) |
| **Web Dashboard** | 9876 | Human-facing UI: browse, verify, edit, search secrets |
| **CLI** | - | Terminal commands: init, status, list, get, add, health |

---

## Web Dashboard

Full-featured web UI at `http://localhost:9876` for human operators.

### Features

- **Provider-grouped view** — Secrets organized by detected provider (Anthropic, Stripe, Resend, etc.)
- **Key verification** — One-click verification against provider APIs. Detects: active, error, restricted-scope, unknown
- **Masked values** — First 4 + last 4 characters displayed (e.g., `sk-a...8QAA`)
- **Sidebar filters** — Filter by provider, status (active/error/unknown), category
- **Full-text search** — Search across key names, accounts, descriptions, projects
- **Metadata editing** — Set account, environment (production/development/test), description per key
- **Add / Rotate / Delete** — Full CRUD via modals
- **Dark theme** — Purple accent, designed for developer use

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard HTML (embedded, no external deps) |
| `GET` | `/api/status` | Vault summary: encryption, counts, providers, status |
| `GET` | `/api/secrets` | All secrets with masked values and metadata |
| `POST` | `/api/secrets` | Add a new secret |
| `DELETE` | `/api/secrets/{key}` | Delete a secret |
| `PUT` | `/api/secrets/{key}/rotate` | Rotate secret value |
| `PUT` | `/api/secrets/{key}/meta` | Update account, environment, description |
| `POST` | `/api/secrets/{key}/verify` | Verify key against provider API |
| `GET` | `/api/health` | Health report |
| `GET` | `/api/search?q=...` | Search secrets |

### Key Verification Logic

Verification hits provider API endpoints with proper auth injection:

| Status Code | Interpretation |
|-------------|---------------|
| 2xx | **active** — key is valid |
| 400 | **active** — auth passed, request format issue |
| 401/403 + "restricted" | **active** — valid key with limited scope |
| 401/403 | **error** — key invalid or expired |
| 5xx | **unknown** — server error, try later |
| Connection error | **error** — can't reach provider |

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
| Master password | macOS Keychain + file cache (`~/.pqvault/.master_cache`) |
| Nonce reuse prevention | Random 12-byte nonce per encryption (collision probability negligible) |

---

## MCP Tools (14)

### Read Operations

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_status` | none | Encryption info, key count, project count, health status, active alerts |
| `vault_get` | `key`, `caller?` | Get secret value. Rate-limited per provider. Usage tracked. Returns value + usage stats |
| `vault_list` | `category?` | List all secrets with metadata (name, category, provider, usage, rotation date). No values shown |
| `vault_search` | `pattern` | Case-insensitive search across key names, descriptions, categories, and tags |
| `vault_health` | none | Expired keys, rotation-due keys, orphaned keys, smart alerts (usage spikes, idle keys) |
| `vault_usage` | `key` | Detailed per-key report: total/daily/monthly requests, rate limit %, cost, callers, alerts |
| `vault_dashboard` | none | Full markdown dashboard: all keys with usage, costs, limits, health in a table |
| `vault_project_env` | `project` | Generate `.env` file content for a registered project |

### Write Operations

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_add` | `key`, `value`, `category?`, `description?` | Add secret. Auto-detects provider. Sets up rate limits |
| `vault_rotate` | `key`, `new_value` | Update secret value, reset rotation timestamp, clear alerts |
| `vault_delete` | `key` | Remove secret and clean up project references |
| `vault_import_claude` | none | Scan `~/.claude.json` for API keys in MCP server env blocks |

### Zero-Knowledge Operations

| Tool | Parameters | Description |
|------|-----------|-------------|
| `vault_proxy` | `key`, `method`, `url`, `body?`, `headers?`, `query?`, `caller?`, `auth_override?` | **Proxy API calls through vault — key never exposed to caller.** Auth auto-injected based on provider. SSRF-protected |
| `vault_write_env` | `project`, `directory`, `filename?` | **Write .env file to disk — values never returned to caller.** Path validated, permissions set to 0600 |

### vault_proxy Details

The proxy tool is the recommended way to call external APIs. Instead of `vault_get` + manual HTTP call (which exposes the key), `vault_proxy` keeps the key inside the vault process:

```
# Instead of:
vault_get("STRIPE_SECRET_KEY")  → gets key → caller makes HTTP call

# Use:
vault_proxy(key="STRIPE_SECRET_KEY", method="GET", url="/v1/balance")
  → vault makes HTTP call with key injected → returns response only
```

**Security features:**
- HTTPS-only enforcement
- SSRF protection: blocks IP literals, localhost, .local, .internal, metadata endpoints
- Domain allowlisting per provider
- Auth method auto-detection: Bearer, CustomHeader, BasicAuth, QueryParam
- `auth_override` for unknown providers: `"bearer"`, `"basic"`, `"header:X-Key"`, `"query:api_key"`
- 1MB response limit
- Binary response detection

---

## Provider System

### Auto-Detection

When a key is added, PQVault detects the provider by:

1. **Name matching** (word-boundary aware): Key name checked against provider patterns. Uses word boundaries — `AWESOME_VAR` does NOT match `AWS`, but `AWS_KEY` does.
2. **Value pattern matching**: Key value checked against regex patterns (e.g., `^sk-ant-` for Anthropic).
3. **Longest match first**: If multiple patterns could match, longer patterns take priority.

### Provider Configs (10)

| Provider | Name Pattern | Value Pattern | RPM | Daily | Monthly | Cost/req | Rotation | Verify Path |
|----------|-------------|---------------|-----|-------|---------|----------|----------|-------------|
| Anthropic | `ANTHROPIC` | `^sk-ant-` | 50 | 10,000 | - | $0.003 | 90d | `/v1/models` |
| OpenAI | `OPENAI` | `^sk-[a-zA-Z0-9]{20,}` | 60 | 10,000 | - | $0.002 | 90d | `/v1/models` |
| GitHub | `GITHUB` | `^(ghp_\|gho_\|github_pat_)` | 83 | 5,000 | - | $0.000 | 90d | `/user` |
| Stripe | `STRIPE` | `^(sk_live_\|sk_test_\|pk_)` | 100 | 10,000 | - | $0.000 | 30d | `/v1/balance` |
| Google | `GOOGLE_API` | `^AIza` | 100 | 10,000 | - | $0.001 | 180d | - |
| Brave | `BRAVE` | `^BSA[a-zA-Z0-9]{20,}` | 10 | - | 2,000 | $0.000 | 365d | `/res/v1/web/search?q=test&count=1` |
| Resend | `RESEND` | `^re_` | 10 | 100 | - | $0.000 | 180d | `/api-keys` |
| Cloudflare | `CLOUDFLARE`, `CF_API` | - | 50 | 10,000 | - | $0.000 | 90d | `/client/v4/user/tokens/verify` |
| ElevenLabs | `ELEVENLABS` | - | 20 | 500 | - | $0.005 | 180d | `/v1/user` |
| Serper | `SERPER` | - | 5 | - | 100 | $0.000 | 365d | - |

### Rate Limiting

Three-tier rate limiting:

1. **Token Bucket** (per-minute): Smooth rate limiting. Tokens refill at `rpm/60` per second.
2. **Daily Counter**: Hard cap per calendar day. Resets at midnight.
3. **Monthly Counter**: Hard cap per calendar month. Used for Brave, Serper.

### Smart Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `unused_key` | No access for 30+ days | warning |
| `rotation_due` | Key age > provider's rotation_days | warning/critical |
| `usage_spike` | Today's requests > 3x 7-day average | warning |

---

## Data Model

### SecretEntry

```rust
struct SecretEntry {
    value: String,              // The secret value
    category: String,           // Auto-detected: ai, payment, cloud, social, email, database, auth, search, general
    description: String,        // Human description
    created: String,            // YYYY-MM-DD
    rotated: String,            // YYYY-MM-DD (last rotation date)
    expires: Option<String>,    // YYYY-MM-DD (optional hard expiry)
    rotation_days: i64,         // Recommended rotation interval
    projects: Vec<String>,      // Which projects use this key
    tags: Vec<String>,          // Searchable tags
    account: Option<String>,    // Account identity (e.g. "pranjal@dataxlr8.com")
    environment: Option<String>,// production, development, test
    related_keys: Vec<String>,  // Paired keys (e.g. client_id <-> client_secret)
    last_verified: Option<String>,  // Last verification timestamp (RFC 3339)
    last_error: Option<String>,     // Last error from verification
    key_status: String,             // active, error, unknown, revoked
}
```

### KeyUsage (smart.rs)

```rust
struct KeyUsage {
    provider: String,                    // Detected provider name
    total_requests: u64,                 // Lifetime request count
    daily_counts: HashMap<String, u64>,  // YYYY-MM-DD → count
    monthly_counts: HashMap<String, u64>,// YYYY-MM → count
    last_used: Option<String>,           // RFC 3339 timestamp
    first_used: Option<String>,          // RFC 3339 timestamp
    estimated_cost_usd: f64,             // Cumulative estimated cost
    token_bucket: Option<TokenBucket>,   // Per-minute rate limiter
    alerts: Vec<AlertEntry>,             // Smart alerts
    recent_callers: Vec<CallerEntry>,    // Last 20 callers
}
```

---

## Keychain & Password Caching

Master password storage uses a three-tier approach to avoid macOS Keychain prompt storms:

1. **In-process cache** (`OnceLock<Option<String>>`): Single read per process lifetime
2. **File cache** (`~/.pqvault/.master_cache`): Permissions 0600, avoids Keychain for subsequent processes
3. **macOS Keychain** (Secure Enclave): Authoritative source, queried only if file cache is missing

This was implemented to solve the problem of 30+ MCP `pqvault serve` processes (one per tmux pane) each triggering Keychain prompts simultaneously.

---

## File Layout

```
~/.pqvault/
├── vault.enc             # Encrypted vault data (hybrid PQ+classical)
├── vault.meta.json       # Algorithm metadata (not encrypted, no secrets)
├── pq_public.bin         # ML-KEM-768 encapsulation key (1184 bytes)
├── pq_private.enc        # ML-KEM-768 decapsulation key (encrypted)
├── x25519_public.bin     # X25519 public key (32 bytes)
├── x25519_private.enc    # X25519 private key (encrypted)
├── usage.json            # Per-key usage stats, rate limit state, alerts
├── .master_cache         # File-cached master password (0600 permissions)
├── audit.log             # JSONL access log (rotates at 10k lines)
├── audit.log.{1,2,3}     # Rotated logs (max 3)
└── backups/
    └── vault.YYYY-MM-DD.enc
```

---

## Installation

```bash
git clone https://github.com/pdaxt/pqvault-rs.git
cd pqvault-rs
cargo build --release
codesign -s - target/release/pqvault  # macOS: ad-hoc sign to avoid Gatekeeper
```

### MCP Configuration

Add to your MCP client configuration:

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

### CLI Commands

```bash
pqvault init                    # Initialize vault (generates keys, stores master pw in Keychain)
pqvault serve                   # Start MCP server (stdio JSON-RPC)
pqvault status                  # Show vault health summary
pqvault list                    # List all secrets (no values)
pqvault get MY_KEY              # Print secret value
pqvault add KEY val [-c cloud]  # Add secret with optional category
pqvault health                  # Show rotation/expiry/orphan warnings
pqvault web [--port 9876]       # Start web dashboard
```

---

## Known Gaps

### Security

1. **No authentication on web UI** — Anyone on localhost can access all secrets via the web dashboard. Needs session auth or TOTP.
2. **File cache stores master password in plaintext** — `~/.pqvault/.master_cache` is 0600 but readable by same-user processes. Trade-off for avoiding Keychain storms.
3. **usage.json leaks key names** — Not encrypted. An attacker can see which API keys exist without decrypting the vault.
4. **No TLS on web UI** — Listening on localhost only, but secrets are transmitted over HTTP.
5. **Audit log not encrypted** — JSONL with action, key name, timestamps in plaintext.

### Functionality

6. **No batch verification** — Web UI "Verify All" runs sequentially; could be parallelized.
7. **No webhook/notification** — When a key verification fails, there's no push notification.
8. **No key expiry warnings in web UI** — Health report exists but isn't prominently shown.
9. **Usage stats not shown in web UI** — API returns usage data but the dashboard doesn't display it prominently.
10. **No multi-user support** — Single vault, single master password. No access control per user.
11. **No backup management in web UI** — Backups exist but aren't visible or manageable.
12. **Provider-specific headers hardcoded** — Only Anthropic has a special header (`anthropic-version`). Future providers may need similar treatment.
13. **No import from .env files** — Can import from `~/.claude.json` but not from existing `.env` files.

### Architecture

14. **Web UI HTML embedded in Rust binary** — 560+ lines of HTML/CSS/JS in a raw string. Hard to iterate. Should be a separate file or template.
15. **No database** — All state in JSON files. Works for <1000 secrets but won't scale.
16. **Vault re-encrypted on every save** — Full hybrid encrypt for every modification. Could use a faster path for small changes.

---

## Source Structure

```
src/
├── main.rs        # CLI + MCP server entry point (220 lines)
├── lib.rs         # Module re-exports (12 lines)
├── mcp.rs         # MCP server: 14 tools via rmcp (876 lines)
├── web.rs         # Axum web dashboard + API (1304 lines)
├── smart.rs       # Usage tracking, rate limiting, dashboard (652 lines)
├── proxy.rs       # HTTP proxy with SSRF protection (538 lines)
├── crypto.rs      # Hybrid PQ+classical encryption (340 lines)
├── providers.rs   # 10 provider configs + detection (281 lines)
├── models.rs      # Data types + auto-categorize (199 lines)
├── vault.rs       # Vault file operations (149 lines)
├── audit.rs       # Append-only audit log + rotation (107 lines)
├── keychain.rs    # macOS Keychain + file cache (87 lines)
├── health.rs      # Expiry, rotation, orphan checks (64 lines)
└── env_gen.rs     # .env file generation (39 lines)

Total: 4,868 lines of Rust
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rmcp` | 1.1 | MCP server framework (stdio JSON-RPC, tool routing) |
| `axum` | 0.8 | Web framework for dashboard |
| `tower` | 0.5 | HTTP middleware |
| `ml-kem` | 0.2 | ML-KEM-768 post-quantum KEM (FIPS 203) |
| `kem` | 0.3.0-pre.0 | KEM traits (Encapsulate/Decapsulate) |
| `x25519-dalek` | 2 | X25519 Diffie-Hellman key exchange |
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption |
| `hkdf` | 0.12 | HKDF-SHA256 key derivation |
| `sha2` | 0.10 | SHA-256 hash function |
| `scrypt` | 0.11 | Memory-hard password KDF |
| `keyring` | 3 | macOS Keychain (apple-native feature) |
| `reqwest` | 0.12 | HTTP client (proxy, verification) |
| `clap` | 4 | CLI argument parsing |
| `tokio` | 1 | Async runtime (multi-thread) |
| `serde` / `serde_json` | 1.0 | JSON serialization |
| `schemars` | 1.0 | JSON Schema generation for MCP tool parameters |
| `chrono` | 0.4 | Date/time handling |
| `regex` | 1 | Provider key pattern matching |
| `url` | 2 | URL parsing and validation |
| `base64` | 0.22 | Base64 encoding for Basic auth |
| `rand` | 0.8 | Cryptographic RNG (OsRng) |
| `thiserror` | 1 | Error type derivation |
| `anyhow` | 1 | Error context propagation |
| `tracing` | 0.1 | Structured logging (stderr) |
| `dirs` | 5 | Cross-platform home directory |

---

## Security Roadmap (v3)

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
1. Master password removed from Keychain — entered via web portal (TOTP-gated), held only in daemon memory
2. usage.json + audit.log encrypted — key names no longer leak
3. Every vault_get requires a session token — tokens created only via web portal with TOTP
4. Hybrid approval model: low-risk keys auto-approve, high-risk keys require human approval
5. Token scoping: each token specifies which keys/categories it can access with TTL
6. Instant revocation from web portal
