<div align="center">

# 🔐 PQVault

### Post-Quantum Secrets Management for AI Agents

**Your API keys deserve quantum-resistant encryption. Your AI agents deserve controlled access.**

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-f74c00?style=for-the-badge&logo=rust&logoColor=white)](https://rust-lang.org)
[![MCP](https://img.shields.io/badge/MCP-Compatible-00d084?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJMMyA3djEwbDkgNSA5LTVWN2wtOS01eiIvPjwvc3ZnPg==)](https://modelcontextprotocol.io)
[![Encryption](https://img.shields.io/badge/ML--KEM--768_%2B_X25519-AES--256--GCM-blueviolet?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/203/final)
[![Version](https://img.shields.io/badge/v2.1.0-stable-blue?style=for-the-badge)]()

<br>

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [MCP Tools](#-mcp-tools-14) · [Web Dashboard](#-web-dashboard) · [Encryption](#-encryption-deep-dive) · [Providers](#-provider-system)

<br>

```
AI Agent → MCP request → PQVault → decrypts → injects key → proxies API call → returns response
                                    ↑
                          The agent never sees the key.
```

</div>

---

## The Problem

```
~/.env                      → plaintext, no access control, no audit trail
claude.json env blocks      → keys scattered across MCP configs
shell history               → keys logged forever
1Password / Bitwarden       → designed for humans, not AI agents
HashiCorp Vault             → enterprise complexity for a dev machine
```

**AI agents need API keys.** But they don't need to _see_ them. They don't need unlimited access. And nobody's tracking which agent burned through your $200 Anthropic quota at 3am.

## The Solution

```
┌─────────────────────────────────────────────────┐
│  PQVault                                        │
│                                                 │
│  ✓ One encrypted vault for all secrets          │
│  ✓ AI agents access keys via MCP protocol       │
│  ✓ Zero-knowledge proxy — keys never leave      │
│  ✓ Per-key rate limits (RPM, daily, monthly)    │
│  ✓ Usage tracking + cost estimation per key     │
│  ✓ Audit log for every access                   │
│  ✓ Post-quantum encryption (ML-KEM-768)         │
│  ✓ Web dashboard for humans, MCP for agents     │
└─────────────────────────────────────────────────┘
```

---

## PQVault vs Everything Else

| Feature | `.env` files | 1Password | HashiCorp Vault | **PQVault** |
|---------|:-----------:|:---------:|:---------------:|:-----------:|
| AI agent access (MCP) | ❌ | ❌ | ❌ | ✅ |
| Zero-knowledge proxy | ❌ | ❌ | ❌ | ✅ |
| Post-quantum encryption | ❌ | ❌ | ❌ | ✅ |
| Per-key rate limiting | ❌ | ❌ | ✅ | ✅ |
| Usage & cost tracking | ❌ | ❌ | ❌ | ✅ |
| Auto provider detection | ❌ | ❌ | ❌ | ✅ |
| Key health monitoring | ❌ | ❌ | ✅ | ✅ |
| No infrastructure needed | ✅ | ✅ | ❌ | ✅ |
| Free & open source | ✅ | ❌ | Partial | ✅ |
| Single binary | ✅ | ❌ | ❌ | ✅ |

---

## 🚀 Quick Start

```bash
# Clone and build
git clone https://github.com/pdaxt/pqvault-rs.git
cd pqvault-rs
cargo build --release

# macOS: ad-hoc sign to avoid Gatekeeper
codesign -s - target/release/pqvault

# Initialize vault (generates PQ + classical keypairs, stores master password in Keychain)
./target/release/pqvault init

# Add your first secret
./target/release/pqvault add ANTHROPIC_API_KEY sk-ant-xxxxx

# Check vault status
./target/release/pqvault status

# Start the web dashboard
./target/release/pqvault web
# → http://localhost:9876

# Start MCP server (for AI agents)
./target/release/pqvault serve
```

### Configure MCP Client

Add to your Claude Code, Cursor, or any MCP-compatible client:

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

PQVault ships as 4 focused MCP servers for modular use:

| Server | Crate | Tools | Purpose |
|--------|-------|-------|---------|
| `pqvault serve` | `pqvault-mcp` | vault_get, vault_add, vault_list, ... | Core vault operations |
| `pqvault proxy` | `pqvault-proxy-mcp` | vault_proxy | Zero-knowledge API proxy |
| `pqvault health` | `pqvault-health-mcp` | vault_health, vault_dashboard, vault_usage | Monitoring & analytics |
| `pqvault env` | `pqvault-env-mcp` | vault_project_env, vault_write_env, vault_rotate | Environment management |

---

## 🏗 Architecture

```
 HUMAN                                    AI AGENTS
  │                                          │
  │ http://localhost:9876                     │ stdio JSON-RPC (MCP)
  ▼                                          ▼
┌──────────────────┐        ┌─────────────────────────────────────────┐
│  Web Dashboard   │        │  PQVault MCP Server (rmcp 1.1)          │
│  (Axum)          │        │                                         │
│                  │        │  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  • Browse keys   │        │  │ 14 Tools │ │ Rate     │ │ Usage   │ │
│  • Verify keys   │        │  │ (MCP)    │ │ Limiter  │ │ Tracker │ │
│  • Edit metadata │        │  └────┬─────┘ └────┬─────┘ └────┬────┘ │
│  • Search/filter │        │       └─────────────┼───────────┘      │
└────────┬─────────┘        │                     │                   │
         │                  │  ┌──────────────────▼──────────────────┐│
         │                  │  │ Vault Engine                        ││
         └──────────────────┤  │  open → decrypt → operate → encrypt ││
                            │  └──────────────────┬──────────────────┘│
                            │                     │                   │
                            │  ┌──────────────────▼──────────────────┐│
                            │  │ Hybrid Crypto Layer                 ││
                            │  │  ML-KEM-768 ⊕ X25519 → HKDF →     ││
                            │  │  AES-256-GCM                       ││
                            │  └──────────────────┬──────────────────┘│
                            └─────────────────────┼───────────────────┘
                                                  │
                         ┌────────────────────────┼──────────────────┐
                         ▼                        ▼                  ▼
                    ~/.pqvault/             macOS Keychain      ~/.pqvault/
                    vault.enc              (master password)    usage.json
                    *.bin / *.enc                               audit.log
```

### Workspace Structure

```
pqvault-rs/
├── crates/
│   ├── pqvault-core/        # Crypto, vault engine, providers, models
│   ├── pqvault-mcp/         # Core MCP server (14 tools)
│   ├── pqvault-proxy-mcp/   # Zero-knowledge API proxy
│   ├── pqvault-health-mcp/  # Health monitoring & dashboards
│   ├── pqvault-env-mcp/     # .env generation & management
│   ├── pqvault-cli/         # Terminal interface
│   └── pqvault-web/         # Web dashboard (Axum)
└── Cargo.toml               # Workspace root
```

---

## 🛡 Zero-Knowledge Proxy

The killer feature. AI agents call APIs **through** PQVault — the key never leaves the vault process.

```
 ┌─────────────────┐                  ┌─────────────────┐
 │  AI Agent        │  vault_proxy()  │  PQVault         │
 │                  │ ───────────────>│                  │
 │  "Call Stripe    │                 │  1. Decrypt key  │
 │   /v1/balance"   │                 │  2. Inject auth  │──> Stripe API
 │                  │  { response }   │  3. Make request │<── Response
 │                  │ <───────────────│  4. Return data  │
 └─────────────────┘                  └─────────────────┘
                                       Key stays here ↑
```

```
# Instead of this (key exposed to agent):
vault_get("STRIPE_SECRET_KEY")  →  agent gets key  →  agent calls Stripe

# Do this (key never exposed):
vault_proxy(key="STRIPE_SECRET_KEY", method="GET", url="/v1/balance")
  →  vault calls Stripe internally  →  returns only the response
```

**Security layers:**
- HTTPS-only enforcement
- SSRF protection (blocks localhost, metadata endpoints, IP literals)
- Domain allowlisting per provider
- Auto-detected auth injection (Bearer, Basic, header, query param)
- 1MB response limit

---

## 🧰 MCP Tools (14)

### Read Operations

| Tool | Description |
|------|-------------|
| `vault_status` | Encryption info, key count, health status, active alerts |
| `vault_get` | Retrieve a secret (rate-limited, usage-tracked, audit-logged) |
| `vault_list` | List all secrets with metadata — no values exposed |
| `vault_search` | Case-insensitive search across names, descriptions, tags |
| `vault_health` | Expired keys, rotation warnings, usage spikes, idle key alerts |
| `vault_usage` | Per-key analytics: requests, rate limit %, cost, callers |
| `vault_dashboard` | Full markdown dashboard with all keys, costs, limits |
| `vault_project_env` | Generate `.env` content for a registered project |

### Write Operations

| Tool | Description |
|------|-------------|
| `vault_add` | Add secret with auto-detected provider, category, and rate limits |
| `vault_rotate` | Rotate secret value, reset timestamp, clear alerts |
| `vault_delete` | Remove secret and clean up project references |
| `vault_import_claude` | Scan `~/.claude.json` and import API keys from MCP env blocks |

### Zero-Knowledge Operations

| Tool | Description |
|------|-------------|
| `vault_proxy` | Proxy API calls — key auto-injected, never exposed to caller |
| `vault_write_env` | Write `.env` file to disk — values never returned to caller |

---

## 🌐 Web Dashboard

Full-featured web UI at `http://localhost:9876` — embedded in the binary, zero external dependencies.

| Capability | Details |
|------------|---------|
| **Provider-grouped view** | Secrets organized by Anthropic, Stripe, Resend, GitHub, etc. |
| **One-click verification** | Hit provider APIs to check if keys are active, expired, or restricted |
| **Masked values** | Shows `sk-a...8QAA` — click to reveal |
| **Sidebar filters** | Filter by provider, status (active/error/unknown), category |
| **Full-text search** | Search across key names, accounts, descriptions, projects |
| **Metadata editing** | Set account, environment, description per key |
| **CRUD operations** | Add, rotate, delete secrets via modal dialogs |
| **Dark theme** | Purple accent, designed for developer use |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard HTML |
| `GET` | `/api/status` | Vault summary |
| `GET` | `/api/secrets` | All secrets (masked values) |
| `POST` | `/api/secrets` | Add secret |
| `DELETE` | `/api/secrets/{key}` | Delete secret |
| `PUT` | `/api/secrets/{key}/rotate` | Rotate value |
| `PUT` | `/api/secrets/{key}/meta` | Update metadata |
| `POST` | `/api/secrets/{key}/verify` | Verify against provider API |
| `GET` | `/api/health` | Health report |
| `GET` | `/api/search?q=...` | Search secrets |

---

## 🔑 Encryption Deep-Dive

### Why Hybrid Post-Quantum?

> NIST standardized ML-KEM in 2024 (FIPS 203). **Harvest-now-decrypt-later** attacks mean data encrypted today with classical-only crypto may be readable by quantum computers in 5-15 years. API keys rotate faster than that — but the vault's **master key and private keys** protect _all_ secrets. Those deserve quantum-resistant protection now.

### Encryption Flow

```
                    ┌─────────────────────┐
                    │  Plaintext secrets   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                                  ▼
   ┌─────────────────┐               ┌─────────────────┐
   │  ML-KEM-768     │               │  X25519 ECDH    │
   │  (Post-Quantum) │               │  (Classical)    │
   │                 │               │                 │
   │  pq_ss (32B)    │               │  x_ss (32B)     │
   └────────┬────────┘               └────────┬────────┘
            │                                  │
            └──────────────┬───────────────────┘
                           ▼
              ┌────────────────────────┐
              │  HKDF-SHA256           │
              │  ikm = pq_ss ‖ x_ss   │
              │  info = "pqvault-      │
              │    hybrid-dek-v1"      │
              └───────────┬────────────┘
                          ▼
              ┌────────────────────────┐
              │  AES-256-GCM           │
              │  key = derived DEK     │
              │  aad = "pqvault-v1"    │
              └───────────┬────────────┘
                          ▼
                   ┌──────────────┐
                   │  Ciphertext   │
                   └──────────────┘
```

An attacker must break **both** ML-KEM-768 (post-quantum lattice) **and** X25519 (classical ECDH) simultaneously.

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Quantum resistance | ML-KEM-768 (FIPS 203, lattice-based) |
| Classical resistance | X25519 + AES-256-GCM |
| Hybrid binding | Both shared secrets required for DEK derivation |
| Forward secrecy | Ephemeral X25519 keypair per encryption |
| Authentication | AES-GCM AEAD with associated data |
| Key-at-rest protection | scrypt (N=131072, 128MB) + AES-256-GCM |
| Master password | macOS Keychain (Secure Enclave) + file cache |

### Binary Payload Format

```
Bytes 0-3:   u32 BE — pq_ciphertext length (1088 for ML-KEM-768)
Bytes 4-7:   u32 BE — x25519_ephemeral length (32)
Bytes 8-11:  u32 BE — salt length (32)
Bytes 12-15: u32 BE — nonce length (12)
Bytes 16-19: u32 BE — ciphertext length (varies)
Byte  20+:   pq_ciphertext ‖ x25519_ephemeral ‖ salt ‖ nonce ‖ ciphertext
```

---

## 📊 Provider System

### Auto-Detection

When a key is added, PQVault detects the provider from:
1. **Key name** — word-boundary matching (`AWS_KEY` matches, `AWESOME_VAR` doesn't)
2. **Value pattern** — regex on the secret value (e.g., `^sk-ant-` → Anthropic)
3. **Longest match wins** — avoids false positives

### Built-in Providers (10)

| Provider | Detected By | Rate Limit | Cost/req | Rotation |
|----------|-------------|:----------:|:--------:|:--------:|
| **Anthropic** | `ANTHROPIC`, `^sk-ant-` | 50 RPM / 10k daily | $0.003 | 90d |
| **OpenAI** | `OPENAI`, `^sk-[a-z0-9]{20,}` | 60 RPM / 10k daily | $0.002 | 90d |
| **GitHub** | `GITHUB`, `^ghp_\|gho_` | 83 RPM / 5k daily | free | 90d |
| **Stripe** | `STRIPE`, `^sk_live_\|sk_test_` | 100 RPM / 10k daily | free | 30d |
| **Google** | `GOOGLE_API`, `^AIza` | 100 RPM / 10k daily | $0.001 | 180d |
| **Brave** | `BRAVE`, `^BSA` | 10 RPM / 2k monthly | free | 365d |
| **Resend** | `RESEND`, `^re_` | 10 RPM / 100 daily | free | 180d |
| **Cloudflare** | `CLOUDFLARE`, `CF_API` | 50 RPM / 10k daily | free | 90d |
| **ElevenLabs** | `ELEVENLABS` | 20 RPM / 500 daily | $0.005 | 180d |
| **Serper** | `SERPER` | 5 RPM / 100 monthly | free | 365d |

### Three-Tier Rate Limiting

```
Request → [Token Bucket (per-minute)] → [Daily Counter] → [Monthly Counter] → Allowed
              refills at RPM/60                resets at midnight      resets monthly
```

### Smart Alerts

| Alert | Trigger | Severity |
|-------|---------|----------|
| Unused key | No access for 30+ days | ⚠️ Warning |
| Rotation due | Key age exceeds provider recommendation | ⚠️ / 🔴 Critical |
| Usage spike | Today's requests > 3x 7-day average | ⚠️ Warning |

---

## 📁 File Layout

```
~/.pqvault/
├── vault.enc               # Encrypted vault (hybrid PQ + classical)
├── vault.meta.json         # Algorithm metadata (no secrets)
├── pq_public.bin           # ML-KEM-768 encapsulation key (1184 bytes)
├── pq_private.enc          # ML-KEM-768 decapsulation key (encrypted)
├── x25519_public.bin       # X25519 public key (32 bytes)
├── x25519_private.enc      # X25519 private key (encrypted)
├── usage.json              # Per-key usage stats, rate limits, alerts
├── .master_cache           # Cached master password (0600 permissions)
├── audit.log               # JSONL access log (rotates at 10k lines)
├── audit.log.{1,2,3}       # Rotated audit logs (max 3)
└── backups/
    └── vault.YYYY-MM-DD.enc
```

---

## CLI Reference

```bash
pqvault init                        # Initialize vault + generate keypairs
pqvault serve                       # Start MCP server (stdio JSON-RPC)
pqvault status                      # Vault health summary
pqvault list                        # List secrets (no values)
pqvault get <KEY>                   # Print secret value
pqvault add <KEY> <VALUE> [-c cat]  # Add secret with optional category
pqvault health                      # Rotation, expiry, orphan warnings
pqvault web [--port 9876]           # Start web dashboard
```

---

## 🔮 Roadmap: Daemon Mode (v3)

```
           HUMAN (Browser)
                │
         localhost:7700
         TOTP + password auth
                │
    ┌───────────┴───────────────────────────┐
    │  PQVault Daemon                       │
    │                                       │
    │  Web Portal (Axum)                    │
    │  Token Manager (SQLite)               │
    │  Approval Queue (SSE push)            │
    │  Vault Engine (existing crypto)       │
    │                                       │
    │  localhost:7700 (HTTP)                 │
    │  /tmp/pqvault.sock (Unix)             │
    └────────────┬──────────────────────────┘
                 │ Unix socket + token
        ┌────────┼────────┐
        ▼        ▼        ▼
    MCP Proxy   CLI     Other tools
```

**Planned changes:**
- Master password entered via web portal (TOTP-gated), held only in daemon memory
- Encrypted usage.json + audit.log (key names no longer leak)
- Token-scoped access per agent (which keys, TTL, auto-approve vs. human-approve)
- Instant revocation from web portal

---

## Known Limitations

<details>
<summary><b>Security</b> (click to expand)</summary>

- No authentication on web UI (localhost-only, but still unprotected)
- File cache stores master password in plaintext (0600 perms, same-user readable)
- `usage.json` and `audit.log` not encrypted (key names visible)
- No TLS on web UI (localhost HTTP only)

</details>

<details>
<summary><b>Functionality</b></summary>

- No batch key verification (sequential only)
- No push notifications on key failures
- No import from `.env` files (only `~/.claude.json`)
- Single vault, single master password (no multi-user)
- No backup management in web UI

</details>

<details>
<summary><b>Architecture</b></summary>

- Web UI HTML embedded in binary (~560 lines of inline HTML/CSS/JS)
- All state in JSON files (works for <1000 secrets)
- Full hybrid re-encrypt on every save

</details>

---

## Dependencies

Built on well-audited Rust crates:

| Category | Crates |
|----------|--------|
| **Crypto** | `ml-kem` 0.2, `x25519-dalek` 2, `aes-gcm` 0.10, `hkdf` 0.12, `scrypt` 0.11 |
| **MCP** | `rmcp` 1.1 (stdio JSON-RPC, tool routing, schemars) |
| **Web** | `axum` 0.8, `tower` 0.5, `tower-http` 0.6 |
| **HTTP** | `reqwest` 0.12 (rustls-tls, no OpenSSL) |
| **CLI** | `clap` 4 with derive macros |
| **Runtime** | `tokio` 1 (multi-threaded async) |
| **Keychain** | `keyring` 3 (apple-native) |
| **Serialization** | `serde` 1.0, `serde_json` 1.0, `schemars` 1.0 |

---

<div align="center">

Built by [Pranjal Gupta](https://github.com/pdaxt) at [DataXLR8](https://dataxlr8.ai)

Part of the DataXLR8 AI infrastructure ecosystem.

</div>
