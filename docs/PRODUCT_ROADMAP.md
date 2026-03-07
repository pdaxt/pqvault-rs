# PQVault Product Roadmap

**The secrets manager built for the AI agent era.**

> Every other vault was designed for humans typing passwords into forms. PQVault is designed for a world where 50 AI agents are making 10,000 API calls per hour — and you need to know exactly which agent, which key, how much it cost, and whether that key is about to expire, get revoked, or get harvested for quantum decryption in 2035.

---

## The Problem Space

### Problems We Solve Today

1. **Secrets Sprawl** — API keys scattered across `.env` files, `~/.claude.json`, shell history, Docker configs, CI/CD secrets, Vercel dashboards, and plaintext configs. No single source of truth.

2. **Zero Visibility** — You have 92 API keys. Which ones are active? Which expired last month? Which one is burning $400/day because an agent is stuck in a retry loop? You have no idea.

3. **AI Agent Key Leakage** — AI agents need API keys to function. Every agent that sees a raw key can accidentally include it in output, logs, or generated code. `vault_proxy` solves this — agents make API calls through the vault without ever seeing the key.

4. **No Rotation Culture** — Keys get created and never rotated. The Stripe key from 2022 is still running production payments. When it gets leaked, you find out from Twitter.

5. **Quantum Harvest Risk** — Nation-state actors are harvesting encrypted data now for quantum decryption later. Your vault's master key protects all secrets — it needs to survive 20+ years. Classical-only encryption is a ticking time bomb.

6. **Keychain Prompt Storms** — 48 tmux panes × 1 MCP process each = 48 simultaneous macOS Keychain prompts. Solved with three-tier caching.

### Problems We Should Solve

7. **Key Compromise Detection** — A key gets posted on GitHub. You find out when your Stripe account is drained. There's no automated scanning.

8. **Cost Runaway** — An AI agent enters a loop calling Claude API 10,000 times. Your $500 monthly budget is gone in 20 minutes. No circuit breaker exists.

9. **Team Key Sharing** — Onboarding a developer means Slack DMs with API keys in plaintext. No secure provisioning workflow.

10. **Environment Drift** — Prod has `STRIPE_SECRET_KEY=sk_live_xxx`, dev has `sk_test_yyy`, staging has... nobody knows. Environments diverge silently.

11. **Dead Keys** — 30 of your 92 keys haven't been used in 6 months. Are they still needed? Are they for a service you shut down? Nobody audits.

12. **Compliance Theater** — SOC2 auditor asks "how do you manage secrets?" You show them a `.env` file and pray.

13. **Cross-Service Dependencies** — Rotating your Stripe key breaks 4 services. You don't know which 4 until they crash.

14. **Agent Budget Control** — You want Agent A to spend max $50/month on Claude API. Currently impossible to enforce.

15. **Secret Lifecycle** — Keys are born and never die. No deprecation workflow, no sunset warnings, no retirement process.

---

## Feature Roadmap: 100 Features

### Phase 1: Foundation Hardening (v2.1)
*Make what exists bulletproof.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 1 | **Web UI authentication** — TOTP or passkey login for web dashboard | Anyone on localhost can see all secrets | Critical |
| 2 | **`pqvault run <cmd>`** — Inject secrets as env vars, run command, wipe on exit | Developers still create .env files manually | Critical |
| 3 | **`.env` file import** — `pqvault import .env` with auto-categorization | Migration from existing workflows is manual | Critical |
| 4 | **Encrypted audit log** — Audit entries encrypted at rest, not plaintext JSONL | Audit log leaks key names and access patterns | High |
| 5 | **Encrypted usage.json** — Usage stats encrypted alongside vault | Key names visible in plaintext usage file | High |
| 6 | **`pqvault scan <dir>`** — Scan codebase for hardcoded secrets | Developers commit keys to git constantly | High |
| 7 | **Shell completions** — bash, zsh, fish auto-complete for all commands | CLI DX is bare-bones | Medium |
| 8 | **`pqvault export`** — Export to .env, JSON, YAML, Docker secrets format | Can import but can't export | Medium |
| 9 | **Separate web UI files** — Extract 560-line HTML from Rust binary to static files | Can't iterate on dashboard without recompiling | Medium |
| 10 | **File-watch vault reload** — Web server detects vault.enc changes and reloads | CLI/Web state divergence causes data loss | High |

### Phase 2: Lifecycle Management (v2.2)
*Keys are living things. Birth, health, sickness, death.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 11 | **Auto-rotation engine** — Rotate keys via provider APIs (Stripe, GitHub, Resend) | Keys never get rotated | Critical |
| 12 | **Rotation policies** — Per-key or per-category rotation schedules | No enforceable rotation cadence | Critical |
| 13 | **Pre-rotation testing** — Verify new key works before committing the swap | Bad rotation takes down production | High |
| 14 | **Rotation rollback** — Keep old key for N hours, auto-rollback if new key fails | No safety net for rotation | High |
| 15 | **Key retirement workflow** — deprecate → warn → disable → archive → delete | Keys are immortal, can never be cleaned up | High |
| 16 | **Expiry enforcement** — Auto-disable keys past their expiry date | Expired keys sit around active indefinitely | Medium |
| 17 | **Secret versioning** — Full history of every value a key has held | Can't audit what value was active at a given time | Medium |
| 18 | **Dual-write rotation** — Both old and new key work during transition period | Rotation breaks in-flight requests | Medium |
| 19 | **Rotation scheduling** — Schedule rotations during maintenance windows | Rotations happen at bad times | Low |
| 20 | **Bulk emergency rotate** — One command rotates all keys of a category/provider | Breach response requires manual key-by-key rotation | High |

### Phase 3: AI Agent Control Plane (v2.3)
*The killer feature. No other vault does this.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 21 | **Agent-scoped tokens** — Each AI agent gets a token that can only access specific keys | All agents see all keys equally | Critical |
| 22 | **Per-agent budget caps** — `agent-X can spend max $50/month on ANTHROPIC_API_KEY` | One agent can burn entire API budget | Critical |
| 23 | **Cost circuit breaker** — Auto-revoke access when spend exceeds threshold | No spending guardrails | Critical |
| 24 | **Session-based access** — Keys auto-expire when agent session ends | Keys stay accessible after agent crashes | High |
| 25 | **Usage attribution dashboard** — Which agent used which key, when, how much | Zero visibility into agent behavior | High |
| 26 | **Just-in-time decryption** — Key only decrypted at moment of use, zeroed immediately | Keys sit decrypted in memory longer than needed | High |
| 27 | **Agent sandboxing levels** — `proxy-only` (never see key) vs `read` (get value) vs `admin` (rotate/delete) | vault_proxy exists but no tiered access | Medium |
| 28 | **Multi-agent coordination** — Lock a key so only one agent uses it at a time | Two agents hit rate limit competing for same key | Medium |
| 29 | **Natural language search** — "find my stripe test key for the checkout service" | Search is keyword-only | Low |
| 30 | **Key recommendation** — Agent describes task, vault suggests which keys it needs | Agents request keys by exact name or nothing | Low |

### Phase 4: Monitoring & Intelligence (v2.4)
*Know everything. Predict problems before they happen.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 31 | **Real-time usage dashboard** — Live updating charts of API calls, costs, rate limits | Dashboard shows static data, no trends | Critical |
| 32 | **Anomaly detection** — Flag unusual access patterns (10x normal, new caller, weird hours) | Compromised key goes unnoticed | High |
| 33 | **Cost forecasting** — "At current rate, ANTHROPIC_API_KEY will cost $847 this month" | No cost visibility until bill arrives | High |
| 34 | **Provider health monitoring** — Periodic pings to check if provider APIs are up | Don't know if key failed because revoked or API is down | High |
| 35 | **Key health score** — Composite score: age, last verified, usage pattern, rotation status | Multiple health signals but no unified view | Medium |
| 36 | **Dead key detection** — "LEGACY_PAYMENT_KEY hasn't been used in 180 days" with auto-archive | Vault accumulates abandoned keys forever | Medium |
| 37 | **Duplicate key detection** — Same value stored under different names | Duplicate keys waste slots and cause confusion | Medium |
| 38 | **Alert rules engine** — Custom conditions: "alert if daily cost > $100 AND provider = anthropic" | Fixed alert conditions, no customization | Medium |
| 39 | **Weekly digest report** — Email/Slack summary: top costs, expiring keys, unused keys, anomalies | No proactive reporting | Medium |
| 40 | **Grafana/Prometheus export** — Metrics endpoint for existing monitoring infrastructure | Can't integrate with existing observability stack | Low |

### Phase 5: Team & Access Control (v2.5)
*From solo developer to team.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 41 | **Multi-user RBAC** — Admin, developer, viewer, agent roles | Single-user vault, no access control | Critical |
| 42 | **Team workspaces** — Separate vaults per team with shared keys | One vault for everything | High |
| 43 | **SSO integration** — Google, GitHub, SAML for enterprise login | Web UI has no auth at all | High |
| 44 | **Approval workflows** — Request a key → manager approves → time-limited access | Keys are self-serve, no oversight | High |
| 45 | **Break-glass access** — Emergency override with mandatory justification and audit | No emergency access with accountability | Medium |
| 46 | **Key ownership** — Every key has an owner who gets notified on issues | Nobody is responsible for any specific key | Medium |
| 47 | **Access reviews** — Quarterly recertification: "do you still need access to these 12 keys?" | Permissions accumulate, never get cleaned up | Medium |
| 48 | **Temporary access grants** — "Give dev-X access to PROD_DB_URL for 4 hours" | Access is permanent or nothing | Medium |
| 49 | **Invite links** — Secure one-time links to share specific keys with new team members | Onboarding involves Slack DMs with keys | Low |
| 50 | **Activity feed** — "Alice rotated STRIPE_KEY" / "Bob's agent exceeded budget" | No team-wide visibility into vault operations | Low |

### Phase 6: Integration Ecosystem (v2.6)
*PQVault as the hub of your infrastructure.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 51 | **GitHub Actions integration** — `pqvault-action` to inject secrets into CI/CD | CI/CD still uses GitHub Secrets (no rotation, no audit) | Critical |
| 52 | **Docker secrets bridge** — `pqvault docker-secrets` generates Docker secrets from vault | Docker workflows need separate secret management | High |
| 53 | **Kubernetes secrets sync** — Operator that syncs vault to K8s secrets with auto-rotation | K8s secrets are base64 plaintext, no rotation | High |
| 54 | **Terraform provider** — `terraform-provider-pqvault` for IaC secret references | Terraform stores secrets in state files | High |
| 55 | **VS Code extension** — Inline key status, rotation warnings, one-click rotate in editor | Developers manage keys outside their IDE | Medium |
| 56 | **AWS Secrets Manager sync** — Bi-directional sync with AWS | Some keys live in AWS, duplicated manually | Medium |
| 57 | **GCP Secret Manager sync** — Bi-directional sync with Google Cloud | Same problem with GCP | Medium |
| 58 | **1Password import/export** — Migration path from 1Password developer vaults | Can't migrate from existing tools | Medium |
| 59 | **Hashicorp Vault migration** — Import from HCV with mapping | Enterprise migration path | Low |
| 60 | **Webhook notifications** — Fire webhooks on key events (create, rotate, expire, access anomaly) | No push notifications, everything is pull | Medium |

### Phase 7: Developer Experience (v2.7)
*Make it a joy to use.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 61 | **Interactive TUI** — Full terminal UI with browsing, search, inline edit (ratatui) | CLI is command-by-command, no browse mode | High |
| 62 | **`pqvault diff`** — Compare secrets between environments (prod vs dev vs staging) | No way to see environment drift | High |
| 63 | **`pqvault sync`** — Sync secrets to/from cloud provider (Vercel, Netlify, Railway) | Manual copy-paste to deployment platforms | High |
| 64 | **Fuzzy search** — `pqvault get str` matches `STRIPE_SECRET_KEY` | Exact match only, must know full key name | Medium |
| 65 | **`pqvault edit`** — Open secret in $EDITOR with temp file, auto-save on close | Editing means delete + re-add | Medium |
| 66 | **`pqvault bulk`** — Bulk add/rotate/delete from a manifest file | One-at-a-time operations only | Medium |
| 67 | **`pqvault doctor`** — Comprehensive system check (vault integrity, Keychain, permissions) | No self-diagnosis tool | Medium |
| 68 | **`pqvault history <key>`** — Show all historical values and who changed them | No visibility into change history | Medium |
| 69 | **`pqvault tree`** — Visual tree of keys grouped by provider/category/project | `list` is flat, no hierarchy view | Low |
| 70 | **Config file support** — `~/.pqvault/config.toml` for defaults (default category, rotation policy) | All configuration is hardcoded | Low |

### Phase 8: Security Hardening (v2.8)
*Enterprise-grade security features.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 71 | **GitHub/GitLab secret scanning** — Monitor public repos for leaked keys from your vault | Key leaks detected by Twitter, not by tooling | Critical |
| 72 | **Breach database cross-reference** — Check if any vault keys appear in known breaches | Compromised keys sit active in vault | High |
| 73 | **Entropy analysis** — Flag weak keys (low entropy, common patterns, test keys in prod) | Weak keys accepted without warning | High |
| 74 | **Shamir's secret sharing** — Split master password into N shares, require M to reconstruct | Single master password is a single point of failure | High |
| 75 | **HSM integration** — Store master key in hardware security module (YubiKey, TPM) | Master key cached in plaintext file | Medium |
| 76 | **Tamper-evident audit log** — Cryptographic hash chain (each entry signs the previous) | Audit log can be modified without detection | Medium |
| 77 | **IP allowlisting per key** — "PROD_DB_URL can only be accessed from 10.0.0.0/8" | No network-level access control per key | Medium |
| 78 | **Time-based access** — Keys only accessible during business hours (per timezone) | No temporal access control | Low |
| 79 | **Canary keys** — Honeypot keys that trigger alerts if accessed | No intrusion detection for vault compromise | Low |
| 80 | **Memory zeroization** — Explicitly zero secret values in memory after use | Secrets may linger in memory after use | Medium |

### Phase 9: Web Dashboard v2 (v2.9)
*From functional to beautiful.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 81 | **Dark/light theme toggle** — User preference for dashboard theme | Only dark theme available | Medium |
| 82 | **Key detail page** — Click a key → full page with history, usage graph, related keys, audit trail | Everything crammed into table rows | High |
| 83 | **Bulk operations** — Select multiple keys, batch rotate/delete/re-categorize | One-at-a-time operations only | High |
| 84 | **Usage graphs** — Per-key sparklines showing usage trend, cost trend | No visual trends, just numbers | High |
| 85 | **Real-time WebSocket updates** — Dashboard auto-updates when vault changes | Must refresh to see changes | Medium |
| 86 | **API playground** — Test a key inline: pick endpoint, see response, verify it works | Must use curl to test keys | Medium |
| 87 | **Keyboard shortcuts** — `j/k` navigate, `/` search, `r` rotate, `d` delete | Mouse-only interaction | Low |
| 88 | **Export dashboard as PDF** — Compliance-ready report of all secrets with status | Can't generate reports for auditors | Medium |
| 89 | **Mobile responsive** — Dashboard works on phone (for emergency key checks) | Dashboard only works on desktop | Low |
| 90 | **Drag-and-drop organization** — Drag keys between categories/groups | Must edit category field manually | Low |

### Phase 10: Advanced & Differentiators (v3.0)
*Features no other vault has.*

| # | Feature | Problem Solved | Priority |
|---|---------|---------------|----------|
| 91 | **Dependency graph** — Visual map: which services use which keys, what breaks if rotated | Rotation impact is unknown until things break | High |
| 92 | **Impact analysis** — "If I revoke STRIPE_KEY, these 4 services will fail" | No blast radius estimation | High |
| 93 | **Secret templates** — "Create a new Stripe integration" auto-creates pk_*, sk_*, whsec_* | Must know what keys each service needs | Medium |
| 94 | **Cross-vault sync** — Sync specific keys between personal and team vaults | Multiple vaults are isolated silos | Medium |
| 95 | **Compliance reports** — Auto-generate SOC2/ISO27001 evidence packages | Manual compliance documentation | Medium |
| 96 | **GitOps for secrets** — Declare desired state in YAML, vault converges to match | Imperative-only management | Medium |
| 97 | **Secret inheritance** — Base key + environment overrides (like CSS cascading) | Copy-paste same key across environments | Low |
| 98 | **Provider marketplace** — Community-contributed provider configs (verify endpoints, rate limits) | 10 hardcoded providers, adding more requires code changes | Low |
| 99 | **Vault-to-vault migration** — Encrypted transfer between PQVault instances | Can't move secrets between machines securely | Low |
| 100 | **Self-destructing secrets** — Key auto-deletes after N accesses or time period | Temporary keys persist forever | Low |

---

## Competitive Positioning

### What Exists Today

| Tool | Designed For | AI-Native? | Post-Quantum? | Agent Budget Control? | Proxy Mode? |
|------|-------------|-----------|--------------|----------------------|------------|
| **HashiCorp Vault** | Enterprise infra | No | No | No | No |
| **AWS Secrets Manager** | AWS ecosystem | No | No | No | No |
| **1Password** | Humans | No | No | No | No |
| **Doppler** | Teams | No | No | No | No |
| **Infisical** | Open-source teams | No | No | No | No |
| **sops** | GitOps | No | No | No | No |
| **PQVault** | **AI agents + developers** | **Yes** | **Yes** | **Yes (planned)** | **Yes** |

### PQVault's Moat

1. **AI-agent-first** — `vault_proxy` is the only zero-knowledge API proxy in any secrets manager. Agents never see keys.
2. **Post-quantum** — Only secrets manager using NIST-standardized ML-KEM-768. Future-proof by design.
3. **MCP-native** — First-class integration with Claude Code and the MCP ecosystem.
4. **Per-key economics** — Rate limiting, cost tracking, budget enforcement per key per agent. Nobody else does this.
5. **Single binary** — No Docker, no database, no cloud dependency. One Rust binary. Works offline.

---

## Use Cases

### Use Case 1: Solo AI Developer
*"I have 50+ API keys across 10 services. I run Claude Code in 48 tmux panes."*

**Today:** Keys in `.env` files. Every Claude instance can see every key. No rate limiting. $800 Claude bill last month — no idea which pane caused it.

**With PQVault:** One encrypted vault. Each pane gets keys through MCP with rate limiting. Usage dashboard shows pane-3 made 8,000 Claude API calls (stuck in a retry loop). Cost tracking shows exact spend per key per agent.

### Use Case 2: AI Startup Team
*"5 engineers, 20 microservices, 3 environments. Keys everywhere."*

**Today:** Shared 1Password vault. Copy-paste to .env files. New hire takes 2 days to get all keys. Keys in Slack DMs. Nobody knows which keys are for what.

**With PQVault:** Team vault with RBAC. New hire gets scoped access via invite link. `pqvault run` injects secrets — no .env files. `pqvault diff prod dev` shows environment drift. Rotation policies auto-rotate Stripe keys every 30 days.

### Use Case 3: Compliance-Sensitive Company
*"SOC2 auditor is coming. We need to prove key management practices."*

**Today:** Scramble to document manual processes. Screenshots of cloud dashboards. "We rotate keys... sometimes."

**With PQVault:** Tamper-evident audit log shows every access. Rotation policies enforced automatically. Compliance report generated as PDF. Key health scores show no expired or unrotated keys. Auditor satisfied in 15 minutes.

### Use Case 4: AI Agent Orchestration Platform
*"We run 100+ AI agents that each need different API access."*

**Today:** All agents share one API key. Can't attribute costs. Can't limit spending. One rogue agent can drain the entire budget.

**With PQVault:** Agent-scoped tokens: Agent-A gets Claude + Stripe, Agent-B gets only Brave Search. Budget caps: Agent-A max $100/month on Claude. Circuit breaker: auto-revoke if spend rate exceeds 3x average. Usage attribution: know exactly which agent made every call.

### Use Case 5: Open Source Project Maintainer
*"Contributors need test API keys. Can't give them production keys."*

**Today:** Test keys in repository secrets. No rotation. Contributors ask for keys on Discord.

**With PQVault:** Environment-scoped access: contributors get `test` environment only. Self-destructing tokens: access expires after PR is merged. `vault_proxy`: contributors test against real APIs without seeing keys.

### Use Case 6: Security-Conscious Developer
*"I want my secrets to survive the quantum computing era."*

**Today:** GPG-encrypted .env files. Classical crypto only. If keys are harvested now and quantum computers arrive in 10 years, everything is exposed.

**With PQVault:** Hybrid ML-KEM-768 + X25519 encryption. Attacker must break both post-quantum AND classical crypto. NIST FIPS 203 standardized. Future-proof by design.

### Use Case 7: Incident Response
*"Our Stripe key just leaked on GitHub. What do we do?"*

**Today:** Panic. Manually check which services use that key. Log into Stripe dashboard. Rotate manually. Hope nothing breaks. Update .env files everywhere.

**With PQVault:** Dependency graph shows exactly which 4 services use STRIPE_KEY. Emergency rotate: one command generates new key via Stripe API, dual-write for 30 minutes, then cut over. Automatic rollback if any service fails health check. Incident report auto-generated from audit log.

### Use Case 8: Multi-Cloud Operations
*"We have keys in AWS, GCP, Vercel, Netlify, Railway. Syncing is a nightmare."*

**Today:** Keys duplicated manually across platforms. Environment drift. Rotating a key means updating 5 dashboards.

**With PQVault:** `pqvault sync vercel` pushes secrets to Vercel. `pqvault sync gcp` pushes to Google Secret Manager. One rotation propagates everywhere. Drift detection alerts when a platform has a stale value.

---

## Revenue Model (Future)

### Open Source Core (Free Forever)
- Single-user vault
- CLI + MCP server
- Local web dashboard
- 10 providers
- All encryption features

### PQVault Pro ($19/month)
- Team workspaces (up to 5 users)
- Auto-rotation for all providers
- Usage analytics + cost forecasting
- GitHub/GitLab secret scanning
- Priority support

### PQVault Enterprise ($99/month per team)
- Unlimited users + RBAC + SSO
- Approval workflows
- Compliance reports (SOC2, ISO27001)
- Breach database monitoring
- SLA + dedicated support
- HSM integration
- Audit log tamper evidence

### PQVault Cloud (Future)
- Hosted vault with E2E encryption
- Cross-team secret sharing
- Global CDN for vault_proxy (low-latency API calls worldwide)
- Managed key rotation with rollback

---

## Technical Architecture Evolution

### v2 (Current) — Single Binary
```
pqvault binary
├── CLI commands
├── MCP server (stdio)
├── Web dashboard (embedded HTML)
└── Encrypted file store (~/.pqvault/)
```

### v3 (Target) — Daemon Architecture
```
pqvault-daemon (always running)
├── gRPC API (local socket)
├── Web dashboard (separate process)
├── File watcher (vault.enc changes)
├── Background jobs
│   ├── Auto-rotation scheduler
│   ├── Health check pinger
│   ├── Cost tracker
│   └── Alert evaluator
└── Encrypted file store

pqvault CLI → gRPC → daemon
pqvault MCP → gRPC → daemon
pqvault web → gRPC → daemon
```

**Why daemon:** Eliminates CLI/Web state divergence. Single process owns vault file. Background jobs run without CLI or web being active. Multiple clients (CLI, MCP, web) all go through one process.

### v4 (Future) — Optional Cloud Sync
```
pqvault-daemon (local, always runs)
├── Local encrypted store (primary)
├── Optional cloud sync (E2E encrypted)
│   ├── Team vault sharing
│   ├── Cross-device sync
│   └── Hosted backup
└── Offline-first (cloud optional)
```

---

## Implementation Priority Matrix

### Must Have (v2.1-2.2)
These are the features that turn PQVault from "cool tool" into "I can't live without this":

1. `pqvault run <cmd>` — THE developer workflow feature
2. Web UI authentication — Can't call it a vault without auth
3. `.env` import — Migration path
4. File-watch reload — Fix the state divergence bug
5. Auto-rotation — The #1 reason people want a vault
6. Secret scanning — Prevent the problem, not just manage it
7. Encrypted audit + usage — Security gaps that undermine trust

### Should Have (v2.3-2.5)
Features that make PQVault compelling for teams:

8. Agent-scoped tokens — THE differentiator
9. Per-agent budgets — AI economics control
10. RBAC — Team readiness
11. Usage graphs in dashboard — Visual is everything
12. Dependency graph — Know blast radius before you rotate

### Nice to Have (v2.6+)
Features that make PQVault best-in-class:

13. GitHub Actions integration
14. Terraform provider
15. Interactive TUI
16. Compliance reports
17. Self-destructing secrets

---

## Success Metrics

| Metric | Current | v2.5 Target | v3.0 Target |
|--------|---------|------------|------------|
| Secrets managed | 92 | 500+ | 2,000+ |
| Providers supported | 10 | 25 | 50+ |
| MCP tools | 14 | 25 | 40+ |
| CLI commands | 9 | 20 | 30+ |
| Active users | 1 | 10 | 100+ |
| Test coverage | 147 tests | 500+ | 1,000+ |
| GitHub stars | 0 | 100 | 1,000 |

---

*Last updated: 2026-03-07*
*Author: PQVault Team*
