# @pdaxt/pqvault-mcp

Post-quantum secrets management for AI agents via MCP.

## Install

```bash
npx @pdaxt/pqvault-mcp
```

## What is this?

This is an npm wrapper for [PQVault](https://github.com/pdaxt/pqvault-rs), a Rust-native secrets manager built for AI agent workflows. It provides 18 MCP tools for managing API keys with:

- **ML-KEM-768 + X25519 + AES-256-GCM** hybrid post-quantum encryption
- **Zero-knowledge API proxy** — secrets never leave the vault
- **Per-key rate limiting** and usage tracking
- **10 provider configs** with auto-detection (Anthropic, OpenAI, Stripe, etc.)

## MCP Configuration

```json
{
  "mcpServers": {
    "pqvault": {
      "command": "npx",
      "args": ["@pdaxt/pqvault-mcp"]
    }
  }
}
```

## Build from source

For best performance, build the Rust binary directly:

```bash
git clone https://github.com/pdaxt/pqvault-rs
cd pqvault-rs
cargo build --release
```

## License

MIT — Built by [Pranjal Gupta](https://github.com/pdaxt) at [DataXLR8](https://dataxlr8.ai)
