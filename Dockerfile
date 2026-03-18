# PQVault Connector — Multi-stage build for Cloud Run deployment
# Serves MCP over Streamable HTTP for Claude.ai Custom Connectors

FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy workspace manifests and source
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Note: root src/ is legacy code, not part of workspace. Not copied.

# Build only the connector binary in release mode
ENV CARGO_BUILD_JOBS=4
RUN cargo build --release --package pqvault-connector

# Runtime stage — minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pqvault-connector /usr/local/bin/pqvault-connector

ENV PORT=8080
EXPOSE 8080

RUN mkdir -p /root/.pqvault

ENTRYPOINT ["pqvault-connector"]
