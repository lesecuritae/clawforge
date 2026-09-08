FROM rust:1.98-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/lesecuritae/clawforge" \
      org.opencontainers.image.title="Clawforge Security Platform" \
      org.opencontainers.image.description="Rust security intelligence API, worker, MCP gateway, notifier, and optional incident analyzer"
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/clawforge-api /usr/local/bin/clawforge-api
COPY --from=builder /src/target/release/clawforge-worker /usr/local/bin/clawforge-worker
COPY --from=builder /src/target/release/clawforge-analyzer /usr/local/bin/clawforge-analyzer
COPY --from=builder /src/target/release/clawforge-notifier /usr/local/bin/clawforge-notifier
COPY --from=builder /src/target/release/clawforge-events /usr/local/bin/clawforge-events
COPY --from=builder /src/target/release/clawforge-mcp /usr/local/bin/clawforge-mcp
USER 10001:10001
EXPOSE 8080 8090
CMD ["/usr/local/bin/clawforge-api"]
