FROM rust:1.98-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim AS runtime
ARG RELEASE_VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/lesecuritae/clawforge" \
      org.opencontainers.image.title="Clawforge Services" \
      org.opencontainers.image.description="Rust Operations Intelligence API, worker, MCP gateway, connectors, and incident services" \
      org.opencontainers.image.description.de="Selbsthostbare Operations-Intelligence-Plattform für Infrastruktur, Incidents und kontrollierte LLM-Abläufe" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/clawforge-api /usr/local/bin/clawforge-api
COPY --from=builder /src/target/release/clawforge-worker /usr/local/bin/clawforge-worker
COPY --from=builder /src/target/release/clawforge-analyzer /usr/local/bin/clawforge-analyzer
COPY --from=builder /src/target/release/clawforge-notifier /usr/local/bin/clawforge-notifier
COPY --from=builder /src/target/release/clawforge-events /usr/local/bin/clawforge-events
COPY --from=builder /src/target/release/clawforge-mcp /usr/local/bin/clawforge-mcp
COPY --from=builder /src/target/release/clawforge-correlation /usr/local/bin/clawforge-correlation
COPY --from=builder /src/target/release/clawforge-incidents /usr/local/bin/clawforge-incidents
COPY --from=builder /src/target/release/clawforge-executor /usr/local/bin/clawforge-executor
USER 10001:10001
EXPOSE 8080 8090
CMD ["/usr/local/bin/clawforge-api"]
