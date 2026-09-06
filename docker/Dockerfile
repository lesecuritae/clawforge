FROM rust:1.98-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/clawforge-api /usr/local/bin/clawforge-api
COPY --from=builder /src/target/release/clawforge-worker /usr/local/bin/clawforge-worker
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/clawforge-api"]
