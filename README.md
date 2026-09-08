<div align="center">
  <img src="assets/branding/clawforge-horizontal.svg" width="600" alt="Clawforge Security Platform">
  <h1>Clawforge Security Platform</h1>
  <p><strong>Security intelligence for observable, policy-driven protection.</strong></p>
</div>

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

Clawforge is an independent Rust security-intelligence service. It combines threat feeds, network intelligence, risk and trust scoring, PostgreSQL persistence, incidents, alerts, a read-only Agent API v1, and a Rust MCP adapter for OpenClaw. The production stack includes health/readiness checks, daily backup/restore procedures, scoped agent access, audit logging, and no provider result can block traffic directly.

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

Read the [German documentation](README.de.md) or [English documentation](README.en.md) for configuration, providers, deployment, and security details.
See [production.md](docs/production.md) and [openclaw-integration.md](docs/openclaw-integration.md) for production operation and the OpenClaw MCP contract.
