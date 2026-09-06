<div align="center">
  <img src="assets/branding/clawforge-horizontal.svg" width="600" alt="Clawforge Security Platform">
  <h1>Clawforge Security Platform</h1>
  <p><strong>Security intelligence for observable, policy-driven protection.</strong></p>
</div>

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

Clawforge is an independent Rust security-intelligence service. It combines threat feeds, network intelligence, risk and trust scoring, PostgreSQL persistence, and a policy boundary. The current implementation is a backend foundation with an Axum API and Tokio worker; no provider result can block traffic directly.

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

Read the [German documentation](README.de.md) or [English documentation](README.en.md) for configuration, providers, deployment, and security details.
