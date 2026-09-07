<div align="center">
  <img src="assets/branding/clawforge-horizontal.svg" width="600" alt="Logo der Clawforge Security Platform">
  <h1>Clawforge Security Platform</h1>
  <p><strong>Security Intelligence für nachvollziehbaren, richtliniengesteuerten Schutz.</strong></p>
</div>

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

Clawforge ist eine eigenständige Rust-Plattform für Security Intelligence. Sie verbindet Threat-Intelligence-Feeds, Netzwerkdaten, Risiko- und Vertrauensbewertung, PostgreSQL-Persistenz und eine Policy-Grenze. Die aktuelle Version besteht aus einer Axum-API und einem Tokio-Worker. Kein einzelner Feed darf direkt eine Sperre auslösen.

## Enthalten

- Provider-Adapter für ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar und Spamhaus
- Validierung, Normalisierung, Deduplizierung und Ablaufzeiten für Indicators
- Risk Engine mit erklärbaren Bewertungen und Multi-Signal-Schutz
- PostgreSQL mit sqlx-Migrationen, Providerstatus und Risk-History
- Trusted Infrastructure als explizit registriertes Vertrauenssignal
- API-Endpunkte für Health/Readiness, Intelligence, Netzwerk, Trust und Prometheus-Metriken sowie Graceful Shutdown

## Schnellstart

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
curl http://127.0.0.1:8080/version
```

Feed-Synchronisation bleibt standardmäßig deaktiviert. Für Provider mit Authentifizierung werden private Docker-Secret-Dateien benötigt. Details stehen in [docs/configuration.md](docs/configuration.md), [docs/providers.md](docs/providers.md) und [docs/deployment.md](docs/deployment.md).

## Struktur

- `api/` — Axum REST API
- `worker/` — Tokio-Worker und Feed-Scheduler
- `intelligence/` — Provider und normalisierte Intelligence-Daten
- `risk/` — Risiko- und Trust-Bewertung
- `storage/` — PostgreSQL/sqlx-Abstraktion
- `migrations/` — sqlx-Migrationen
- `docs/` — Architektur, Betrieb und Sicherheitsmodell

Die Architektur ist in [docs/architecture.md](docs/architecture.md) beschrieben. Das Projekt steht unter der [Apache License 2.0](LICENSE).
