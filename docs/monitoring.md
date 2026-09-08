# Monitoring

`GET /metrics` exposes Prometheus text format. It includes provider sync and
error counters, per-provider sync status, indicator and risk-event totals,
active incidents, open alerts, BGP changes, database availability, and a
worker heartbeat gauge. The worker
updates its PostgreSQL heartbeat on every scheduler tick; PostgreSQL remains
the source of truth.

The API process also exposes `clawforge_api_requests_total`,
`clawforge_api_errors_total`, and `clawforge_api_rate_limited_total`.

Use `/health` for process/configuration checks, `/ready` for PostgreSQL and
migration readiness, and `/version` for the running release and schema status.
Alert when `clawforge_worker_up` or `clawforge_database_up` is zero, provider
status is zero, provider errors increase unexpectedly, or
`clawforge_alerts_open` grows without operator acknowledgement. MCP exposes
separate request/error/auth-failure counters at its internal `/metrics`
endpoint.

## Observability Stack

Prometheus und Grafana sind als optionales Compose-Profil enthalten. Beide
Dienste verwenden nur das interne Backend-Netzwerk; ihre Host-Ports sind
standardmäßig an Loopback gebunden.

```sh
docker compose --profile observability up -d prometheus grafana
```

Das vorinstallierte Dashboard **Clawforge Overview** zeigt API-, MCP-,
Datenbank-, Incident-, Alert-, Correlation-, Provider- und Agent-Metriken.
Prometheus ist unter `http://127.0.0.1:${CLAWFORGE_PROMETHEUS_PORT:-9090}` und
Grafana unter `http://127.0.0.1:${CLAWFORGE_GRAFANA_PORT:-3001}` erreichbar.
Die optionale Profil-Installation wird nicht benötigt, damit die Kernplattform
startet.

Zusätzliche Metriken umfassen Antwortzeiten, Authentifizierungsfehler,
MCP-Tool-Aufrufe, Tool-Fehler, aktive Streamable-HTTP-Sessions,
Correlation-Beziehungen, durchschnittliche Provider-Qualität und Agent-API-
Zugriffe. Ein Session-Wert beschreibt die aktuell aktiven MCP-HTTP-Anfragen.
