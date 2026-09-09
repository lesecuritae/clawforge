# Clawforge v1.0 Roadmap

Dieses Dokument beschreibt den inkrementellen Weg von der Operations-
Intelligence-Plattform zu v1.0. Bestehende Layer bleiben die Grundlage:
Event Backbone, Correlation, Incidents, Risk/Trust/Policy, Provider, Alerts,
Agent API v1, MCP und OpenClaw.

## Aktueller Stand

- v0.1: Rust-/PostgreSQL-Grundplattform, Docker, Basis-Events und Readiness.
- v0.2: Event Backbone, Risk/Trust/Policy, Dashboard und Security Operations.
- v0.2.x: Agent API v1, Token-/Scope-System, Audit und MCP-Adapter.
- v0.3.0: Correlation, Incident Management, Provider Intelligence, Alerts,
  Context/Decision/Operations APIs und OpenClaw-Integration.
- v0.4: Historische Operations-Snapshots, Trend Intelligence, erweiterte
  Correlation, Alert-Gruppierung und Security Posture.

## Phasen bis v1.0

1. API-v1-Vertrag stabilisieren: OpenAPI, Scopes, Fehlercodes,
   Versionierungs- und Deprecation-Regeln.
2. Agent Management: Registry, Nutzung, Ablauf, Rotation, Widerruf und Audit.
3. Historical/Change Intelligence: Snapshots, Trends und neue Risiken.
4. Correlation Intelligence: Zeitfenster, Quellen, Infrastruktur,
   Indikatoren, Ziele und Confidence-Verlauf.
5. Knowledge Layer: wiederkehrende Muster, bekannte Incidents und Lessons
   Learned.
6. Alert Intelligence: Gruppierung, Deduplizierung, Aging, Confidence und
   `/api/v1/alerts` sowie ein read-only MCP-Tool.
7. Incident Operations: Verantwortliche, Kommentare, Tags, SLA und
   Eskalationshistorie mit Audit.
8. Connector Framework, Dashboard, Reporting und Security Review.
9. Backup/Recovery und vollständige Qualitätsprüfung.
10. OpenClaw plus OpenRouter Live-Validation mit echtem MCP, Token und Modell.

Jede Phase ist erst abgeschlossen, wenn Code, Tests, Docker, Dokumentation,
Auditierbarkeit und `origin/main` konsistent sind. MCP bleibt read-only; direkte
Datenbankzugriffe, Secrets im Repository und automatische Remediation sind
ausgeschlossen. Breaking Changes erhalten eine neue API-Version.

## Nach v1.0: Operations Firewall Foundation

Die v1.0 bleibt eine Operations-Intelligence-Plattform. Eine spätere
Kontrollschicht kann zwischen LLM-Agenten, MCP/API und Infrastruktur liegen und
Kontext, Risiko, Policy, Freigaben, Audit und Ausführung gemeinsam begrenzen.
Sie ergänzt eine Governance-Firewall für Agenten und Automatisierung; sie
ersetzt keine klassische Netzwerk-Firewall. Jede Erweiterung muss die
Read-only-Grenze von MCP, Approval-Pflichten, Auditierbarkeit und
Secret-Isolation bewahren.
