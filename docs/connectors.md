# Connector Framework

Clawforge v0.8 führt ein modulares, read-only Connector-Registry ein. Jeder
Connector beschreibt Typ, Version, Zustand, Health und eine explizite Liste
seiner Fähigkeiten. Connector-Metadaten enthalten keine Zugangsdaten.

## Registrierte Connectoren

- **Docker Connector**: Container auflisten, Status, Health, Image-Version und
  Restart Count lesen.
- **GitHub Connector**: Repository-Status, letzte Commits, Security Alerts
  (falls verfügbar) und Workflow-Status lesen.
- **Proxmox Connector Foundation**: Interface, Secret-Referenz und Health-Check
  für eine spätere Integration; noch keine vollständige Infrastrukturabfrage.

Alle Fähigkeiten sind read-only. Es gibt keine Restart-, Schreib-, Policy- oder
Workflow-Aktion.

## Sicherheit

Connector-Zugriffe werden als Audit-Ereignis erfasst und benötigen den Scope
`agent:connector:read`. Credentials werden ausschließlich über Secret-Dateien
injiziert; weder API, MCP noch die Datenbank speichern Token im Klartext.
MCP verwendet ausschließlich die Agent API v1 und greift nicht direkt auf die
Datenbank oder externe Connector-Endpunkte zu.

## API und MCP

Die versionierten Routen sind `GET /api/v1/connectors`,
`/api/v1/connectors/{id}`, `/health` und `/capabilities`. Die MCP-Adaptertools
heißen `list_connectors`, `get_connector_status` und
`get_connector_capabilities`.
