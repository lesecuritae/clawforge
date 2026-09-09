# Sicherheitsmodell

Clawforge behandelt Provider, Events, Risk, Trust, Policy, Agenten und
Connectoren mit getrennten Grenzen. Ein Feed-Fehler, ein einzelner Indicator
oder ein einzelnes ASN/BGP/RPKI-Signal kann keine Sperre auslösen.

`/health` prüft Prozess und Runtime-Konfiguration. `/ready` prüft PostgreSQL
und den vollständigen sqlx-Migrationsstand. `/version` meldet Release und
Schema. Datenbank- und Provider-Credentials werden über Compose-Secret-Dateien
bezogen; `.env` und echte Secret-Dateien sind von Git ausgeschlossen.

Trusted Infrastructure muss vom Administrator registriert und `Verified` sein.
Tailscale, NetBird, VLAN, VPN, IP-Bereiche, ASNs und Prefixes erhalten allein
durch ihren Namen keinen Trust. Risk-Historie und Audit-Events bleiben
append-orientiert.

## API-Schutz

Rate Limits verwenden globale und Endpoint-Buckets mit gehashten Bearer-
Identitäten. Rohe Tokens und Adressen gelangen nicht in Auditdetails.
`/health` und `/ready` sind für Orchestrierung ausgenommen. Überschreitungen
antworten mit `429`, `Retry-After` und Rate-Limit-Headern und erzeugen ein
Audit-Event.

## Interne Events

Das Event Backbone akzeptiert nur strukturierte, gefilterte Payloads. Schlüssel
für Feeds, Secrets, Tokens, Passwörter und API-Keys werden vor Speicherung
entfernt. Interne Event- und Consumer-Endpunkte verlangen Service-Tokens aus
Docker Secrets; wiederholte Zustellfehler werden begrenzt und in Dead Letters
verschoben.

## Agent- und Alert-Grenzen

Agent API v1 und Rust-MCP sind read-only. Agent-Tokens besitzen explizite
Scopes; MCP greift weder auf Datenbank noch Event Backbone zu und leitet nur
bereinigte API-Antworten weiter. Credentials und Rohpayloads werden nie
zurückgegeben.

Alerts sind beratend. Sie ändern Risk, Trust oder Policy nicht und starten keine
Remediation. Incident-, Alert-, Approval- und Execution-Änderungen werden
rollenbasiert geprüft und auditiert.

## Connectoren und Secrets

Connector-Actions sind allowlisted, deaktiviert und approvalgebunden. Der
Executor ist Dry-Run und besitzt keine freie Shell-Schnittstelle. Secret
Provider speichern nur Referenzen und Health-Metadaten; Secretwerte bleiben in
Docker Secrets, externen Providern, Vaultwarden oder SOPS.

Die englische Referenz ist [security.md](security.md); der ausführliche Audit
steht in [security-audit.md](security-audit.md).
