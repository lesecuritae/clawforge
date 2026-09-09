# Workflow Governance v0.7

Clawforge-Workflows sind eine kontrollierte Vorbereitungsschicht oberhalb der
Decision Engine. Sie nehmen Entscheidungen auf, erzeugen protokollierte Runs,
verwalten Approval-Zustände und bereiten definierte Schritte vor.

## Erlaubte Schritte

Workflow-Schritte sind deklarativ und dürfen nur `notification`, `analysis`,
`approval`, `external_check` oder `manual` sein. Es gibt keine Shell-
Ausführung, keine frei definierbaren Skripte und keinen direkten Zugriff auf
Systeme oder Provider.

## Zustände und Freigaben

Runs wechseln kontrolliert zwischen `pending`, `running`,
`waiting_approval`, `completed`, `failed` und `cancelled`. Schritte mit
Auswirkungen markieren `required_approval`. Der Worker bereitet dafür einen
Run und eine offene Freigabe vor, führt aber keinen Schritt aus.

Die interne Administratorroute `POST /api/v1/workflows/{id}/approve` zeichnet eine
Freigabe mit Benutzer, Zeitpunkt, Kommentar und Begründung auf. Sie setzt den
Run auf `pending`, startet ihn aber nicht. MCP und Agenten können nur
Definitionen, Runs und Auditstatus lesen.

## Beispielabläufe

- **Security Incident Workflow:** kritischer Incident → Decision → Approval →
  vorbereitete Benachrichtigung.
- **Provider Health Workflow:** Providerfehler → Qualitätskontext →
  Empfehlung → Approval.
- **Backup Monitoring Workflow:** Backupfehler → Incident-/Decision-Kontext →
  Analysevorbereitung → Approval für Benachrichtigung.

Alle Zustandsänderungen landen zusätzlich in `workflow_audit_log`. Die
Agent-API verwendet `agent:workflow:read`; `agent:workflow:approve` bleibt für
spätere, separat geschützte interne Freigabeflüsse reserviert.
