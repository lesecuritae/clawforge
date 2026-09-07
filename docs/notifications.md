# Notification layer

The optional `clawforge-notifier` container delivers selected incident and
operational events through webhook, SMTP, or Matrix webhook channels. It has
no access to PostgreSQL and communicates with the API only over the internal
backend network. PostgreSQL remains the source of truth for the queue.

Administrators create channels and rules through the authenticated API:

* `GET/POST /admin/notifications/channels`
* `POST /admin/notifications/channels/{id}/status`
* `GET/POST /admin/notifications/rules`
* `POST /admin/notifications/rules/{id}/status`

Channel targets and non-secret configuration are stored in PostgreSQL. A
channel may contain `secret_ref`, which is only an environment variable name;
the token or password is resolved by the notifier from Docker Secrets or
environment injection and is never written to the database, logs, or payload.
Webhook targets must therefore be secret-free URLs; put authentication in the
referenced secret instead of a query parameter.

Supported event types are `incident_created`,
`incident_severity_changed`, `incident_closed`, `bgp_change`, `rpki_invalid`,
`provider_error`, `backup_error`, and `system_health_error`. Rules match an
event type (or `*`) and minimum severity. They only deliver messages; they
cannot alter risk, trust, policy, or provider state.

Delivery is idempotent through a unique queue key. Failed attempts use
exponential retry backoff and become `failed` after five attempts. Every
delivery result is recorded as an audit event.
