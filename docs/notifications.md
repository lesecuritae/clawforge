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
channel may select only one fixed secret ID bound to its type:
`webhook_auth`, `matrix_auth`, or `smtp_password`. These IDs map to dedicated
Docker Secret files inside the notifier. Arbitrary environment-variable names
are rejected, so a channel cannot select an unrelated process credential.

All outbound hosts must be listed exactly in the comma-separated
`CLAWFORGE_NOTIFIER_ALLOWED_HOSTS` setting. An empty list disables notification
egress. Webhook and Matrix targets must use credential-free HTTPS on port 443;
userinfo, query strings, fragments, literal IP addresses, and redirects are
rejected. Immediately before delivery, DNS is resolved, every private,
loopback, link-local, multicast, unspecified, or documentation address is
rejected, and the accepted addresses are pinned into the HTTP client. SMTP
recipients and configuration are bounded, the SMTP host uses the same exact
allowlist and DNS-address checks, and secrets are forbidden in stored config.
API creation and the notifier both enforce the policy so direct database
tampering cannot bypass the egress boundary.

Supported event types are `incident_created`,
`incident_severity_changed`, `incident_closed`, `bgp_change`, `rpki_invalid`,
`provider_error`, `backup_error`, and `system_health_error`. Rules match an
event type (or `*`) and minimum severity. They only deliver messages; they
cannot alter risk, trust, policy, or provider state.

Delivery is idempotent through a unique queue key. Failed attempts use
exponential retry backoff and become `failed` after five attempts. Every
delivery result is recorded as an audit event.

Internal service credentials are operation-bound. The API derives the fixed
`events`, `notifier`, or `analyzer` consumer from the bearer token and ignores
client-selected consumer names. A delivery result is accepted only from its
owning consumer. Backup and health producers use a separate operations token,
which cannot read or acknowledge event queues.

High and critical events also create an advisory record in `alerts`. The
authenticated Alert Explorer (`GET /admin/alerts`) exposes source, severity,
lifecycle and delivery status; Operators and Administrators may acknowledge or
resolve a record through `/admin/alerts/{id}/status`. Every status change is
written to `alert_status_history` and the audit log. Alert records never
perform a block, policy change, provider activation or trust change.
