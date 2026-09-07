# Clawforge Administration Layer

The administration API is a backend-only surface. It does not provide a public UI and it never performs a direct block action.

## Bootstrap and authentication

On a new database, `POST /admin/auth/bootstrap` accepts a one-time bootstrap secret and an administrator password. The bootstrap secret is read from `CLAWFORGE_ADMIN_BOOTSTRAP_TOKEN_FILE` (Docker Secret in production) and is never written to PostgreSQL. Passwords are stored as Argon2 hashes.

The response contains a short-lived session bearer token. Subsequent calls use `Authorization: Bearer <token>`. Sessions expire after twelve hours. Administrators can create API tokens with `POST /admin/auth/tokens`; only the hash, prefix, and metadata are stored, and the token is shown once. Rotation revokes the previous token before issuing a new one.

Roles are:

- **Administrator**: configuration, providers, trust registry, tokens, and all read access.
- **Operator**: provider status, manual synchronization, events, reports, and read access.
- **Viewer**: read-only provider, trust, configuration, and audit views.

## Administrative endpoints

Provider status is available at `/admin/providers`. An administrator can update an interval or enabled flag. Administrators and operators can queue a manual synchronization at `/admin/providers/{id}/sync`; the worker consumes this request and applies the existing provider-to-risk pipeline.

Trusted networks are managed at `/admin/trust-networks`. New registrations start as `Pending`. Only an administrator can move a network to `Verified` or `Revoked`. The existing trust engine remains responsible for the resulting score; technology names do not grant trust automatically.

`GET /audit/events` is protected by the same bearer authentication and supports `from`, `to`, `source`, `severity`, `user`, and `limit` filters. Authentication, configuration, provider, token, and trusted-network changes are recorded as audit events.

## Configuration and secrets

`/admin/config` stores only allow-listed non-secret JSON settings such as intervals, thresholds, and network settings. Keys containing `secret`, `password`, `token`, or `api_key` are rejected. Provider credentials remain Docker Secret files and are injected through environment variables ending in `_FILE`; they are not returned by the API or persisted in the database.

The bootstrap secret must be replaced before deployment. Revoke sessions and rotate API tokens after an operator or administrator leaves the system.
