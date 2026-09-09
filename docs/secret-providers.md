# Secret Provider Layer

Clawforge v0.12 stores only secret provider metadata and references. Values
never enter PostgreSQL, API responses, MCP responses, logs, or container
images.

Supported reference types are:

- Docker Secret files under `/run/secrets`
- environment references supplied by the runtime
- Vaultwarden references (metadata only until a reviewed resolver is enabled)
- SOPS file references (metadata only; decryption stays outside the core)
- external provider references

The `secret_providers` and `secret_references` tables contain a provider type,
configuration reference, purpose, status, and bounded error metadata. They do
not contain secret values. Connector credentials continue to be injected with
Compose secrets or `_FILE` variables. Secret providers are not read through
MCP and no agent scope grants access to secret values.

The default Docker Secret provider is seeded by migration `0027_incidents.sql`.
Use a backup that excludes `/run/secrets` and any external secret store.
