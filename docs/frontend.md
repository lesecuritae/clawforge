# Clawforge Console

The React and TypeScript console is a presentation layer for the Clawforge API. It does not implement risk scoring, trust decisions, provider control logic, or database access.

Development:

    cd frontend
    npm install
    npm run dev

The Vite development proxy forwards the /api path to http://localhost:8080. The production container uses Nginx to serve the static bundle and proxy /api to clawforge-api.

The console provides Overview, Incident Center, Threat Intelligence, Network Intelligence, Trust Management, Administration, and Audit views. It stores only the short-lived API session token in browser session storage. Provider secrets and database credentials never enter the frontend bundle.

Build:

    npm run build

The Compose service is clawforge-frontend and listens on CLAWFORGE_FRONTEND_PORT (default 3000).

## Frontend hardening

The console keeps its bearer token in `sessionStorage` only; it never writes tokens to `localStorage`, logs, or API data. Every JSON and text API request emits a shared unauthorized event on HTTP 401. The application clears the session and returns to the login view when that event is received. `prepareTokenRefresh()` is the single boundary for a future refresh endpoint and currently returns no token because the API does not expose refresh tokens.

The overview is read-only and reads system, readiness, worker, provider, incident, risk, and latest audit data from the API. Indicators, incidents, audit events, and provider records have search, filters, sorting, and API pagination. Incident status changes use the existing permission-checked API endpoint; a denied operation is shown as an API error. Network pages only display ASN, BGP, prefix, and RPKI fields returned by the API and do not calculate scores in the browser.

The production build disables source maps. Nginx sends a restrictive content security policy and browser security headers. The image runs as an unprivileged user with a read-only filesystem and temporary paths mounted by Compose.
