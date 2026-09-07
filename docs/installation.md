# Installation

Clawforge requires Docker Compose v2 and a Docker Engine with named-volume and
secret support. PostgreSQL is the production database; the API and worker images
run as UID/GID `10001`; the Nginx frontend runs as UID/GID `101`.

1. Copy `.env.example` to `.env`.
2. Copy each `secrets/*.example` file to a private file, then put real database
   and provider credentials in those files. Never commit the private files.
3. Start the stack with `docker compose up -d --build`.
4. Wait for `curl --fail http://127.0.0.1:8080/ready` and inspect `/version`.

Feed and network jobs are disabled by default. Enable them deliberately in
`.env`; a feed is always passed through the risk and policy boundaries.
