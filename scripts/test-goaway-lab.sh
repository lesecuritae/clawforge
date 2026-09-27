#!/usr/bin/env sh
# Runs clawforge-firewall-agent's real-go-away tests (#[ignore]-gated,
# "requires a real go-away process") inside a disposable container -
# never against dev-device or any other real deployment host. Builds a
# real go-away binary from source (WeebDataHoarder/go-away, the fork
# with the SIGHUP-based live policy reload Anubis itself does not have -
# see the GoAwayAdapter module doc comment), loads an operator-owned main
# policy plus the Clawforge-owned network snippet, starts it fronting
# a trivial local backend, then runs the adapter's real apply/verify/
# rollback round trip against it with CLAWFORGE_GOAWAY_RELOAD_COMMAND set
# to a direct `kill -HUP <pid>` (no systemd in a throwaway container -
# production uses `systemctl kill --signal=HUP`, see that constant's own
# doc comment for why the whole reload command, not just a unit name, is
# configurable).
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
go_version=1.24.2
target_dir=/var/tmp/clawforge-goaway-lab-target
mkdir -p "$target_dir"

docker run --rm \
  -v "$repo_dir:/src" \
  -v "$target_dir:/src/target" \
  -w /src \
  rust:1.98-bookworm \
  sh -c '
    set -eu
    apt-get update -qq >/dev/null
    apt-get install -y -qq curl python3 >/dev/null

    curl -fsSL "https://go.dev/dl/go'"$go_version"'.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    go version

    git init -q /tmp/go-away-src
    git -C /tmp/go-away-src fetch -q --depth 1 https://github.com/WeebDataHoarder/go-away 95ac08540b8cf45a5e4e6fce0758ed52113bc893
    git -C /tmp/go-away-src checkout -q --detach FETCH_HEAD
    cd /tmp/go-away-src
    go build -o /usr/local/bin/go-away ./cmd/go-away
    cd /src

    # Trivial backend go-away fronts - just needs to answer something.
    python3 -m http.server 19000 --bind 127.0.0.1 >/tmp/backend.log 2>&1 &
    backend_pid=$!

    mkdir -p /tmp/goaway-snippets
    cp /src/tests/fixtures/goaway-main-policy.yml /tmp/goaway-main.yml
    export CLAWFORGE_GOAWAY_POLICY_FILE=/tmp/goaway-snippets/clawforge-managed.yml
    cp /src/tests/fixtures/goaway-managed-empty.yml "$CLAWFORGE_GOAWAY_POLICY_FILE"

    go-away --backend "test.local=http://127.0.0.1:19000" \
      --policy /tmp/goaway-main.yml --policy-snippets /tmp/goaway-snippets \
      --client-ip-header X-Forwarded-For --check

    go-away --bind 127.0.0.1:18090 --backend "test.local=http://127.0.0.1:19000" \
      --policy /tmp/goaway-main.yml --policy-snippets /tmp/goaway-snippets \
      --client-ip-header X-Forwarded-For >/tmp/go-away.log 2>&1 &
    goaway_pid=$!

    tries=0
    while ! curl -fsS -H "Host: test.local" -o /dev/null "http://127.0.0.1:18090/" 2>/dev/null; do
      tries=$((tries + 1))
      if [ "$tries" -gt 100 ]; then
        echo "go-away never came up:" >&2
        cat /tmp/go-away.log >&2
        exit 1
      fi
      sleep 0.1
    done
    echo "go-away up, pid=$goaway_pid"

    export CLAWFORGE_GOAWAY_RELOAD_COMMAND="kill,-HUP,$goaway_pid"

    cargo test -p clawforge-firewall-agent -- --ignored --test-threads=1 goaway_lab

    # The real point of this lab: SIGHUP must reload in place, never
    # restart - the same PID must still be alive and answering after
    # every apply/rollback the test above just did.
    if ! kill -0 "$goaway_pid" 2>/dev/null; then
      echo "go-away process (pid $goaway_pid) is gone after SIGHUP reloads - it restarted or crashed instead of reloading in place" >&2
      cat /tmp/go-away.log >&2
      exit 1
    fi
    if ! curl -fsS -H "Host: test.local" -o /dev/null "http://127.0.0.1:18090/"; then
      echo "go-away stopped answering requests after SIGHUP reloads" >&2
      cat /tmp/go-away.log >&2
      exit 1
    fi
    echo "go-away (pid $goaway_pid) survived every SIGHUP reload and is still answering - confirmed no restart"

    kill "$goaway_pid" "$backend_pid" 2>/dev/null || true
  '
