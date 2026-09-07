#!/usr/bin/env bash
set -euo pipefail

# Live smoke checks for the phase-one endpoints. This script enables feed mode
# only for the bounded validation process; it never starts the scheduler or
# writes indicators. Authenticated providers are skipped when their key is not
# present in the environment. Fixture coverage is provided by the Rust unit
# tests run by the release-validation script.

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

check_json() {
  local name="$1" url="$2"; shift 2
  local body="$work_dir/${name}.json"
  if ! curl --fail --silent --show-error --location --max-time 30 --retry 1 "$@" -o "$body" "$url"; then
    echo "$name: FAIL (download)" >&2
    return 1
  fi
  if [ ! -s "$body" ] || ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$body"; then
    echo "$name: FAIL (empty or invalid JSON)" >&2
    return 1
  fi
  echo "$name: OK ($(wc -c < "$body") bytes)"
}

check_text() {
  local name="$1" url="$2"; shift 2
  local body="$work_dir/${name}.txt"
  if ! curl --fail --silent --show-error --location --max-time 30 --retry 1 "$@" -o "$body" "$url"; then
    echo "$name: FAIL (download)" >&2
    return 1
  fi
  [ -s "$body" ] || { echo "$name: FAIL (empty response)" >&2; return 1; }
  echo "$name: OK ($(wc -c < "$body") bytes)"
}

check_prefix_text() {
  local name="$1" url="$2"; shift 2
  local body="$work_dir/${name}.txt"
  if ! curl --fail --silent --show-error --location --max-time 30 --retry 1 "$@" -o "$body" "$url"; then
    echo "$name: FAIL (download)" >&2
    return 1
  fi
  if ! grep -Eq '(^|[[:space:]])([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}([[:space:];]|$)|(^|[[:space:]])[0-9A-Fa-f:]+/[0-9]{1,3}([[:space:];]|$)' "$body"
  then
    echo "$name: FAIL (no network prefixes)" >&2
    return 1
  fi
  echo "$name: OK ($(wc -c < "$body") bytes)"
}

check_prefix_or_merged_text() {
  local name="$1" url="$2"; shift 2
  local body="$work_dir/${name}.txt"
  if ! curl --fail --silent --show-error --location --max-time 30 --retry 1 "$@" -o "$body" "$url"; then
    echo "$name: FAIL (download)" >&2
    return 1
  fi
  if ! grep -Eq '(^|[[:space:]])([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}([[:space:];]|$)|(^|[[:space:]])[0-9A-Fa-f:]+/[0-9]{1,3}([[:space:];]|$)' "$body" \
    && ! grep -Eiq 'merged into' "$body"; then
    echo "$name: FAIL (no network prefixes or merge notice)" >&2
    return 1
  fi
  echo "$name: OK ($(wc -c < "$body") bytes)"
}

check_asn_json_lines() {
  local name="$1" url="$2"; shift 2
  local body="$work_dir/${name}.jsonl"
  if ! curl --fail --silent --show-error --location --max-time 30 --retry 1 "$@" -o "$body" "$url"; then
    echo "$name: FAIL (download)" >&2
    return 1
  fi
  if ! grep -Eq '"asn"[[:space:]]*:[[:space:]]*[0-9]+' "$body"; then
    echo "$name: FAIL (no ASN records)" >&2
    return 1
  fi
  echo "$name: OK ($(wc -c < "$body") bytes)"
}

export CLAWFORGE_ENABLE_FEEDS=true
check_json "feodo" "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
check_prefix_text "spamhaus-drop" "https://www.spamhaus.org/drop/drop.txt"
check_prefix_or_merged_text "spamhaus-edrop" "https://www.spamhaus.org/drop/edrop.txt"
check_asn_json_lines "spamhaus-asn" "https://www.spamhaus.org/drop/asndrop.json"

for provider in threatfox urlhaus malwarebazaar; do
  variable="${provider^^}_AUTH_KEY"
  case "$provider" in
    threatfox) url="https://threatfox-api.abuse.ch/api/v1/"; body='{"query":"get_ioc","days":1}' ;;
    urlhaus) url="https://urlhaus-api.abuse.ch/v1/urls/recent/"; body='' ;;
    malwarebazaar) url="https://mb-api.abuse.ch/api/v1/"; body='{"query":"get_recent","selector":"time"}' ;;
  esac
  if [ -z "${!variable:-}" ]; then
    echo "$provider: SKIP ($variable is not configured)"
    continue
  fi
  if [ -n "$body" ]; then
    check_json "$provider" "$url" -H "Auth-Key: ${!variable}" -H 'Content-Type: application/json' --data "$body"
  else
    check_json "$provider" "$url" -H "Auth-Key: ${!variable}"
  fi
done
