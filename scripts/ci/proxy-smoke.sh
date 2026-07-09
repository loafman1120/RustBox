#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_PATH="${RUSTBOX_BIN:-$ROOT_DIR/target/debug/rustbox-app}"
WORK_DIR="${RUSTBOX_CI_WORK_DIR:-$ROOT_DIR/target/ci-proxy-smoke}"

HTTP_PROXY_PORT="${RUSTBOX_HTTP_PROXY_PORT:-18080}"
SOCKS_PROXY_PORT="${RUSTBOX_SOCKS_PROXY_PORT:-1080}"
MIXED_PROXY_PORT="${RUSTBOX_MIXED_PROXY_PORT:-2080}"
HTTP_TARGET_PORT="${RUSTBOX_HTTP_TARGET_PORT:-19080}"
HTTPS_TARGET_PORT="${RUSTBOX_HTTPS_TARGET_PORT:-19443}"

MARKER="rustbox-ci-proxy-smoke-ok"
RUSTBOX_PID=""
HTTP_PID=""
HTTPS_PID=""
CURL_LOG_INDEX=0

log() {
  printf '[rustbox-ci] %s\n' "$*"
}

dump_logs() {
  if [[ -d "$WORK_DIR/logs" ]]; then
    for log_file in "$WORK_DIR"/logs/*.log; do
      [[ -f "$log_file" ]] || continue
      printf '\n===== %s =====\n' "$log_file"
      cat "$log_file" || true
    done
  fi
}

cleanup() {
  local status=$?
  set +e
  for pid in "$RUSTBOX_PID" "$HTTP_PID" "$HTTPS_PID"; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
    fi
  done
  wait "$RUSTBOX_PID" "$HTTP_PID" "$HTTPS_PID" 2>/dev/null
  if [[ "$status" -ne 0 || "${RUSTBOX_CI_DUMP_LOGS:-0}" == "1" ]]; then
    dump_logs
  fi
  exit "$status"
}
trap cleanup EXIT

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local label="$3"
  python3 - "$host" "$port" "$label" <<'PY'
import socket
import sys
import time

host, port, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
deadline = time.time() + 20
last_error = None
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=1):
            print(f"[rustbox-ci] {label} is listening on {host}:{port}")
            raise SystemExit(0)
    except OSError as exc:
        last_error = exc
        time.sleep(0.2)
print(f"[rustbox-ci] timed out waiting for {label} on {host}:{port}: {last_error}", file=sys.stderr)
raise SystemExit(1)
PY
}

assert_curl_body() {
  local label="$1"
  shift
  local body
  local safe_label
  local curl_log
  local header_log
  local body_file

  CURL_LOG_INDEX=$((CURL_LOG_INDEX + 1))
  safe_label="${label//[^A-Za-z0-9._-]/_}"
  curl_log="$WORK_DIR/logs/curl-${CURL_LOG_INDEX}-${safe_label}.log"
  header_log="$WORK_DIR/logs/curl-${CURL_LOG_INDEX}-${safe_label}.headers.log"
  body_file="$WORK_DIR/logs/curl-${CURL_LOG_INDEX}-${safe_label}.body.log"

  log "curl check: $label"
  curl --fail --silent --show-error --verbose \
    --max-time 15 --retry 2 --retry-delay 1 --noproxy "" \
    --dump-header "$header_log" \
    --output "$body_file" \
    "$@" 2>"$curl_log"
  body="$(cat "$body_file")"
  if [[ "$body" != *"$MARKER"* ]]; then
    printf '[rustbox-ci] unexpected response for %s\n' "$label" >&2
    printf '%s\n' "$body" >&2
    return 1
  fi
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[rustbox-ci] required tool not found: %s\n' "$tool" >&2
    return 1
  fi
}

start_http_target() {
  python3 -m http.server "$HTTP_TARGET_PORT" \
    --bind 127.0.0.1 \
    --directory "$WORK_DIR/www" \
    >"$WORK_DIR/logs/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp 127.0.0.1 "$HTTP_TARGET_PORT" "http target"
}

start_https_target() {
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/tls/key.pem" \
    -out "$WORK_DIR/tls/cert.pem" \
    -days 1 \
    -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    >"$WORK_DIR/logs/openssl.log" 2>&1

  python3 - "$WORK_DIR/www" "$HTTPS_TARGET_PORT" "$WORK_DIR/tls/cert.pem" "$WORK_DIR/tls/key.pem" \
    >"$WORK_DIR/logs/https-target.log" 2>&1 <<'PY' &
import functools
import http.server
import ssl
import sys

directory, port, cert_file, key_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_file, key_file)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
  HTTPS_PID=$!
  wait_for_tcp 127.0.0.1 "$HTTPS_TARGET_PORT" "https target"
}

start_rustbox() {
  cat >"$WORK_DIR/rustbox-ci.toml" <<EOF
schema_version = 1

[observability]
level = "debug"
file = "$WORK_DIR/logs/rustbox-events.log"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:$HTTP_PROXY_PORT"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:$SOCKS_PROXY_PORT"

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:$MIXED_PROXY_PORT"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
EOF

  "$BIN_PATH" run --config "$WORK_DIR/rustbox-ci.toml" \
    >"$WORK_DIR/logs/rustbox-stdout.log" 2>"$WORK_DIR/logs/rustbox-stderr.log" &
  RUSTBOX_PID=$!

  wait_for_tcp 127.0.0.1 "$HTTP_PROXY_PORT" "http inbound"
  wait_for_tcp 127.0.0.1 "$SOCKS_PROXY_PORT" "socks5 inbound"
  wait_for_tcp 127.0.0.1 "$MIXED_PROXY_PORT" "mixed inbound"
}

verify_observability() {
  local events="$WORK_DIR/logs/rustbox-events.log"
  log "checking RustBox observability log"
  grep -q "connection_accepted" "$events"
  grep -q "route_selected" "$events"
  grep -q "outbound_connected outbound=1" "$events"
  grep -q "traffic_recorded" "$events"
}

main() {
  require_tool curl
  require_tool openssl
  require_tool python3

  if [[ ! -x "$BIN_PATH" ]]; then
    printf '[rustbox-ci] RustBox binary is missing or not executable: %s\n' "$BIN_PATH" >&2
    printf '[rustbox-ci] run: cargo build -p rustbox-app\n' >&2
    return 1
  fi

  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR/www" "$WORK_DIR/tls" "$WORK_DIR/logs"
  printf '%s\n' "$MARKER" >"$WORK_DIR/www/rustbox-ci.txt"

  start_http_target
  start_https_target
  start_rustbox

  assert_curl_body \
    "http inbound -> direct outbound -> local HTTP target" \
    --proxy "http://127.0.0.1:$HTTP_PROXY_PORT" \
    "http://127.0.0.1:$HTTP_TARGET_PORT/rustbox-ci.txt"

  assert_curl_body \
    "http CONNECT inbound -> direct outbound -> local HTTPS target" \
    --insecure \
    --proxy "http://127.0.0.1:$HTTP_PROXY_PORT" \
    "https://127.0.0.1:$HTTPS_TARGET_PORT/rustbox-ci.txt"

  assert_curl_body \
    "socks5 inbound -> direct outbound -> local HTTPS target" \
    --insecure \
    --socks5-hostname "127.0.0.1:$SOCKS_PROXY_PORT" \
    "https://127.0.0.1:$HTTPS_TARGET_PORT/rustbox-ci.txt"

  assert_curl_body \
    "mixed inbound as HTTP proxy -> direct outbound -> local HTTP target" \
    --proxy "http://127.0.0.1:$MIXED_PROXY_PORT" \
    "http://127.0.0.1:$HTTP_TARGET_PORT/rustbox-ci.txt"

  assert_curl_body \
    "mixed inbound as SOCKS5 proxy -> direct outbound -> local HTTPS target" \
    --insecure \
    --socks5-hostname "127.0.0.1:$MIXED_PROXY_PORT" \
    "https://127.0.0.1:$HTTPS_TARGET_PORT/rustbox-ci.txt"

  if [[ "${RUSTBOX_CI_EXTERNAL:-0}" == "1" ]]; then
    log "optional external egress check is enabled"
    curl --fail --silent --show-error --verbose \
      --max-time 20 --retry 2 --retry-delay 1 --noproxy "" \
      --dump-header "$WORK_DIR/logs/curl-external-egress.headers.log" \
      --proxy "http://127.0.0.1:$HTTP_PROXY_PORT" \
      --head "https://example.com/" \
      >"$WORK_DIR/logs/curl-external-egress.body.log" \
      2>"$WORK_DIR/logs/curl-external-egress.log"
  else
    log "optional external egress check is disabled; set RUSTBOX_CI_EXTERNAL=1 to enable it"
  fi

  verify_observability
  log "proxy smoke test passed"
}

main "$@"
