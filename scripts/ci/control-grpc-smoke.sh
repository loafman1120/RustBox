#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log() {
  printf '[rustbox-ci] %s\n' "$*"
}

main() {
  cd "$ROOT_DIR"
  local cargo_bin="${CARGO:-cargo}"
  if ! command -v "$cargo_bin" >/dev/null 2>&1; then
    if [[ "$cargo_bin" == "cargo" ]] && command -v cargo.exe >/dev/null 2>&1; then
      cargo_bin="cargo.exe"
    elif [[ -n "${USERPROFILE:-}" && -x "$USERPROFILE/.cargo/bin/cargo.exe" ]]; then
      cargo_bin="$USERPROFILE/.cargo/bin/cargo.exe"
    else
      printf '[rustbox-ci] required tool not found: cargo\n' >&2
      return 1
    fi
  fi

  log "running native gRPC control API smoke test"
  "$cargo_bin" test --locked -p rustbox-control-api --test control_grpc_smoke -- --nocapture
}

main "$@"
