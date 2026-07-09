# RustBox

Modular proxy engine in Rust, built on Tokio.

## Build

```powershell
cargo build --workspace
```

## Run

```powershell
# show help
cargo run -p rustbox-app

# default HTTP CONNECT proxy (127.0.0.1:18080)
cargo run -p rustbox-app -- http-proxy

# default SOCKS5 proxy (127.0.0.1:1080)
cargo run -p rustbox-app -- socks5-proxy

# from a TOML config
cargo run -p rustbox-app -- run --config examples/rustbox.toml

# validate a config without starting
cargo run -p rustbox-app -- check-config --config examples/rustbox.toml

# print platform capabilities
cargo run -p rustbox-app -- platform-capabilities
```

Stop with `Ctrl+C`.

## Logging

```powershell
$env:RUSTBOX_LOG = "debug"
cargo run -p rustbox-app -- http-proxy
```

Levels: `trace`, `debug`, `info`, `warn`, `error`, `off`.

## Control gRPC

```powershell
cargo run -p rustbox-app -- --control-grpc 127.0.0.1:19090 http-proxy
# with auth:
cargo run -p rustbox-app -- --control-grpc 0.0.0.0:19090 --control-token secret http-proxy
```

## Config

See `examples/rustbox.toml`. Inbound types: `http-connect`, `socks5`, `mixed`.
Outbound types: `direct`, `block`, `socks5`, `http`, `shadowsocks`, `anytls`.

## Verify

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com -I
curl.exe --socks5-hostname 127.0.0.1:1080 https://example.com -I
```

## Test

```powershell
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```
