# AnyTLS support contract

> Last verified: 2026-07-10

RustBox's `anytls` outbound uses the exact-pinned `anytls 0.2.3` crate. This
version retains the canonical AnyTLS v2 stream lifecycle and exposes a
`DialOutFunc`, allowing RustBox to keep socket creation behind its existing
`NetworkProvider` boundary instead of implementing the protocol or bypassing
the host network abstraction.

The supported TCP interoperability peer is sing-box 1.13.14. The CI test uses
sing-box as a real AnyTLS server and sends three sequential requests through
the full application chain.

## Supported behavior

| Capability | Status | Verification |
|---|---|---|
| TLS and password authentication | Supported | Module tests and sing-box E2E |
| Canonical `Settings`, `SYN`, `PSH`, `FIN` frames | Supported by dependency | sing-box E2E |
| Session stream-ID progression and reuse | Supported by dependency | Three sequential sing-box E2E requests |
| `SYNACK` and server error handling | Supported by dependency | AnyTLS v2 implementation and sing-box E2E |
| TCP proxy stream | Supported | Module round trip and sing-box E2E |
| UDP-over-TCP v2 | Supported | Module UOT round-trip test |
| TLS certificate verification, SNI, and ALPN | Supported | Rustls configuration path |
| Self-signed certificate for smoke tests | Supported with `insecure = true` | CI only |

`insecure = true` is only appropriate for controlled tests. Production
configurations should validate the server certificate and set `server_name`
when the server address is not the intended TLS name.

## RustBox configuration

```toml
[[outbounds]]
id = "anytls"
type = "anytls"
server = "proxy.example.com:443"
password = "replace-with-a-secret"

[outbounds.tls]
enabled = true
server_name = "proxy.example.com"

[[routes]]
type = "default"
outbound = "anytls"
```

The server can be any implementation that follows the canonical AnyTLS v2
wire protocol. RustBox continuously verifies sing-box; other peers should be
treated as compatible by protocol rather than as separately certified test
targets.

## Implementation choice

The selected crate version is older than the package's 0.3.x line by design:

- `anytls 0.2.3` keeps canonical stream creation, monotonically increasing
  stream IDs, session pooling, and injectable dialing. It requires only a thin
  RustBox stream/datagram adapter and passes the sing-box E2E.
- `anytls 0.3.5` removed the original stream multiplexer, fixed the data SID to
  1, and accepts `PSH` as an implicit open only in its matching server. It is
  self-compatible but cannot be used for RustBox's general AnyTLS outbound.
- `anytls-rs 0.5.4` implements the canonical stream model but its published
  dependency defaults require CMake/NASM on the current Windows baseline.
- `meow-anytls 0.16.0` is meow-rs's MIT vendored fork of that implementation.
  It fixes stream teardown and uses rustls/ring, but its high-level Client owns
  TCP/TLS dialing. Using it directly would bypass RustBox's `NetworkProvider`,
  while integrating its lower session layer would require RustBox to own more
  pooling and authentication code.

The `0.2.3` choice therefore minimizes project-owned protocol code while
preserving both canonical interoperability and RustBox's host-network boundary.

## Verification

Run module tests and the real sing-box process test:

```powershell
cargo test -p rustbox-outbound-anytls
cargo build -p rustbox-app
$env:RUSTBOX_SBOX_OUTBOUND = "anytls"
./scripts/ci/sing-box-smoke.ps1
```

The sing-box smoke chain is:

```text
curl -> RustBox HTTP inbound -> RustBox AnyTLS outbound
     -> sing-box AnyTLS inbound -> HTTP target
```

CI runs this E2E on Linux, Windows, and macOS. AnyTLS gets three sequential
requests per run so a regression that only supports the initial SID 1 cannot
pass.

## Upgrade policy

Changing the AnyTLS dependency requires all of the following in the same
change:

1. retain an injectable dial API or explicitly preserve `NetworkProvider` by
   another reviewed mechanism;
2. update the exact dependency pin and `SUPPORTED_ANYTLS_PROFILE`;
3. pass TCP and UDP-over-TCP module tests;
4. pass the three-request sing-box E2E on Linux, Windows, and macOS;
5. verify stream close/drop does not leak sessions or target connections; and
6. update this implementation comparison and the crate-evaluation record.

Do not declare an AnyTLS version usable based only on compilation or a
client/server test using the same non-canonical implementation.
