# VMess, VLESS, Trojan, and AnyTLS Crate Evaluation

> **Status:** AnyTLS decision implemented; other protocols remain investigation-only
> **Checked:** 2026-07-09 on Windows MSVC with `rustc 1.95.0`
> **Policy:** VMess, VLESS, and Trojan remain configuration-only in RustBox.
> AnyTLS is implemented through the selected `anytls` crate.

## 1. What “usable” means here

A crate name or a successful docs.rs build is not enough. A candidate must:

1. be a published Rust library rather than only an executable;
2. expose a client-side stream/session API that can be adapted to
   `rustbox-io` without starting a second local proxy;
3. compile on RustBox's current toolchain and target;
4. have a license suitable for RustBox's `MIT OR Apache-2.0` distribution; and
5. pass a future interoperability test against an independent implementation.

The checks below establish publication, public API, local compilation, and
license. They do **not** establish wire interoperability or production
readiness, so no candidate is added to `Cargo.toml` by this investigation.

## 2. Results

| Protocol | Candidate | Verified facts | RustBox decision |
|---|---|---|---|
| VMess | [`meow-proxy` 0.16.0](https://docs.rs/meow-proxy/0.16.0/meow_proxy/) | Published library; public `VmessAdapter`; the `vmess,vless,trojan,anytls` feature build passed locally. License is GPL-3.0 and its adapters use the meow runtime abstractions. | Technically real, but not suitable as a direct dependency under the current license and architecture. |
| VMess | [`shoes` 0.2.2](https://crates.io/crates/shoes/0.2.2) | MIT implementation with VMess AEAD support, but the published package declares only a binary target. The upstream project documents broad protocol support. | Useful reference implementation, not an embeddable crate API. |
| VMess | [`tobira` 0.4.0](https://docs.rs/tobira/0.4.0/tobira/) | Published library and VMess relay, licensed AGPL-3.0-or-later. | Reference only; license is not suitable for direct inclusion. |
| VLESS | [`meow-proxy` 0.16.0](https://docs.rs/meow-proxy/0.16.0/meow_proxy/) | Published library; public `VlessAdapter` and Vision mode; local feature build passed. GPL-3.0 and coupled to meow abstractions. | Technically real, but rejected as a direct dependency. |
| VLESS | [`shoes` 0.2.2](https://github.com/cfal/shoes) | Upstream documents VLESS, Vision, and Reality support under MIT; crates.io package is binary-only. | Reference/interoperability peer only. |
| Trojan | [`trojan-proto` 0.10.1](https://docs.rs/trojan-proto/0.10.1/trojan_proto/) | Published codec library; local library build passed. It provides request and UDP parsing/serialization, not a RustBox-ready outbound. GPL-3.0-only. | Real codec, but incomplete for the outbound and would require changing RustBox's distribution policy. |
| Trojan | [`trojan_rust` 0.1.0](https://docs.rs/trojan_rust/0.1.0/trojan_rust/) | MIT library; local library build passed. Its public API starts a local SOCKS5 proxy while the Trojan connector modules are private. | Builds, but cannot be cleanly adapted to `Outbound::open_stream`; do not adopt as-is. |
| AnyTLS | [`anytls` 0.3.5](https://docs.rs/anytls/0.3.5/anytls/) | MIT published library. Its client feature exposes dial-out injection and public session/stream APIs; `cargo check --no-default-features --features client` passed locally. | Adopted by `rustbox-outbound-anytls` for TCP and UDP-over-TCP. Local TLS/authentication/target/relay tests cover both paths. |
| AnyTLS | [`anytls-rs` 0.5.4](https://docs.rs/anytls-rs/0.5.4/anytls_rs/) | MIT published library with client/session APIs. Its local Windows library build failed in `aws-lc-sys` because CMake/NASM was unavailable. | Not accepted for RustBox's current Windows build baseline. Re-evaluate only with an explicit native-toolchain policy. |

`meow-proxy` is the only checked published library that covers all four
protocols behind feature flags, but its GPL-3.0 license is a blocking issue for
the current project. `shoes` is a credible MIT implementation and a valuable
interoperability peer, but its crates.io artifact is an application, not a
library target.

## 3. Reproducible compile probes

The following package manifests were downloaded by `cargo info` and checked
without adding them to this workspace:

```text
cargo check meow-proxy 0.16.0 --lib --no-default-features \
  --features vmess,vless,trojan,anytls                         PASS
cargo check anytls 0.3.5 --lib --no-default-features \
  --features client                                            PASS
cargo check trojan-proto 0.10.1 --lib                          PASS
cargo check trojan_rust 0.1.0 --lib                            PASS
cargo check anytls-rs 0.5.4 --lib                              FAIL
  aws-lc-sys: missing CMake/NASM on the current Windows host
cargo check shoes 0.2.2 --bin shoes                            FAIL
  aws-lc-sys: missing CMake/NASM on the current Windows host
```

The PASS results only prove that the selected published source resolves and
type-checks on the stated toolchain. The failures are environment-specific but
material because RustBox currently builds on that environment without those
native prerequisites.

## 4. Adoption gates

Before changing any protocol from configuration-only to implemented:

1. add a dedicated outbound crate beneath `crates/modules/outbound`;
2. keep TLS and socket creation behind RustBox host/transport boundaries;
3. test TCP byte relay through the RustBox kernel;
4. test authentication failure and malformed peer behavior;
5. run an interoperability matrix against an independent implementation such
   as [sing-box](https://sing-box.sagernet.org/configuration/outbound/) or
   `shoes`;
6. verify UDP behavior separately where the protocol supports it; and
7. repeat license and supply-chain review for the exact pinned version.

VMess, VLESS, and Trojan still must not compose until these gates pass. AnyTLS
now composes because it has a dedicated outbound, configuration validation, and
local end-to-end data-plane tests. An independent sing-box interoperability job
remains desirable before declaring the adapter production-hardened.
