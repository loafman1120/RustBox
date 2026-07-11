# Third-party notices

## meow-rs protocol implementations

Parts of the proxy protocol wire implementations are adapted from
[`madeye/meow-rs`](https://github.com/madeye/meow-rs), pinned for provenance at
commit `0609fed0da813496899a85d3d52e10719552aa63`, whose root license is MIT
(Copyright 2023 KT).

The copied or adapted files retain their upstream attribution. The TUN work was
reviewed alongside that project, but no Meow-rs TUN source was copied because
the pinned revision does not contain a desktop TUN listener.

Current adapted components:

- Trojan request header and SOCKS5-style destination encoding.
- Plain VLESS request/response headers and destination encoding.
- VMess AEAD header, KDF, body record crypto, and relay framing.

## anytls-rs

RustBox vendors the full library implementation of `ssrlive/anytls-rs` version
`0.2.3`, including its protocol core, client, server-session runtime, and UOT
support. The vendored package is built as the workspace crate `rustbox-anytls`
and remains available under the upstream MIT license.
