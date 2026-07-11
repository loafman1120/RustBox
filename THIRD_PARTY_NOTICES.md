# Third-party notices

## meow-rs protocol implementations

Parts of the proxy protocol wire implementations are adapted from
[`madeye/meow-rs`](https://github.com/madeye/meow-rs), pinned for provenance at
commit `0609fed0da813496899a85d3d52e10719552aa63`.

The copied or adapted files retain their upstream attribution. Before a public
RustBox release, verify that the upstream repository's package metadata and
license file consistently identify the promised MIT license.

Current adapted components:

- Trojan request header and SOCKS5-style destination encoding.
- Plain VLESS request/response headers and destination encoding.
- VMess AEAD header, KDF, body record crypto, and relay framing.
