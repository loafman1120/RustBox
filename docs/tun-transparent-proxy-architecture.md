# RustBox TUN, Transparent Proxy, And System Routing Architecture

> **Document status:** Design recommendation
> **Last updated:** 2026-07-07
> **Scope:** TUN inbound, transparent proxy inbound, packet-to-flow stack,
> platform route control, automatic routing, and process lookup
> **Reference architecture:** `docs/architecture.md`
> **Current implementation map:** `docs/current-architecture.md`

This document designs the missing TUN, transparent proxy, system routing, and
process metadata layers without weakening the existing portability rule:

```text
portable proxy core must compile without native operating-system facilities
```

The design uses sing-box TUN inbound as a configuration and behavior reference,
but keeps RustBox's own layer model, capability ports, and configuration
pipeline.

References:

- sing-box TUN inbound: https://sing-box.sagernet.org/configuration/inbound/tun/
- sing-box redirect inbound: https://sing-box.sagernet.org/configuration/inbound/redirect/
- Linux transparent proxying: https://www.kernel.org/doc/html/latest/networking/tproxy.html
- Wintun: https://www.wintun.net/
- Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- Android `VpnService`: https://developer.android.com/reference/android/net/VpnService
- Apple `NEPacketTunnelProvider`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider

---

## 1. Current State

The repository already has the correct architectural placeholders:

| Area | Current location | Current status |
|---|---|---|
| Packet device I/O contract | `rustbox-io::PacketDevice` | Portable poll interface exists |
| Packet device provider | `rustbox-host-api::PacketDeviceProvider` | Typed contract exists with name, addresses, MTU, route mode, and DNS mode |
| Network control | `rustbox-host-api::NetworkControl` | Typed transaction contract exists; `AddRoute` is implemented through `net-route`, while address/MTU/rule/transparent operations are still planned |
| Packet-to-flow boundary | `rustbox-stack::NetworkStack` | Contract exists; planned error implementation |
| Windows platform boundary | `rustbox-platform-windows` | TUN packet device through `tun-rs` / Wintun; `AddRoute` through `net-route`; typed planned errors for WFP, address/MTU, and process lookup |
| Linux platform boundary | `rustbox-platform-linux` | TUN packet device through `tun-rs`; `AddRoute` through `net-route`; typed planned errors for route rules, tproxy/redirect, address/MTU, and process lookup |
| Metadata enrichment | `rustbox-kernel::MetadataEnricher` | Correct hook for process metadata |
| Routing | `rustbox-route` | Pure `FlowMeta -> RouteDecision` |

The missing work is therefore not a kernel rewrite. It is a controlled expansion
of L1 capability contracts, L3 inbound/stack modules, L4 composition, and
platform adapter crates.

---

## 2. Non-Goals

The design should not do these things:

- Add `cfg(target_os)` branches to `rustbox-kernel`, `rustbox-route`,
  protocol modules, or `rustbox-types` for OS behavior.
- Let TUN creation, WFP filters, nftables rules, Android `VpnService`, or Apple
  Network Extension APIs appear in portable crates.
- Treat the routing table as the owner of process lookup, DNS sniffing, or
  platform state.
- Acquire TUN devices, routes, firewall rules, or system proxy settings in
  constructors.
- Copy sing-box config verbatim when RustBox needs different names or stronger
  typed validation.

---

## 3. Target Data Paths

### 3.1 TUN Inbound

```text
platform PacketDevice
    -> rustbox-inbound-tun service
    -> rustbox-stack packet-to-flow adapter
    -> Flow(Stream or Datagram) + FlowMeta
    -> kernel enrichment
    -> route table
    -> outbound
    -> host NetworkProvider
```

TUN is an inbound service. It owns lifecycle and calls platform capabilities
during `start`, not during construction.

### 3.2 Transparent Proxy Inbound

```text
platform redirect / TPROXY / WFP / NETransparentProxyProvider
    -> rustbox-inbound-transparent service
    -> original destination lookup
    -> Flow(Stream or Datagram) + FlowMeta
    -> kernel enrichment
    -> route table
    -> outbound
```

Transparent proxy is not the same as TUN:

| Mode | Packet device needed | Packet-to-flow stack needed | Typical platform control |
|---|---:|---:|---|
| TUN | Yes | Yes | Interface, routes, DNS, leak protection |
| Linux redirect | No | No | nftables/iptables REDIRECT plus original-dst lookup |
| Linux TPROXY | No | No | transparent socket, fwmark, policy route, nftables/iptables |
| Windows WFP | Usually no | No | ALE/connect redirection or filtering |
| Apple Network Extension transparent proxy | No | No | host app extension settings |
| Android VpnService | Yes | Yes | VPN interface, routes, protected sockets |

---

## 4. Crate Layout

Recommended crate additions after the first Windows/Linux boundary step:

```text
crates/modules/inbound/rustbox-inbound-tun
crates/modules/inbound/rustbox-inbound-transparent
crates/modules/stack/rustbox-stack-smoltcp

crates/platform/rustbox-platform-apple
crates/platform/rustbox-platform-android
```

`rustbox-stack` should remain the platform-independent contract crate. A
concrete stack implementation can be introduced as `rustbox-stack-smoltcp`.

Platform crates may use target-specific dependencies behind
`[target.'cfg(...)'.dependencies]`. They should still compile as explicit
unsupported stubs on non-matching targets when included in the workspace.

---

## 5. Capability Contracts

The existing `PacketDeviceProvider` and `NetworkControl` contracts are too
coarse for real use. Extend them by adding typed data while preserving the
outer dependency direction.

### 5.1 Packet Device

Recommended host-api model:

```rust
pub struct PacketDeviceConfig {
    pub name: Option<String>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    pub route_mode: RouteMode,
    pub dns_mode: TunDnsMode,
}

pub struct PacketDeviceInfo {
    pub name: String,
    pub index: Option<u32>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
}

pub struct PacketDeviceLease {
    pub device: Box<dyn PacketDevice>,
    pub info: PacketDeviceInfo,
}
```

`PacketDevice` remains pure packet I/O. Interface addresses, MTU, route
insertion, DNS settings, and proxy settings are `NetworkControl` work.

### 5.2 Network Control

Replace the current text-only transaction with typed, reversible operations:

```rust
pub struct NetworkTransaction {
    pub reason: NetworkControlReason,
    pub operations: Vec<NetworkOperation>,
    pub rollback_policy: RollbackPolicy,
}

pub enum NetworkOperation {
    AddInterfaceAddress { interface: InterfaceRef, address: IpCidr },
    SetInterfaceMtu { interface: InterfaceRef, mtu: u16 },
    AddRoute { destination: IpCidr, gateway: Option<IpAddress>, interface: InterfaceRef, metric: Option<u32> },
    AddRouteRule { selector: RouteSelector, table: RouteTableId, priority: Option<u32> },
    AddDnsServer { interface: InterfaceRef, server: IpAddress },
    AddTransparentRedirectRule(TransparentRedirectRule),
    AddLeakProtectionRule(LeakProtectionRule),
    SetPlatformHttpProxy(PlatformProxyConfig),
    ProtectSocket { handle: SocketProtectionHandle },
}
```

`NetworkControl::apply` should return a `NetworkLease` that can be explicitly
reverted during service stop. The lease should be idempotent: double stop must
not leave routes or firewall rules behind.

### 5.3 Process Lookup

Add a capability separate from routing:

```rust
pub trait ProcessLookup: Send + Sync {
    fn lookup(&self, key: ConnectionKey) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>>;
}

pub struct ConnectionKey {
    pub network: Network,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub direction: FlowDirection,
}

pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub package_name: Option<String>,
    pub user_id: Option<u32>,
}
```

`ProcessLookup` should be used by a `MetadataEnricher`. The router sees only
enriched `FlowMeta` fields. Process metadata is best effort and cacheable; route
validation must not require it to be available on every platform.

### 5.4 Egress Protection

Automatic routing creates a loop risk: RustBox outbounds can be captured by
RustBox's own TUN or transparent proxy rules.

Add egress hints to network requests:

```rust
pub struct TcpConnect {
    pub target: Endpoint,
    pub egress: Option<EgressPolicy>,
}

pub enum EgressPolicy {
    Default,
    BypassRustBoxCapture,
    Interface(InterfaceRef),
}
```

Platform implementations map this to Android `VpnService.protect`, Windows WFP
conditions, Linux fwmarks/routing rules, or interface binding where available.

---

## 6. TUN Inbound Configuration

Recommended TOML shape:

```toml
[[inbounds]]
id = "tun"
type = "tun"
interface_name = "rustbox0"
addresses = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"]
mtu = 9000
stack = "smoltcp"
auto_route = true
strict_route = true
route_includes = ["0.0.0.0/0", "::/0"]
route_excludes = ["127.0.0.0/8", "::1/128"]
dns_hijack = ["any:53"]
platform_http_proxy = false
auto_redirect = false
```

Suggested source model:

```rust
pub enum InboundConfig {
    Tun(TunInboundConfig),
    Transparent(TransparentInboundConfig),
    // existing variants
}

pub struct TunInboundConfig {
    pub id: String,
    pub interface_name: Option<String>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    pub stack: TunStackKind,
    pub auto_route: bool,
    pub strict_route: bool,
    pub route_includes: Vec<IpCidr>,
    pub route_excludes: Vec<IpCidr>,
    pub dns_hijack: Vec<DnsHijackTarget>,
    pub platform_http_proxy: bool,
    pub auto_redirect: bool,
}
```

Validation rules:

- `type = "tun"` requires `PacketDevice`, `NetworkControl`, and `TaskSpawner`.
- `addresses` must contain at least one IPv4 or IPv6 CIDR.
- `mtu` must fit platform limits and be greater than the minimum IPv4/IPv6 MTU.
- `auto_redirect = true` is Linux-only and requires `auto_route = true`.
- `strict_route = true` requires platform leak protection support.
- `platform_http_proxy = true` is valid only when the selected platform declares
  that capability.
- Route include/exclude CIDRs must not overlap in a way that makes the result
  empty unless an explicit empty-capture mode is allowed.

---

## 7. Transparent Inbound Configuration

Recommended TOML shape:

```toml
[[inbounds]]
id = "transparent"
type = "transparent"
listen = "127.0.0.1:12345"
network = "tcp-udp"
mode = "redirect"
auto_rules = true
mark = 2022
```

Suggested source model:

```rust
pub struct TransparentInboundConfig {
    pub id: String,
    pub listen: Endpoint,
    pub network: TransparentNetwork,
    pub mode: TransparentMode,
    pub auto_rules: bool,
    pub mark: Option<u32>,
}

pub enum TransparentMode {
    Redirect,
    Tproxy,
    WfpRedirect,
    NetworkExtension,
}
```

Validation rules:

- `redirect` is Linux/BSD/macOS-style NAT redirect where original destination
  can be recovered from the accepted socket.
- `tproxy` is Linux-only and requires transparent sockets, fwmark, policy route,
  and nftables/iptables rules.
- `wfp-redirect` is Windows-only and requires a WFP backend.
- `network-extension` is Apple-only and generally host-app managed.
- `auto_rules = true` requires `NetworkControl`; `false` allows an operator to
  provide external firewall/routing rules.

---

## 8. Packet-To-Flow Stack

`rustbox-stack-smoltcp` should be the first portable stack adapter:

```text
PacketDevice read loop
    -> parse IP packet
    -> feed smoltcp interface
    -> accepted TCP socket becomes FlowPayload::Stream
    -> UDP endpoint map becomes FlowPayload::Datagram
    -> outbound responses are written back as IP packets
```

Implementation notes:

- Keep TCP state, retransmission, and window handling inside the stack adapter.
- Keep DNS hijack as a route/hijack service above the stack, not as ad hoc UDP
  packet parsing in `rustbox-kernel`.
- Use a bounded session table keyed by 5-tuple.
- Emit observability events for packet-device open, stack attach, sessions
  created, sessions expired, and packet drops.
- Provide a fake packet device test harness before real OS integration.

Crate options discovered with `cargo search`:

| Crate | Search result | Recommended role |
|---|---|---|
| `smoltcp` | `0.13.1`, TCP/IP stack | Preferred low-level userspace stack building block |
| `netstack-smoltcp` | `0.2.3`, TUN packets to TCP streams/UDP packets | Evaluate as a higher-level adapter; do not couple kernel APIs to it |
| `ipstack` | `1.0.0`, async lightweight TUN stack | Evaluate only after checking API maturity and maintenance |
| `tun2proxy` | `0.8.2`, tunnel interface to proxy | Reference implementation only; RustBox should keep its own Flow boundary |
| `etherparse` | `0.20.3`, packet parser/writer | Useful for lightweight IP/TCP/UDP parsing tests |
| `pnet_packet` | `0.35.0`, packet parsing/manipulation | Alternative packet parser if its API fits better |

---

## 9. Platform Adapters

### 9.1 Windows

Recommended crate: keep `rustbox-platform-windows` and replace planned errors
incrementally.

Responsibilities:

- Packet device: Wintun through `tun-rs` or a direct Wintun adapter.
- Route control: Windows IP Helper APIs or a route crate if it preserves full
  control and rollback semantics.
- Transparent proxy/leak protection/process lookup: WFP ALE layers through a
  reviewed WFP binding or direct `windows-sys` / `windows` calls.
- Process metadata: owner PID from IP Helper tables or WFP metadata, then image
  path through process APIs.

Crate candidates:

| Crate | Search result | Position |
|---|---|---|
| `tun-rs` | `2.8.6`, cross-platform TUN/TAP | Preferred first TUN adapter candidate |
| `wfp` | `0.0.7`, Windows Filtering Platform API | Candidate for WFP after API review |
| `windows-wfp` | `0.2.1`, WFP wrapper | Review license and API before use |
| `netstat2` | `0.11.2`, cross-platform socket info | Candidate for best-effort process lookup |
| `sysinfo` | `0.39.5`, process info | Candidate to turn PID into process metadata |

### 9.2 Linux

Recommended new crate: `rustbox-platform-linux`.

Responsibilities:

- Packet device: `tun-rs` or `tokio-tun`.
- Routes and rules: `rtnetlink`, `netlink-packet-route`, or a higher-level
  route crate that supports rollback.
- TPROXY/redirect: nftables first; iptables compatibility only as an adapter.
- Process lookup: sock diag / procfs / netstat-style lookup with caching.
- Egress protection: fwmark and policy routing for RustBox-owned sockets.

Crate candidates:

| Crate | Search result | Position |
|---|---|---|
| `tun-rs` | `2.8.6`, cross-platform TUN/TAP | Preferred first TUN adapter candidate |
| `tokio-tun` | `0.15.2`, async TUN/TAP for Tokio | Linux-focused alternative |
| `rtnetlink` | `0.21.0`, manipulate Linux networking resources | Preferred for route/link/address control |
| `netlink-packet-route` | `0.31.0`, route netlink packet types | Lower-level support crate |
| `net-route` | `0.4.6`, cross-platform route table manipulation | Evaluate for simple route operations |
| `nftables` | `0.6.3`, nftables JSON API | Preferred first auto-rule adapter |
| `nfq` / `nfqueue` | `0.2.5` / `0.9.1`, NFQUEUE | Optional for advanced interception, not TUN MVP |
| `procfs` | `0.18.0`, Linux procfs | Useful for process metadata fallback |
| `netstat2` | `0.11.2`, socket info | Useful for cross-platform process lookup |

### 9.3 Apple Platforms

Recommended crate split:

```text
rustbox-platform-apple        pure Rust adapter surface
host app / Swift wrapper      Network Extension ownership
```

Responsibilities:

- macOS CLI/dev mode may use utun through a cross-platform TUN crate.
- Production packet tunnel mode should be host-app managed with
  `NEPacketTunnelProvider`.
- Transparent proxy mode should be represented as a host-supplied capability
  rather than a portable Rust implementation.
- System DNS/route/proxy settings are Network Extension settings owned by the
  app extension host.
- Process lookup is entitlement constrained and should be best effort.

RustBox should accept borrowed packet-device handles from FFI/mobile hosts so
the Apple extension can own entitlement-sensitive setup.

### 9.4 Android

Recommended crate split:

```text
rustbox-platform-android      Rust adapter and JNI bridge
Kotlin/Java host              VpnService lifecycle and permissions
```

Responsibilities:

- The host app owns `VpnService.Builder`, user consent, package allow/deny
  lists, routes, DNS, and MTU.
- RustBox receives a packet-device fd through FFI/JNI and adapts it to
  `PacketDevice`.
- `NetworkProvider` must support `protect` semantics so outbound sockets do not
  loop into the VPN.
- Process/package metadata should prefer Android package/user information from
  `VpnService` configuration and platform APIs.

Android support should not require the portable core to depend on JNI.

---

## 10. Automatic Routing Plan

Automatic routing should be compiled into an explicit `NetworkTransaction`.

```text
ValidatedConfig
    -> CompiledTunInbound
    -> NetworkPlan
    -> NetworkControl.apply(plan)
    -> NetworkLease
```

The planner must:

1. Discover or receive the default outbound interface before installing routes.
2. Exclude loopback, link-local, multicast, RustBox listen addresses, and
   configured upstream proxy endpoints by default.
3. Add route includes and excludes in deterministic priority order.
4. Add DNS hijack or DNS route rules only when explicitly configured.
5. Apply egress protection for RustBox-owned sockets.
6. Revert every operation through `NetworkLease` during service stop.

Strict route mode should mean:

```text
captured route includes are enforced and known leak paths are blocked
```

It should not silently promise total leak prevention on platforms that cannot
enforce it. Validation should downgrade or reject based on platform capability
policy selected by the application.

---

## 11. Composition

Composition should become platform-aware without making the core platform-aware:

```rust
pub struct PlatformCapabilities {
    pub packet_devices: Option<Arc<dyn PacketDeviceProvider>>,
    pub network_control: Option<Arc<dyn NetworkControl>>,
    pub process_lookup: Option<Arc<dyn ProcessLookup>>,
}
```

`TokioComposition` can grow into:

```rust
pub struct RuntimeComposition {
    pub runtime: Arc<dyn RuntimeCapabilities>,
    pub platform: PlatformCapabilities,
    pub observability: Arc<dyn ObservabilitySink>,
}
```

When a compiled inbound requires unsupported capabilities, composition should
fail before starting any service.

---

## 12. Testing Strategy

Required tests before real OS rollout:

| Layer | Test type |
|---|---|
| `rustbox-types` | CIDR parsing, route include/exclude normalization |
| `rustbox-config` | TUN and transparent config validation/compilation |
| `rustbox-host-api` | network transaction rollback model unit tests |
| `rustbox-stack` | fake packet device TCP/UDP packet-to-flow tests |
| `rustbox-inbound-tun` | service lifecycle with fake packet provider/control |
| `rustbox-inbound-transparent` | original-destination injection with fake platform |
| Platform crates | target-specific integration tests requiring privileges |
| App | unsupported capability diagnostics are clear and early |

OS integration tests should be opt-in and ignored by default:

```text
cargo test -p rustbox-platform-linux -- --ignored
cargo test -p rustbox-platform-windows -- --ignored
```

---

## 13. Implementation Order

Recommended order:

1. Expand portable types: `IpCidr`, `InterfaceRef`, `ProcessInfo`,
   `ConnectionKey`, and route include/exclude models.
2. Expand `rustbox-host-api` with typed `PacketDeviceConfig`,
   `NetworkTransaction`, `NetworkLease`, `ProcessLookup`, and egress policy.
3. Add config variants for `tun` and `transparent`, with validation but planned
   composition errors.
4. Add `rustbox-inbound-tun` service with fake providers and no real OS code.
5. Implement `rustbox-stack-smoltcp` behind the existing `NetworkStack`
   boundary.
6. Add Linux TUN MVP: packet device and basic route additions first, then
   address/MTU/rule leases through rtnetlink/nftables.
7. Add Windows Wintun MVP: packet device and basic route additions first, then
   address/MTU and WFP-backed adapters.
8. Add Linux redirect/TPROXY transparent inbound.
9. Add process lookup enrichers per platform.
10. Add Android and Apple borrowed-device/host-extension bridges.
11. Add strict-route leak protection and platform HTTP proxy support.

This order keeps every platform-specific step behind already-tested portable
contracts.

---

## 14. Open Decisions

These should be decided before implementation:

- Whether the first stack adapter should wrap `smoltcp` directly or evaluate
  `netstack-smoltcp` first.
- Whether `tun-rs` is sufficient for all desktop TUN needs or Windows should
  use a direct Wintun wrapper for finer control.
- Whether route control should use higher-level crates such as `net-route` or
  direct platform APIs for full rollback and strict-route behavior.
- How much process metadata should be stored in `FlowMeta` versus a separate
  metadata bag once route rules become richer.
- Whether transparent proxy should start Linux-only and expose unsupported
  diagnostics on other platforms, or start as a host-supplied capability for all
  platforms.

---

## 15. Invariants

The following invariants must hold throughout the implementation:

1. `rustbox-kernel` never imports platform crates, TUN crates, WFP crates,
   netlink crates, JNI, or Network Extension bindings.
2. `rustbox-route` stays pure and performs no process lookup, DNS lookup, or
   network control.
3. `rustbox-stack` owns packet-to-flow translation; kernel receives only
   `FlowPayload::Stream` or `FlowPayload::Datagram`.
4. Platform support is declared through capability matrices and validated during
   composition.
5. Network control changes are applied only during explicit lifecycle start and
   reverted during stop.
6. Unsupported platform features return structured capability diagnostics, not
   hidden fallback behavior.
