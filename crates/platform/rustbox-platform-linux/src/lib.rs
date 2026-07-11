//! Linux 平台能力适配边界。
//!
//! 本 crate 只承载 Linux TUN、route control、redirect/TPROXY 和进程查询的
//! 平台边界。当前只接入 `tun-rs` packet device；netlink、nftables 和进程
//! 查询会继续隔离在这里，portable kernel 和协议模块不直接看到 OS 细节。

#[cfg(target_os = "linux")]
use net_route::{Handle as RouteHandle, Route};
#[cfg(target_os = "linux")]
use rustbox_host_api::{AcceptedTransparentStream, TransparentRedirectMode};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, NetworkControl, NetworkControlError, NetworkLease,
    NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceLease,
    PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError, TransparentProxyError,
    TransparentProxyProvider, TransparentStreamListener, TransparentTcpBind,
};
#[cfg(target_os = "linux")]
use rustbox_host_api::{InterfaceRef, NetworkOperation, PacketDeviceInfo, RollbackPolicy};
#[cfg(target_os = "linux")]
use rustbox_io::PacketDevice;
#[cfg(target_os = "linux")]
use rustbox_io::{IoError, IoErrorKind};
#[cfg(target_os = "linux")]
use rustbox_types::IpAddress;
#[cfg(target_os = "linux")]
use rustbox_types::{Endpoint, Host};
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::pin::Pin;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::task::{Context, Poll};
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

/// Linux 平台能力集合。
///
/// 当前实现先提供 typed capability 边界和明确诊断；真实实现应在后续小步中把
/// `tun-rs`/`rtnetlink`/`nftables` 等依赖限制在本 crate 内。
#[derive(Clone, Debug, Default)]
pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn capability_matrix(&self) -> LinuxCapabilityMatrix {
        linux_capability_matrix()
    }
}

impl PacketDeviceProvider for LinuxPlatform {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>> {
        Box::pin(async move { open_linux_packet_device(config) })
    }
}

impl NetworkControl for LinuxPlatform {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(apply_linux_network_transaction(transaction))
    }

    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
        Box::pin(release_linux_network_lease(lease))
    }
}

impl ProcessLookup for LinuxPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>> {
        Box::pin(async move { lookup_linux_process(key) })
    }
}

impl TransparentProxyProvider for LinuxPlatform {
    fn bind_tcp(
        &self,
        request: TransparentTcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn TransparentStreamListener>, TransparentProxyError>> {
        Box::pin(bind_linux_transparent_tcp(request))
    }
}

/// Linux 能力矩阵，用于组合层在启动前给出早期诊断。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxCapabilityMatrix {
    pub tcp_udp: CapabilitySupport,
    pub packet_device: CapabilitySupport,
    pub route_control: CapabilitySupport,
    pub transparent_proxy: CapabilitySupport,
    pub process_lookup: CapabilitySupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySupport {
    Supported,
    Limited,
    Planned,
    Unsupported,
}

#[cfg(target_os = "linux")]
fn linux_capability_matrix() -> LinuxCapabilityMatrix {
    LinuxCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Limited,
        transparent_proxy: CapabilitySupport::Limited,
        process_lookup: CapabilitySupport::Supported,
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_capability_matrix() -> LinuxCapabilityMatrix {
    LinuxCapabilityMatrix {
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    }
}

#[cfg(not(target_os = "linux"))]
fn packet_device_status_message() -> &'static str {
    "Linux packet devices are unavailable on this target"
}

#[cfg(not(target_os = "linux"))]
fn network_control_status_message() -> &'static str {
    "Linux network control is unavailable on this target"
}

#[cfg(target_os = "linux")]
fn process_lookup_status_message() -> &'static str {
    "Linux process lookup uses ss process ownership data"
}

#[cfg(target_os = "linux")]
fn lookup_linux_process(key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    let protocol = match key.network {
        rustbox_types::Network::Tcp => "-tanp",
        rustbox_types::Network::Udp => "-uanp",
    };
    let output = Command::new("ss")
        .args(["-H", protocol])
        .output()
        .map_err(|err| ProcessLookupError::new(format!("start ss process lookup: {err}")))?;
    if !output.status.success() {
        return Err(ProcessLookupError::new(format!(
            "{}: {}",
            process_lookup_status_message(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let port_marker = format!(":{}", key.local.port);
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains(&port_marker) && line.contains("pid="))
        .map(str::to_owned);
    let Some(line) = line else {
        return Ok(None);
    };
    let Some(pid) = line
        .split("pid=")
        .nth(1)
        .and_then(|tail| {
            tail.split(|character: char| !character.is_ascii_digit())
                .next()
        })
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(None);
    };
    let executable_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    Ok(Some(ProcessInfo {
        pid: Some(pid),
        executable_path,
        package_name: None,
        user_id: None,
    }))
}

#[cfg(not(target_os = "linux"))]
fn lookup_linux_process(_key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    Err(ProcessLookupError::new(process_lookup_status_message()))
}

#[cfg(not(target_os = "linux"))]
fn process_lookup_status_message() -> &'static str {
    "Linux process lookup is unavailable on this target"
}

async fn apply_linux_network_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    if transaction.operations.is_empty() {
        return Ok(NetworkLease {
            id: 0,
            operations: transaction.operations,
            active: false,
        });
    }

    #[cfg(target_os = "linux")]
    {
        apply_linux_route_transaction(transaction).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(NetworkControlError::new(format!(
            "{}; reason={:?} operations={}",
            network_control_status_message(),
            transaction.reason,
            transaction.operations.len()
        )))
    }
}

#[cfg(target_os = "linux")]
static NEXT_NETWORK_LEASE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "linux")]
async fn apply_linux_route_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
    let existing = handle
        .list()
        .await
        .map_err(|err| network_control_io_error("list routes", err))?;
    let mut routes = Vec::with_capacity(transaction.operations.len());
    let mut route_operations = Vec::with_capacity(transaction.operations.len());
    let mut deferred = Vec::new();
    for operation in &transaction.operations {
        match operation {
            NetworkOperation::AddRoute {
                destination,
                gateway,
                interface,
                metric,
            } => {
                routes.push(route_from_add_route(
                    *destination,
                    *gateway,
                    interface,
                    *metric,
                )?);
                route_operations.push(operation.clone());
            }
            NetworkOperation::PreserveRoute { destination } => {
                if !has_exact_route(*destination, &existing) {
                    routes.push(preserved_route(*destination, &existing)?);
                    route_operations.push(operation.clone());
                }
            }
            NetworkOperation::SetInterfaceDns { .. }
            | NetworkOperation::SetPlatformHttpProxy(_) => deferred.push(operation.clone()),
        }
    }

    let mut applied = Vec::new();
    for route in &routes {
        if let Err(err) = handle.add(route).await {
            if transaction.rollback_policy == RollbackPolicy::Required {
                rollback_routes(&handle, &applied).await;
            }
            return Err(network_control_io_error("add route", err));
        }
        applied.push(route.clone());
    }
    let mut applied_deferred = Vec::new();
    for operation in &deferred {
        if let Err(err) = apply_linux_non_route_operation(operation) {
            rollback_routes(&handle, &applied).await;
            for applied_operation in applied_deferred.iter().rev() {
                let _ = undo_linux_non_route_operation(applied_operation);
            }
            return Err(err);
        }
        applied_deferred.push(operation.clone());
    }

    route_operations.extend(applied_deferred);
    Ok(NetworkLease {
        id: NEXT_NETWORK_LEASE_ID.fetch_add(1, Ordering::Relaxed),
        operations: route_operations,
        active: true,
    })
}

#[cfg(target_os = "linux")]
fn preserved_route(
    destination: rustbox_types::IpCidr,
    routes: &[Route],
) -> Result<Route, NetworkControlError> {
    let address = std_ip_address(destination.address);
    let best = routes
        .iter()
        .filter(|route| route_contains(route, address))
        .max_by_key(|route| route.prefix)
        .ok_or_else(|| {
            NetworkControlError::new(format!(
                "no existing Linux route can preserve exclusion {destination}"
            ))
        })?;
    let mut route = Route::new(address, destination.prefix_len).with_table(best.table);
    if let Some(index) = best.ifindex {
        route = route.with_ifindex(index);
    }
    if let Some(gateway) = best.gateway {
        route = route.with_gateway(gateway);
    }
    if let Some(metric) = best.metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

#[cfg(target_os = "linux")]
fn route_contains(route: &Route, address: std::net::IpAddr) -> bool {
    match (route.destination, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) => {
            let prefix = route.prefix.min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) => {
            let prefix = route.prefix.min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn has_exact_route(destination: rustbox_types::IpCidr, routes: &[Route]) -> bool {
    let address = std_ip_address(destination.address);
    routes
        .iter()
        .any(|route| route.prefix == destination.prefix_len && route_contains(route, address))
}

async fn release_linux_network_lease(lease: NetworkLease) -> Result<(), NetworkControlError> {
    if !lease.active || lease.operations.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let handle = RouteHandle::new()
            .map_err(|err| network_control_io_error("initialize route handle", err))?;
        let existing = handle
            .list()
            .await
            .map_err(|err| network_control_io_error("list routes", err))?;
        let mut errors = Vec::new();
        for operation in lease.operations.iter().rev() {
            let route = match operation {
                NetworkOperation::AddRoute {
                    destination,
                    gateway,
                    interface,
                    metric,
                } => route_from_add_route(*destination, *gateway, interface, *metric)?,
                NetworkOperation::PreserveRoute { destination } => {
                    preserved_route(*destination, &existing)?
                }
                NetworkOperation::SetInterfaceDns { .. }
                | NetworkOperation::SetPlatformHttpProxy(_) => {
                    if let Err(err) = undo_linux_non_route_operation(operation) {
                        errors.push(err.message);
                    }
                    continue;
                }
            };
            if let Err(err) = handle.delete(&route).await {
                errors.push(err.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(NetworkControlError::new(format!(
                "release Linux network lease {} failed: {}",
                lease.id,
                errors.join("; ")
            )))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(NetworkControlError::new(network_control_status_message()))
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_non_route_operation(
    operation: &NetworkOperation,
) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, servers } => {
            let interface = interface_arg(interface);
            let server_args = servers
                .iter()
                .map(|server| std_ip_address(*server).to_string())
                .collect::<Vec<_>>();
            let mut args = vec!["dns".to_string(), interface];
            args.extend(server_args);
            run_linux_command("resolvectl", &args)
        }
        NetworkOperation::SetPlatformHttpProxy(proxy) => {
            let host = proxy.listen.host.to_string();
            run_linux_command(
                "gsettings",
                &[
                    "set".into(),
                    "org.gnome.system.proxy".into(),
                    "mode".into(),
                    "manual".into(),
                ],
            )?;
            for scheme in ["http", "https"] {
                let base = format!("org.gnome.system.proxy.{scheme}");
                run_linux_command(
                    "gsettings",
                    &["set".into(), base.clone(), "host".into(), host.clone()],
                )?;
                run_linux_command(
                    "gsettings",
                    &[
                        "set".into(),
                        base,
                        "port".into(),
                        proxy.listen.port.to_string(),
                    ],
                )?;
            }
            Ok(())
        }
        other => Err(NetworkControlError::new(format!(
            "not a Linux non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn undo_linux_non_route_operation(operation: &NetworkOperation) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, .. } => {
            run_linux_command("resolvectl", &["revert".into(), interface_arg(interface)])
        }
        NetworkOperation::SetPlatformHttpProxy(_) => run_linux_command(
            "gsettings",
            &[
                "set".into(),
                "org.gnome.system.proxy".into(),
                "mode".into(),
                "none".into(),
            ],
        ),
        other => Err(NetworkControlError::new(format!(
            "not a Linux non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn interface_arg(interface: &InterfaceRef) -> String {
    match interface {
        InterfaceRef::Index(index) => index.to_string(),
        InterfaceRef::Name(name) => name.clone(),
    }
}

#[cfg(target_os = "linux")]
fn run_linux_command(program: &str, args: &[String]) -> Result<(), NetworkControlError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| NetworkControlError::new(format!("start {program}: {err}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NetworkControlError::new(format!(
            "{program} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(target_os = "linux")]
fn route_from_add_route(
    destination: rustbox_types::IpCidr,
    gateway: Option<IpAddress>,
    interface: &InterfaceRef,
    metric: Option<u32>,
) -> Result<Route, NetworkControlError> {
    if destination.prefix_len > destination.address.max_prefix_len() {
        return Err(NetworkControlError::new(format!(
            "invalid route prefix `{}` for destination {}",
            destination.prefix_len, destination.address
        )));
    }

    let mut route = Route::new(std_ip_address(destination.address), destination.prefix_len)
        .with_ifindex(interface_index(interface)?);
    if let Some(gateway) = gateway {
        route = route.with_gateway(std_ip_address(gateway));
    }
    if let Some(metric) = metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

#[cfg(target_os = "linux")]
fn interface_index(interface: &InterfaceRef) -> Result<u32, NetworkControlError> {
    match interface {
        InterfaceRef::Index(index) => Ok(*index),
        InterfaceRef::Name(name) => Err(NetworkControlError::new(format!(
            "net-route AddRoute requires interface index on Linux; got name `{name}`"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn std_ip_address(address: IpAddress) -> std::net::IpAddr {
    match address {
        IpAddress::V4(octets) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
    }
}

#[cfg(target_os = "linux")]
async fn rollback_routes(handle: &RouteHandle, routes: &[Route]) {
    for route in routes.iter().rev() {
        let _ = handle.delete(route).await;
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
fn network_control_io_error(action: &str, err: std::io::Error) -> NetworkControlError {
    NetworkControlError::new(format!("{action} failed: {err}"))
}

async fn bind_linux_transparent_tcp(
    request: TransparentTcpBind,
) -> Result<Box<dyn TransparentStreamListener>, TransparentProxyError> {
    #[cfg(target_os = "linux")]
    {
        if request.mode != TransparentRedirectMode::Redirect {
            return Err(TransparentProxyError::new(format!(
                "Linux transparent proxy currently supports redirect mode only; requested {:?}",
                request.mode
            )));
        }
        if request.mark.is_some() {
            return Err(TransparentProxyError::new(
                "Linux transparent redirect does not use socket mark; set mark only for tproxy",
            ));
        }

        let addr = endpoint_to_socket_addr(&request.listen).map_err(TransparentProxyError::new)?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| TransparentProxyError::new(format!("bind transparent TCP: {err}")))?;
        Ok(Box::new(LinuxTransparentTcpListener { inner: listener })
            as Box<dyn TransparentStreamListener>)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(TransparentProxyError::new(format!(
            "Linux transparent TCP is unavailable on this target; listen={}",
            request.listen
        )))
    }
}

#[cfg(target_os = "linux")]
struct LinuxTransparentTcpListener {
    inner: TcpListener,
}

#[cfg(target_os = "linux")]
impl TransparentStreamListener for LinuxTransparentTcpListener {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(socket_addr_to_endpoint)
    }

    fn accept(
        &mut self,
    ) -> BoxFuture<'_, Result<AcceptedTransparentStream, TransparentProxyError>> {
        Box::pin(async move {
            let (stream, peer) = self.inner.accept().await.map_err(|err| {
                TransparentProxyError::new(format!("accept transparent TCP: {err}"))
            })?;
            let original_destination = original_destination(&stream)?;
            Ok(AcceptedTransparentStream {
                stream: Box::new(stream),
                peer: socket_addr_to_endpoint(peer),
                original_destination,
            })
        })
    }
}

#[cfg(target_os = "linux")]
fn original_destination(stream: &TcpStream) -> Result<Endpoint, TransparentProxyError> {
    match stream
        .local_addr()
        .map(|addr| addr.is_ipv4())
        .unwrap_or(true)
    {
        true => {
            let addr = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::OriginalDst)
                .map_err(|err| {
                    TransparentProxyError::new(format!("read SO_ORIGINAL_DST: {err}"))
                })?;
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Ok(Endpoint::new(
                Host::Ip(IpAddress::V4(ip.octets())),
                u16::from_be(addr.sin_port),
            ))
        }
        false => {
            let addr =
                nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::Ip6tOriginalDst)
                    .map_err(|err| {
                        TransparentProxyError::new(format!("read IP6T_SO_ORIGINAL_DST: {err}"))
                    })?;
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            Ok(Endpoint::new(
                Host::Ip(IpAddress::V6(ip.octets())),
                u16::from_be(addr.sin6_port),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Result<SocketAddr, String> {
    match &endpoint.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
        Host::Domain(domain) => Err(format!(
            "cannot bind transparent listener to domain {domain}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn socket_addr_to_endpoint(addr: SocketAddr) -> Endpoint {
    let host = match addr.ip() {
        IpAddr::V4(ip) => Host::Ip(IpAddress::V4(ip.octets())),
        IpAddr::V6(ip) => Host::Ip(IpAddress::V6(ip.octets())),
    };
    Endpoint::new(host, addr.port())
}

#[cfg(target_os = "linux")]
fn ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

#[cfg(target_os = "linux")]
fn open_linux_packet_device(
    config: PacketDeviceConfig,
) -> Result<PacketDeviceLease, PacketDeviceError> {
    let requested = config.clone();
    let device = build_tun_device(config).map_err(|err| {
        PacketDeviceError::new(format!(
            "failed to open Linux TUN packet device through tun-rs: {err}"
        ))
    })?;
    let name = device.name().map_err(|err| {
        PacketDeviceError::new(format!("failed to read Linux TUN interface name: {err}"))
    })?;
    let index = device.if_index().ok();
    let mtu = device.mtu().ok().or(requested.mtu);
    Ok(PacketDeviceLease {
        device: Box::new(TunPacketDevice::new(device)) as Box<dyn PacketDevice>,
        info: PacketDeviceInfo {
            name,
            index,
            addresses: requested.addresses,
            mtu,
        },
    })
}

#[cfg(not(target_os = "linux"))]
fn open_linux_packet_device(
    config: PacketDeviceConfig,
) -> Result<PacketDeviceLease, PacketDeviceError> {
    Err(PacketDeviceError::new(format!(
        "{}; requested name={:?} addresses={}",
        packet_device_status_message(),
        config.name,
        config.addresses.len()
    )))
}

#[cfg(target_os = "linux")]
fn build_tun_device(config: PacketDeviceConfig) -> std::io::Result<SyncDevice> {
    let mut builder = DeviceBuilder::new().layer(Layer::L3);
    if let Some(name) = config.name {
        builder = builder.name(name);
    }
    if let Some(mtu) = config.mtu {
        builder = builder.mtu(mtu);
    }
    for address in config.addresses {
        match address.address {
            IpAddress::V4(octets) => {
                builder = builder.ipv4(std::net::Ipv4Addr::from(octets), address.prefix_len, None);
            }
            IpAddress::V6(octets) => {
                builder = builder.ipv6(std::net::Ipv6Addr::from(octets), address.prefix_len);
            }
        }
    }

    let device = builder.build_sync()?;
    device.set_nonblocking(true)?;
    Ok(device)
}

/// Thin RustBox `PacketDevice` wrapper over a real Linux TUN `tun-rs` device.
#[cfg(target_os = "linux")]
struct TunPacketDevice {
    device: SyncDevice,
}

#[cfg(target_os = "linux")]
impl TunPacketDevice {
    fn new(device: SyncDevice) -> Self {
        Self { device }
    }
}

#[cfg(target_os = "linux")]
impl PacketDevice for TunPacketDevice {
    fn poll_recv_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        match self.get_mut().device.recv(buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // The adapter is deliberately tiny; a future runtime-specific
                // packet device can replace this with true readiness wakers.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(io_error(err))),
        }
    }

    fn poll_send_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        match self.get_mut().device.send(packet) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(io_error(err))),
        }
    }
}

#[cfg(target_os = "linux")]
fn io_error(err: std::io::Error) -> IoError {
    let kind = match err.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
            IoErrorKind::Interrupted
        }
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            IoErrorKind::InvalidInput
        }
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => IoErrorKind::Closed,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use rustbox_host_api::{InterfaceRef, NetworkControlReason};
    #[cfg(target_os = "linux")]
    use rustbox_types::{IpAddress, IpCidr};

    #[test]
    fn declares_linux_capabilities_for_current_target() {
        let matrix = LinuxPlatform::new().capability_matrix();

        #[cfg(target_os = "linux")]
        {
            assert_eq!(matrix.tcp_udp, CapabilitySupport::Supported);
            assert_eq!(matrix.packet_device, CapabilitySupport::Supported);
            assert_eq!(matrix.route_control, CapabilitySupport::Limited);
            assert_eq!(matrix.transparent_proxy, CapabilitySupport::Limited);
            assert_eq!(matrix.process_lookup, CapabilitySupport::Supported);
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(matrix.tcp_udp, CapabilitySupport::Unsupported);
            assert_eq!(matrix.packet_device, CapabilitySupport::Unsupported);
            assert_eq!(matrix.route_control, CapabilitySupport::Unsupported);
            assert_eq!(matrix.transparent_proxy, CapabilitySupport::Unsupported);
            assert_eq!(matrix.process_lookup, CapabilitySupport::Unsupported);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn accepts_empty_network_control_transaction_as_noop_lease() {
        let platform = LinuxPlatform::new();
        let transaction = NetworkTransaction {
            reason: NetworkControlReason::TunInbound,
            operations: Vec::new(),
            rollback_policy: RollbackPolicy::Required,
        };

        let lease = block_on_ready(platform.apply(transaction)).expect("empty transaction");

        assert_eq!(lease.id, 0);
        assert!(lease.operations.is_empty());
        assert!(!lease.active);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn converts_add_route_operation_to_net_route() {
        let route = route_from_add_route(
            IpCidr::new(IpAddress::V4([10, 14, 0, 0]), 24).expect("cidr"),
            Some(IpAddress::V4([192, 0, 2, 1])),
            &InterfaceRef::Index(9),
            Some(5),
        )
        .expect("route");

        assert_eq!(
            route.destination,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 14, 0, 0))
        );
        assert_eq!(route.prefix, 24);
        assert_eq!(
            route.gateway,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(route.ifindex, Some(9));
        assert_eq!(route.metric, Some(5));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recognizes_an_existing_exact_exclusion_route() {
        let destination = IpCidr::new(IpAddress::V4([192, 0, 2, 7]), 32).expect("host route");
        let routes = vec![
            Route::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
                32,
            )
            .with_ifindex(9),
        ];

        assert!(has_exact_route(destination, &routes));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn opens_and_closes_real_tun_when_e2e_is_enabled() {
        if std::env::var_os("RUSTBOX_TUN_E2E").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime");
        let lease = runtime
            .block_on(LinuxPlatform::new().open(PacketDeviceConfig {
                name: Some(format!("rtun{}", std::process::id() % 10000)),
                addresses: vec![
                    IpCidr::new(IpAddress::V4([198, 18, 0, 1]), 30).expect("test CIDR"),
                ],
                mtu: Some(1500),
                route_mode: rustbox_host_api::RouteMode::Manual,
                dns_mode: rustbox_host_api::TunDnsMode::None,
            }))
            .expect("open real Linux TUN device; runner must have /dev/net/tun and CAP_NET_ADMIN");
        assert!(!lease.info.name.is_empty());
        assert_eq!(lease.info.addresses.len(), 1);
        drop(lease);
    }

    #[cfg(target_os = "linux")]
    fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime")
            .block_on(future)
    }
}
