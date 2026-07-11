//! Windows 平台能力适配边界。
//!
//! Wintun packet I/O and transactional route control live here. Transparent
//! proxy and process lookup remain explicit planned capabilities.

#[cfg(target_os = "windows")]
use net_route::{Handle as RouteHandle, Route};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, NetworkControl, NetworkControlError, NetworkLease,
    NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceLease,
    PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError,
};
#[cfg(target_os = "windows")]
use rustbox_host_api::{InterfaceRef, NetworkOperation, PacketDeviceInfo, RollbackPolicy};
#[cfg(target_os = "windows")]
use rustbox_io::PacketDevice;
#[cfg(target_os = "windows")]
use rustbox_io::{IoError, IoErrorKind};
#[cfg(target_os = "windows")]
use rustbox_types::IpAddress;
#[cfg(target_os = "windows")]
use std::pin::Pin;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::task::{Context, Poll};
#[cfg(target_os = "windows")]
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// Windows 平台能力集合的占位实现。
#[derive(Clone, Debug, Default)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn capability_matrix(&self) -> WindowsCapabilityMatrix {
        windows_capability_matrix()
    }
}

impl PacketDeviceProvider for WindowsPlatform {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>> {
        Box::pin(async move { open_windows_packet_device(config) })
    }
}

impl NetworkControl for WindowsPlatform {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(apply_windows_network_transaction(transaction))
    }

    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
        Box::pin(release_windows_network_lease(lease))
    }
}

impl ProcessLookup for WindowsPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>> {
        Box::pin(async move { lookup_windows_process(key) })
    }
}

/// Windows 能力矩阵，用于向组合层或控制面声明当前支持状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCapabilityMatrix {
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

#[cfg(target_os = "windows")]
fn windows_capability_matrix() -> WindowsCapabilityMatrix {
    WindowsCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Supported,
        transparent_proxy: CapabilitySupport::Planned,
        process_lookup: CapabilitySupport::Supported,
    }
}

#[cfg(not(target_os = "windows"))]
fn windows_capability_matrix() -> WindowsCapabilityMatrix {
    WindowsCapabilityMatrix {
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    }
}

#[cfg(not(target_os = "windows"))]
fn packet_device_status_message() -> &'static str {
    "Windows packet devices are unavailable on this target"
}

#[cfg(not(target_os = "windows"))]
fn network_control_status_message() -> &'static str {
    "Windows network control is unavailable on this target"
}

#[cfg(target_os = "windows")]
fn process_lookup_status_message() -> &'static str {
    "Windows process lookup uses Get-NetTCPConnection/Get-NetUDPEndpoint"
}

#[cfg(target_os = "windows")]
fn lookup_windows_process(key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    let command = match key.network {
        rustbox_types::Network::Tcp => "Get-NetTCPConnection",
        rustbox_types::Network::Udp => "Get-NetUDPEndpoint",
    };
    let script = format!(
        "$c={command} -LocalPort {} -ErrorAction SilentlyContinue | Select-Object -First 1; if($null -ne $c){{$p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; Write-Output $c.OwningProcess; Write-Output $p.Path}}",
        key.local.port
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|err| ProcessLookupError::new(format!("start process lookup: {err}")))?;
    if !output.status.success() {
        return Err(ProcessLookupError::new(format!(
            "{}: {}",
            process_lookup_status_message(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let Some(pid) = lines
        .next()
        .and_then(|line| line.trim().parse::<u32>().ok())
    else {
        return Ok(None);
    };
    let path = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(Some(ProcessInfo {
        pid: Some(pid),
        executable_path: path,
        package_name: None,
        user_id: None,
    }))
}

#[cfg(not(target_os = "windows"))]
fn lookup_windows_process(_key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    Err(ProcessLookupError::new(process_lookup_status_message()))
}

#[cfg(not(target_os = "windows"))]
fn process_lookup_status_message() -> &'static str {
    "Windows process lookup is unavailable on this target"
}

async fn apply_windows_network_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    if transaction.operations.is_empty() {
        return Ok(NetworkLease {
            id: 0,
            operations: transaction.operations,
            active: false,
        });
    }

    #[cfg(target_os = "windows")]
    {
        apply_windows_route_transaction(transaction).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(NetworkControlError::new(format!(
            "{}; reason={:?} operations={}",
            network_control_status_message(),
            transaction.reason,
            transaction.operations.len()
        )))
    }
}

#[cfg(target_os = "windows")]
static NEXT_NETWORK_LEASE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "windows")]
async fn apply_windows_route_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
    let existing = handle
        .list()
        .await
        .map_err(|err| network_control_io_error("list routes", err))?;
    let mut routes = Vec::with_capacity(transaction.operations.len());
    let mut deferred = Vec::new();
    for operation in &transaction.operations {
        match operation {
            NetworkOperation::AddRoute {
                destination,
                gateway,
                interface,
                metric,
            } => routes.push(route_from_add_route(
                *destination,
                *gateway,
                interface,
                *metric,
            )?),
            NetworkOperation::PreserveRoute { destination } => {
                routes.push(preserved_route(*destination, &existing)?);
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
        if let Err(err) = apply_windows_non_route_operation(operation) {
            rollback_routes(&handle, &applied).await;
            for applied_operation in applied_deferred.iter().rev() {
                let _ = undo_windows_non_route_operation(applied_operation);
            }
            return Err(err);
        }
        applied_deferred.push(operation.clone());
    }

    Ok(NetworkLease {
        id: NEXT_NETWORK_LEASE_ID.fetch_add(1, Ordering::Relaxed),
        operations: transaction.operations,
        active: true,
    })
}

#[cfg(target_os = "windows")]
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
                "no existing Windows route can preserve exclusion {destination}"
            ))
        })?;
    let mut route = Route::new(address, destination.prefix_len);
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

#[cfg(target_os = "windows")]
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

async fn release_windows_network_lease(lease: NetworkLease) -> Result<(), NetworkControlError> {
    if !lease.active || lease.operations.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
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
                    if let Err(err) = undo_windows_non_route_operation(operation) {
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
                "release Windows network lease {} failed: {}",
                lease.id,
                errors.join("; ")
            )))
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(NetworkControlError::new(network_control_status_message()))
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_non_route_operation(
    operation: &NetworkOperation,
) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, servers } => {
            if servers.is_empty() {
                return Err(NetworkControlError::new(
                    "Windows DNS server list cannot be empty",
                ));
            }
            let selector = match interface {
                InterfaceRef::Index(index) => format!("-InterfaceIndex {index}"),
                InterfaceRef::Name(name) => format!("-InterfaceAlias '{}'", ps_quote(name)),
            };
            let servers = servers
                .iter()
                .map(|server| format!("'{}'", std_ip_address(*server)))
                .collect::<Vec<_>>()
                .join(",");
            run_powershell(&format!(
                "Set-DnsClientServerAddress {selector} -ServerAddresses @({servers}) -ErrorAction Stop"
            ))
        }
        NetworkOperation::SetPlatformHttpProxy(proxy) => {
            let server = proxy.listen.to_string();
            let bypass = proxy.bypass.join(";");
            run_powershell_with_env(
                "$path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty $path ProxyEnable 1 -Type DWord; Set-ItemProperty $path ProxyServer $env:RUSTBOX_PROXY; Set-ItemProperty $path ProxyOverride $env:RUSTBOX_BYPASS",
                &[("RUSTBOX_PROXY", server), ("RUSTBOX_BYPASS", bypass)],
            )
        }
        other => Err(NetworkControlError::new(format!(
            "not a Windows non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn undo_windows_non_route_operation(
    operation: &NetworkOperation,
) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, .. } => {
            let selector = match interface {
                InterfaceRef::Index(index) => format!("-InterfaceIndex {index}"),
                InterfaceRef::Name(name) => format!("-InterfaceAlias '{}'", ps_quote(name)),
            };
            run_powershell(&format!(
                "Set-DnsClientServerAddress {selector} -ResetServerAddresses -ErrorAction Stop"
            ))
        }
        NetworkOperation::SetPlatformHttpProxy(_) => run_powershell(
            "$path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty $path ProxyEnable 0 -Type DWord",
        ),
        other => Err(NetworkControlError::new(format!(
            "not a Windows non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<(), NetworkControlError> {
    run_powershell_with_env(script, &[])
}

#[cfg(target_os = "windows")]
fn run_powershell_with_env(
    script: &str,
    env: &[(&str, String)],
) -> Result<(), NetworkControlError> {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().map_err(|err| {
        NetworkControlError::new(format!("start PowerShell network command: {err}"))
    })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NetworkControlError::new(format!(
            "PowerShell network command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn interface_index(interface: &InterfaceRef) -> Result<u32, NetworkControlError> {
    match interface {
        InterfaceRef::Index(index) => Ok(*index),
        InterfaceRef::Name(name) => Err(NetworkControlError::new(format!(
            "net-route AddRoute requires interface index on Windows; got name `{name}`"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn std_ip_address(address: IpAddress) -> std::net::IpAddr {
    match address {
        IpAddress::V4(octets) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
    }
}

#[cfg(target_os = "windows")]
async fn rollback_routes(handle: &RouteHandle, routes: &[Route]) {
    for route in routes.iter().rev() {
        let _ = handle.delete(route).await;
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
fn network_control_io_error(action: &str, err: std::io::Error) -> NetworkControlError {
    NetworkControlError::new(format!("{action} failed: {err}"))
}

#[cfg(target_os = "windows")]
fn open_windows_packet_device(
    config: PacketDeviceConfig,
) -> Result<PacketDeviceLease, PacketDeviceError> {
    let requested = config.clone();
    let device = build_tun_device(config).map_err(|err| {
        PacketDeviceError::new(format!(
            "failed to open Windows TUN packet device through tun-rs/Wintun: {err}"
        ))
    })?;
    let name = device.name().map_err(|err| {
        PacketDeviceError::new(format!("failed to read Windows TUN interface name: {err}"))
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

#[cfg(not(target_os = "windows"))]
fn open_windows_packet_device(
    config: PacketDeviceConfig,
) -> Result<PacketDeviceLease, PacketDeviceError> {
    Err(PacketDeviceError::new(format!(
        "{}; requested name={:?} addresses={}",
        packet_device_status_message(),
        config.name,
        config.addresses.len()
    )))
}

#[cfg(target_os = "windows")]
fn build_tun_device(config: PacketDeviceConfig) -> std::io::Result<AsyncDevice> {
    let wintun = locate_wintun_dll()?;
    let mut builder = DeviceBuilder::new().layer(Layer::L3).with(|options| {
        options.wintun_file(wintun.to_string_lossy().into_owned());
    });
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
    builder.build_async()
}

#[cfg(target_os = "windows")]
fn locate_wintun_dll() -> std::io::Result<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("RUSTBOX_WINTUN_DLL") {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        candidates.push(directory.join("wintun.dll"));
    }
    candidates.push(std::path::PathBuf::from("wintun.dll"));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "wintun.dll not found; place the official architecture-matched DLL beside rustbox-app or set RUSTBOX_WINTUN_DLL",
        ))
}

/// Thin RustBox `PacketDevice` wrapper over a Wintun-backed `tun-rs` device.
#[cfg(target_os = "windows")]
struct TunPacketDevice {
    device: AsyncDevice,
}

#[cfg(target_os = "windows")]
impl TunPacketDevice {
    fn new(device: AsyncDevice) -> Self {
        Self { device }
    }
}

#[cfg(target_os = "windows")]
impl PacketDevice for TunPacketDevice {
    fn poll_recv_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut().device.poll_recv(cx, buf).map_err(io_error)
    }

    fn poll_send_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut()
            .device
            .poll_send(cx, packet)
            .map_err(io_error)
    }
}

#[cfg(target_os = "windows")]
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
    #[cfg(target_os = "windows")]
    use rustbox_host_api::InterfaceRef;
    #[cfg(target_os = "windows")]
    use rustbox_host_api::{NetworkControlReason, RollbackPolicy};
    #[cfg(target_os = "windows")]
    use rustbox_types::{IpAddress, IpCidr};

    #[test]
    fn declares_windows_tun_and_route_capabilities_for_current_target() {
        let matrix = WindowsPlatform::new().capability_matrix();

        #[cfg(target_os = "windows")]
        {
            assert_eq!(matrix.tcp_udp, CapabilitySupport::Supported);
            assert_eq!(matrix.packet_device, CapabilitySupport::Supported);
            assert_eq!(matrix.route_control, CapabilitySupport::Supported);
            assert_eq!(matrix.transparent_proxy, CapabilitySupport::Planned);
            assert_eq!(matrix.process_lookup, CapabilitySupport::Supported);
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(matrix.tcp_udp, CapabilitySupport::Unsupported);
            assert_eq!(matrix.packet_device, CapabilitySupport::Unsupported);
            assert_eq!(matrix.route_control, CapabilitySupport::Unsupported);
            assert_eq!(matrix.transparent_proxy, CapabilitySupport::Unsupported);
            assert_eq!(matrix.process_lookup, CapabilitySupport::Unsupported);
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn accepts_empty_network_control_transaction_as_noop_lease() {
        let platform = WindowsPlatform::new();
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
    #[cfg(target_os = "windows")]
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
    #[cfg(target_os = "windows")]
    fn opens_and_closes_real_wintun_when_e2e_is_enabled() {
        if std::env::var_os("RUSTBOX_TUN_E2E").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime");
        let lease = runtime
            .block_on(WindowsPlatform::new().open(PacketDeviceConfig {
                name: Some(format!("RustBox-CI-{}", std::process::id())),
                addresses: vec![
                    IpCidr::new(IpAddress::V4([198, 18, 0, 1]), 30).expect("benchmark CIDR"),
                ],
                mtu: Some(1500),
                route_mode: rustbox_host_api::RouteMode::Manual,
                dns_mode: rustbox_host_api::TunDnsMode::None,
            }))
            .expect("open real Wintun adapter; runner must be elevated and provide Wintun");
        assert!(lease.info.index.is_some());
        assert_eq!(lease.info.addresses.len(), 1);
        drop(lease);
    }

    #[cfg(target_os = "windows")]
    fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut future = core::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
