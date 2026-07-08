//! Windows 平台能力适配边界。
//!
//! 当前只接入 Wintun-backed packet device。Route control、透明代理和进程查询
//! 仍以显式 planned error 暴露，内核不会通过 `cfg(target_os)` 推断平台能力。

#[cfg(target_os = "windows")]
use net_route::{Handle as RouteHandle, Route};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, NetworkControl, NetworkControlError, NetworkLease,
    NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceInfo, PacketDeviceLease,
    PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError,
};
#[cfg(target_os = "windows")]
use rustbox_host_api::{InterfaceRef, NetworkOperation, RollbackPolicy};
use rustbox_io::PacketDevice;
#[cfg(target_os = "windows")]
use rustbox_io::{IoError, IoErrorKind};
#[cfg(target_os = "windows")]
use rustbox_types::IpAddress;
#[cfg(target_os = "windows")]
use std::pin::Pin;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::task::{Context, Poll};
#[cfg(target_os = "windows")]
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

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
}

impl ProcessLookup for WindowsPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>> {
        Box::pin(async move {
            Err(ProcessLookupError::new(format!(
                "{}; network={:?} local={} remote={}",
                process_lookup_status_message(),
                key.network,
                key.local,
                key.remote
            )))
        })
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
        route_control: CapabilitySupport::Limited,
        transparent_proxy: CapabilitySupport::Planned,
        process_lookup: CapabilitySupport::Planned,
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
fn network_control_status_message() -> &'static str {
    "Windows network control is limited to AddRoute through net-route"
}

#[cfg(target_os = "windows")]
fn process_lookup_status_message() -> &'static str {
    "Windows process lookup is not implemented yet"
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
    let mut routes = Vec::with_capacity(transaction.operations.len());
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
            operation => {
                return Err(unsupported_network_operation(
                    transaction.reason,
                    transaction.operations.len(),
                    operation,
                ));
            }
        }
    }

    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
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

    Ok(NetworkLease {
        id: NEXT_NETWORK_LEASE_ID.fetch_add(1, Ordering::Relaxed),
        operations: transaction.operations,
        active: true,
    })
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
fn unsupported_network_operation(
    reason: rustbox_host_api::NetworkControlReason,
    operation_count: usize,
    operation: &NetworkOperation,
) -> NetworkControlError {
    NetworkControlError::new(format!(
        "{}; reason={reason:?} operations={operation_count} planned operation={operation:?}",
        network_control_status_message()
    ))
}

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
    builder.build_sync()
}

/// Thin RustBox `PacketDevice` wrapper over a Wintun-backed `tun-rs` device.
#[cfg(target_os = "windows")]
struct TunPacketDevice {
    device: SyncDevice,
}

#[cfg(target_os = "windows")]
impl TunPacketDevice {
    fn new(device: SyncDevice) -> Self {
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
        match self.get_mut().device.try_recv(buf) {
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
        match self.get_mut().device.try_send(packet) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(io_error(err))),
        }
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
    use rustbox_host_api::{
        NetworkControlReason, NetworkOperation, RollbackPolicy, SocketProtectionHandle,
    };
    #[cfg(target_os = "windows")]
    use rustbox_types::{IpAddress, IpCidr};

    #[test]
    fn declares_windows_tun_and_route_capabilities_for_current_target() {
        let matrix = WindowsPlatform::new().capability_matrix();

        #[cfg(target_os = "windows")]
        {
            assert_eq!(matrix.tcp_udp, CapabilitySupport::Supported);
            assert_eq!(matrix.packet_device, CapabilitySupport::Supported);
            assert_eq!(matrix.route_control, CapabilitySupport::Limited);
            assert_eq!(matrix.transparent_proxy, CapabilitySupport::Planned);
            assert_eq!(matrix.process_lookup, CapabilitySupport::Planned);
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
    fn reports_typed_network_control_request_in_error() {
        let platform = WindowsPlatform::new();
        let transaction = NetworkTransaction {
            reason: NetworkControlReason::TunInbound,
            operations: vec![NetworkOperation::ProtectSocket {
                handle: SocketProtectionHandle(7),
            }],
            rollback_policy: RollbackPolicy::Required,
        };

        let error = block_on_ready(platform.apply(transaction)).expect_err("planned error");

        assert!(error.message.contains("reason=TunInbound"));
        assert!(error.message.contains("operations=1"));
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
