//! macOS utun packet device and transactional route control.

use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};
use net_route::{Handle, Route};
use rustbox_host_api::{
    BoxFuture, InterfaceRef, NetworkControl, NetworkControlError, NetworkLease,
    NetworkOperation, NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceInfo,
    PacketDeviceLease, PacketDeviceProvider, RollbackPolicy,
};
use rustbox_io::{IoError, PacketDevice};
use rustbox_types::{IpAddress, IpCidr};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

#[derive(Clone, Debug, Default)]
pub struct MacosPlatform;

impl MacosPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl PacketDeviceProvider for MacosPlatform {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>> {
        Box::pin(async move { open_packet_device(config) })
    }
}

impl NetworkControl for MacosPlatform {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(apply_transaction(transaction))
    }

    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
        Box::pin(release_lease(lease))
    }
}

static NEXT_LEASE: AtomicU64 = AtomicU64::new(1);

fn open_packet_device(
    config: PacketDeviceConfig,
) -> Result<PacketDeviceLease, PacketDeviceError> {
    let requested = config.clone();
    let mut builder = DeviceBuilder::new().layer(Layer::L3);
    if let Some(name) = config.name {
        builder = builder.name(name);
    }
    if let Some(mtu) = config.mtu {
        builder = builder.mtu(mtu);
    }
    for address in config.addresses {
        builder = match address.address {
            IpAddress::V4(value) => {
                builder.ipv4(std::net::Ipv4Addr::from(value), address.prefix_len, None)
            }
            IpAddress::V6(value) => {
                builder.ipv6(std::net::Ipv6Addr::from(value), address.prefix_len)
            }
        };
    }
    let device = builder
        .build_async()
        .map_err(|err| PacketDeviceError::new(format!("open macOS utun: {err}")))?;
    let name = device
        .name()
        .map_err(|err| PacketDeviceError::new(format!("read utun name: {err}")))?;
    let index = device.if_index().ok();
    let mtu = device.mtu().ok().or(requested.mtu);
    Ok(PacketDeviceLease {
        device: Box::new(MacosPacketDevice(device)),
        info: PacketDeviceInfo {
            name,
            index,
            addresses: requested.addresses,
            mtu,
        },
    })
}

async fn apply_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    if transaction.operations.is_empty() {
        return Ok(NetworkLease {
            id: 0,
            operations: Vec::new(),
            active: false,
        });
    }
    let handle = Handle::new().map_err(error)?;
    let existing = handle.list().await.map_err(error)?;
    let mut applied = Vec::new();
    for operation in &transaction.operations {
        let route = operation_route(operation, &existing)?;
        if let Err(err) = handle.add(&route).await {
            if transaction.rollback_policy == RollbackPolicy::Required {
                for route in applied.iter().rev() {
                    let _ = handle.delete(route).await;
                }
            }
            return Err(error(err));
        }
        applied.push(route);
    }
    Ok(NetworkLease {
        id: NEXT_LEASE.fetch_add(1, Ordering::Relaxed),
        operations: transaction.operations,
        active: true,
    })
}

async fn release_lease(lease: NetworkLease) -> Result<(), NetworkControlError> {
    if !lease.active {
        return Ok(());
    }
    let handle = Handle::new().map_err(error)?;
    let existing = handle.list().await.map_err(error)?;
    let mut failures = Vec::new();
    for operation in lease.operations.iter().rev() {
        match operation_route(operation, &existing) {
            Ok(route) => {
                if let Err(err) = handle.delete(&route).await {
                    failures.push(err.to_string());
                }
            }
            Err(err) => failures.push(err.message),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(NetworkControlError::new(failures.join("; ")))
    }
}

fn operation_route(
    operation: &NetworkOperation,
    existing: &[Route],
) -> Result<Route, NetworkControlError> {
    match operation {
        NetworkOperation::AddRoute {
            destination,
            gateway,
            interface,
            ..
        } => {
            let mut route = Route::new(ip(destination.address), destination.prefix_len)
                .with_ifindex(interface_index(interface)?);
            if let Some(gateway) = gateway {
                route = route.with_gateway(ip(*gateway));
            }
            Ok(route)
        }
        NetworkOperation::PreserveRoute { destination } => preserve(*destination, existing),
        other => Err(NetworkControlError::new(format!(
            "unsupported macOS network operation: {other:?}"
        ))),
    }
}

fn preserve(destination: IpCidr, routes: &[Route]) -> Result<Route, NetworkControlError> {
    let address = ip(destination.address);
    let best = routes
        .iter()
        .filter(|route| contains(route, address))
        .max_by_key(|route| route.prefix)
        .ok_or_else(|| {
            NetworkControlError::new(format!("no route for exclusion {destination}"))
        })?;
    let mut route = Route::new(address, destination.prefix_len);
    if let Some(index) = best.ifindex {
        route = route.with_ifindex(index);
    }
    if let Some(gateway) = best.gateway {
        route = route.with_gateway(gateway);
    }
    Ok(route)
}

fn contains(route: &Route, address: std::net::IpAddr) -> bool {
    match (route.destination, address) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            let p = route.prefix.min(32);
            let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            u32::from(a) & m == u32::from(b) & m
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            let p = route.prefix.min(128);
            let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            u128::from(a) & m == u128::from(b) & m
        }
        _ => false,
    }
}

fn interface_index(interface: &InterfaceRef) -> Result<u32, NetworkControlError> {
    match interface {
        InterfaceRef::Index(index) => Ok(*index),
        InterfaceRef::Name(name) => net_route::ifname_to_index(name).ok_or_else(|| {
            NetworkControlError::new(format!("unknown macOS interface `{name}`"))
        }),
    }
}

fn ip(value: IpAddress) -> std::net::IpAddr {
    match value {
        IpAddress::V4(v) => std::net::Ipv4Addr::from(v).into(),
        IpAddress::V6(v) => std::net::Ipv6Addr::from(v).into(),
    }
}

fn error(error: std::io::Error) -> NetworkControlError {
    NetworkControlError::new(error.to_string())
}

struct MacosPacketDevice(AsyncDevice);
impl PacketDevice for MacosPacketDevice {
    fn poll_recv_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut().0.poll_recv(cx, buf).map_err(IoError::from)
    }
    fn poll_send_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut()
            .0
            .poll_send(cx, packet)
            .map_err(IoError::from)
    }
}
