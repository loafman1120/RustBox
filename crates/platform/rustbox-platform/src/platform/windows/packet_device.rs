#[cfg(test)]
use super::network_control::{has_exact_route, route_from_add_route};
use super::*;

impl PacketDeviceProvider for WindowsPlatform {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>> {
        Box::pin(async move { open_windows_packet_device(config) })
    }
}

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
struct TunPacketDevice {
    device: AsyncDevice,
}

impl TunPacketDevice {
    fn new(device: AsyncDevice) -> Self {
        Self { device }
    }
}

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
    use rustbox_kernel::InterfaceRef;
    use rustbox_kernel::{NetworkControlReason, RollbackPolicy};
    use rustbox_types::{IpAddress, IpCidr};

    #[test]
    fn declares_windows_tun_and_route_capabilities_for_current_target() {
        let matrix = crate::current_capabilities();

        assert_eq!(matrix.tcp_udp, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.packet_device, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.route_control, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.transparent_proxy, crate::CapabilitySupport::Planned);
        assert_eq!(matrix.process_lookup, crate::CapabilitySupport::Supported);
    }

    #[test]
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
                route_mode: rustbox_kernel::RouteMode::Manual,
                dns_mode: rustbox_kernel::TunDnsMode::None,
            }))
            .expect("open real Wintun adapter; runner must be elevated and provide Wintun");
        assert!(lease.info.index.is_some());
        assert_eq!(lease.info.addresses.len(), 1);
        drop(lease);
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
