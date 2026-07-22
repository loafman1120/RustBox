#[cfg(test)]
use super::network_control::{has_exact_route, route_from_add_route};
use super::*;
use std::net::IpAddr;

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
            IpAddr::V4(octets) => {
                builder = builder.ipv4(octets, address.prefix_len, None);
            }
            IpAddr::V6(octets) => {
                builder = builder.ipv6(octets, address.prefix_len);
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
    let path = candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "wintun.dll not found beside the RustBox executable; rebuild the Windows package or set RUSTBOX_WINTUN_DLL for development",
            )
        })?;
    verify_wintun_architecture(&path)?;
    Ok(path)
}

fn verify_wintun_architecture(path: &std::path::Path) -> std::io::Result<()> {
    use object::Object;

    let bytes = std::fs::read(path)?;
    let image = object::File::parse(bytes.as_slice()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid wintun.dll PE image: {error}"),
        )
    })?;
    if image.format() != object::BinaryFormat::Pe {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wintun.dll is not a Windows PE image",
        ));
    }
    let expected = if cfg!(target_arch = "x86_64") {
        object::Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        object::Architecture::Aarch64
    } else if cfg!(target_arch = "x86") {
        object::Architecture::I386
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "unsupported Windows target architecture `{}`",
                std::env::consts::ARCH
            ),
        ));
    };
    if image.architecture() != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "wintun.dll architecture {:?} does not match RustBox target {:?}",
                image.architecture(),
                expected
            ),
        ));
    }
    Ok(())
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
        self.get_mut().device.poll_recv(cx, buf).map_err(Into::into)
    }

    fn poll_send_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut()
            .device
            .poll_send(cx, packet)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_kernel::InterfaceRef;
    use rustbox_kernel::{NetworkControlReason, RollbackPolicy};
    use rustbox_types::IpCidr;

    #[test]
    fn declares_windows_tun_and_route_capabilities_for_current_target() {
        let matrix = crate::current_capabilities();

        assert_eq!(matrix.tcp_udp, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.packet_device, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.route_control, crate::CapabilitySupport::Supported);
        assert_eq!(matrix.transparent_proxy, crate::CapabilitySupport::Planned);
        assert_eq!(matrix.process_lookup, crate::CapabilitySupport::Supported);
        assert!(matrix.strict_route_requires_interface_binding);
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
            IpCidr::new(IpAddr::from([10, 14, 0, 0]), 24).expect("cidr"),
            Some(IpAddr::from([192, 0, 2, 1])),
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
        let destination = IpCidr::new(IpAddr::from([192, 0, 2, 7]), 32).expect("host route");
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
                    IpCidr::new(IpAddr::from([198, 18, 0, 1]), 30).expect("benchmark CIDR"),
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

    #[test]
    fn validates_the_current_windows_binary_architecture() {
        let executable = std::env::current_exe().expect("current test executable");
        verify_wintun_architecture(&executable).expect("matching PE architecture");
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
