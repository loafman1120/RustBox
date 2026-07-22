use crate::{CapabilitySupport, PlatformCapabilities, TunCapabilities};
use rustbox_kernel::{
    BoxFuture, ConnectionKey, NetworkMetadataError, NetworkMetadataInfo, NetworkMetadataLookup,
    ProcessLookup, ProcessLookupError, TransparentProxyProvider,
};
use rustbox_types::ProcessMetadata;
use std::sync::Arc;

pub(super) const CAPABILITIES: PlatformCapabilities = PlatformCapabilities {
    platform: "Android",
    tcp_udp: CapabilitySupport::Supported,
    packet_device: CapabilitySupport::Planned,
    route_control: CapabilitySupport::Planned,
    transparent_proxy: CapabilitySupport::Unsupported,
    process_lookup: CapabilitySupport::Limited,
    strict_route_requires_interface_binding: false,
};

pub(super) fn tun() -> Option<TunCapabilities> {
    None
}
pub(super) fn transparent() -> Option<Arc<dyn TransparentProxyProvider>> {
    None
}
pub(super) fn process() -> Option<Arc<dyn ProcessLookup>> {
    Some(Arc::new(AndroidProcessLookup))
}
pub(super) fn network_metadata() -> Option<Arc<dyn NetworkMetadataLookup>> {
    Some(Arc::new(AndroidNetworkMetadataLookup))
}
pub(super) fn socket_policy() -> Arc<dyn rustbox_kernel::TokioSocketPolicy> {
    Arc::new(AndroidSocketPolicy)
}
pub(super) fn default_route_interface() -> Option<rustbox_kernel::InterfaceRef> {
    None
}

pub(super) fn default_route_interface_index() -> Option<u32> {
    None
}

pub(super) async fn recover_stale_network_state() -> Result<(), String> {
    Ok(())
}

struct AndroidProcessLookup;
struct AndroidNetworkMetadataLookup;
struct AndroidSocketPolicy;

impl rustbox_kernel::TokioSocketPolicy for AndroidSocketPolicy {
    fn bind_interface(
        &self,
        socket: &socket2::Socket,
        interface: &str,
        _destination: std::net::IpAddr,
    ) -> Result<(), rustbox_kernel::NetError> {
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|error| rustbox_kernel::NetError::new(error.to_string()))
    }

    fn set_routing_mark(
        &self,
        socket: &socket2::Socket,
        mark: u32,
    ) -> Result<(), rustbox_kernel::NetError> {
        socket
            .set_mark(mark)
            .map_err(|error| rustbox_kernel::NetError::new(error.to_string()))
    }
}

impl NetworkMetadataLookup for AndroidNetworkMetadataLookup {
    fn lookup_network(
        &self,
        _key: ConnectionKey,
    ) -> BoxFuture<'_, Result<NetworkMetadataInfo, NetworkMetadataError>> {
        Box::pin(async move {
            let routes = tokio::fs::read_to_string("/proc/net/route")
                .await
                .unwrap_or_default();
            let interface = routes.lines().skip(1).find_map(|line| {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                (fields.get(1) == Some(&"00000000"))
                    .then(|| fields.first().copied())
                    .flatten()
                    .map(str::to_owned)
            });
            let network_type = interface.as_deref().map(|name| {
                if name.starts_with("wlan") {
                    rustbox_types::NetworkType::Wifi
                } else if name.starts_with("rmnet")
                    || name.starts_with("ccmni")
                    || name.starts_with("pdp")
                {
                    rustbox_types::NetworkType::Cellular
                } else {
                    rustbox_types::NetworkType::Ethernet
                }
            });
            Ok(NetworkMetadataInfo {
                interface,
                wifi_ssid: None,
                wifi_bssid: None,
                network_type,
            })
        })
    }
}

impl ProcessLookup for AndroidProcessLookup {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessMetadata>, ProcessLookupError>> {
        Box::pin(async move {
            let files = match key.network {
                rustbox_types::Network::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
                rustbox_types::Network::Udp => ["/proc/net/udp", "/proc/net/udp6"],
            };
            let mut uid = None;
            let port = format!("{:04X}", key.local.port);
            for path in files {
                let Ok(table) = tokio::fs::read_to_string(path).await else {
                    continue;
                };
                uid = table.lines().skip(1).find_map(|line| {
                    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                    let local_port = fields.get(1)?.rsplit_once(':')?.1;
                    if !local_port.eq_ignore_ascii_case(&port) {
                        return None;
                    }
                    fields.get(7)?.parse::<u32>().ok()
                });
                if uid.is_some() {
                    break;
                }
            }
            let Some(uid) = uid else { return Ok(None) };
            let mut entries = tokio::fs::read_dir("/proc")
                .await
                .map_err(|error| ProcessLookupError::new(format!("read /proc: {error}")))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|error| ProcessLookupError::new(format!("scan /proc: {error}")))?
            {
                let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
                    continue;
                };
                let Ok(status) = tokio::fs::read_to_string(format!("/proc/{pid}/status")).await
                else {
                    continue;
                };
                let owns_uid = status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:"))
                    .and_then(|value| value.split_ascii_whitespace().next())
                    .and_then(|value| value.parse::<u32>().ok())
                    == Some(uid);
                if !owns_uid {
                    continue;
                }
                let cmdline = tokio::fs::read(format!("/proc/{pid}/cmdline"))
                    .await
                    .ok()
                    .and_then(|bytes| bytes.split(|byte| *byte == 0).next().map(ToOwned::to_owned))
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                let package_name = cmdline
                    .as_deref()
                    .and_then(|value| value.split(':').next())
                    .filter(|value| value.contains('.'))
                    .map(str::to_owned);
                let executable_path = tokio::fs::read_link(format!("/proc/{pid}/exe"))
                    .await
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned());
                let name = executable_path.as_deref().and_then(|path| {
                    std::path::Path::new(path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                });
                return Ok(Some(ProcessMetadata {
                    pid: Some(pid),
                    name,
                    path: executable_path,
                    package_name,
                    user_id: Some(uid),
                    user_name: None,
                }));
            }
            Ok(Some(ProcessMetadata {
                pid: None,
                name: None,
                path: None,
                package_name: None,
                user_id: Some(uid),
                user_name: None,
            }))
        })
    }
}
