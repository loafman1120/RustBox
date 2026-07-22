//! Current-target platform capability facade.
//!
//! This is the only place where an operating-system implementation is
//! selected. Consumers depend on this crate and never name a platform module.

use rustbox_kernel::{
    NetworkControl, NetworkMetadataLookup, NetworkProviderFactory, PacketDeviceProvider,
    ProcessLookup, TokioNetworkProviderFactory, TransparentProxyProvider,
};
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySupport {
    Supported,
    Limited,
    Planned,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    pub platform: &'static str,
    pub tcp_udp: CapabilitySupport,
    pub packet_device: CapabilitySupport,
    pub route_control: CapabilitySupport,
    pub transparent_proxy: CapabilitySupport,
    pub process_lookup: CapabilitySupport,
    pub strict_route_requires_interface_binding: bool,
}

impl fmt::Display for PlatformCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.platform)
    }
}

pub type TunCapabilities = (Arc<dyn PacketDeviceProvider>, Arc<dyn NetworkControl>);

#[cfg(target_os = "linux")]
#[path = "platform/linux/lib.rs"]
mod current;

#[cfg(target_os = "windows")]
#[path = "platform/windows/lib.rs"]
mod current;

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
mod current;

#[cfg(target_os = "android")]
#[path = "platform/android.rs"]
mod current;

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "android"
)))]
mod current {
    use super::*;

    pub(super) const CAPABILITIES: PlatformCapabilities = PlatformCapabilities {
        platform: "Unknown",
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
        strict_route_requires_interface_binding: false,
    };

    pub(super) fn tun() -> Option<TunCapabilities> {
        None
    }

    pub(super) fn transparent() -> Option<Arc<dyn TransparentProxyProvider>> {
        None
    }

    pub(super) fn process() -> Option<Arc<dyn ProcessLookup>> {
        None
    }

    pub(super) fn network_metadata() -> Option<Arc<dyn NetworkMetadataLookup>> {
        None
    }

    pub(super) fn socket_policy() -> Arc<dyn rustbox_kernel::TokioSocketPolicy> {
        Arc::new(rustbox_kernel::DefaultTokioSocketPolicy)
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
}

pub const SUPPORTS_TUN: bool = matches!(
    current::CAPABILITIES.packet_device,
    CapabilitySupport::Supported | CapabilitySupport::Limited
);

pub fn current_capabilities() -> PlatformCapabilities {
    current::CAPABILITIES
}

pub fn tun_capabilities() -> Option<TunCapabilities> {
    current::tun()
}

pub fn transparent_proxy_provider() -> Option<Arc<dyn TransparentProxyProvider>> {
    current::transparent()
}

pub fn process_lookup_provider() -> Option<Arc<dyn ProcessLookup>> {
    current::process()
}

pub fn network_metadata_provider() -> Option<Arc<dyn NetworkMetadataLookup>> {
    current::network_metadata()
}

pub fn network_provider_factory() -> Arc<dyn NetworkProviderFactory> {
    Arc::new(TokioNetworkProviderFactory::new(current::socket_policy()))
}

/// Returns the current physical default interface. Windows returns the adapter
/// friendly name expected by socket2-ext; callers rebuild after a native
/// network-change notification.
pub fn default_route_interface() -> Option<rustbox_kernel::InterfaceRef> {
    current::default_route_interface()
}

/// Returns the default physical interface index captured before TUN routes are
/// installed. Packet-oriented capabilities such as ICMP use the numeric index.
pub fn default_route_interface_index() -> Option<u32> {
    current::default_route_interface_index()
}

/// Recover an abandoned Windows network lease. This is public so the small
/// out-of-process watchdog can execute the same idempotent undo path used at
/// the next client start.
pub async fn recover_stale_network_state() -> Result<(), String> {
    current::recover_stale_network_state().await
}

/// Native network-change subscription used by long-lived desktop clients.
/// The Windows implementation is backed by IP Helper notifications through
/// `netwatcher`; no polling or shell process is involved.
#[cfg(target_os = "windows")]
pub struct NetworkChangeMonitor {
    receiver: tokio::sync::mpsc::UnboundedReceiver<()>,
    _handle: netwatcher::WatchHandle,
}

#[cfg(target_os = "windows")]
impl NetworkChangeMonitor {
    pub async fn changed(&mut self) -> bool {
        self.receiver.recv().await.is_some()
    }
}

#[cfg(target_os = "windows")]
pub fn network_change_monitor() -> Result<Option<NetworkChangeMonitor>, String> {
    let physical = match netdev::get_default_interface() {
        Ok(interface) => interface,
        Err(_) => return Ok(None),
    };
    let physical_index = physical.index;
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let handle = netwatcher::watch_interfaces_with_callback(move |update| {
        if update.is_initial {
            return;
        }
        let physical_changed = update.diff.removed.contains(&physical_index)
            || update.diff.modified.contains_key(&physical_index);
        let physical_added = update.diff.added.iter().any(|index| {
            update
                .interfaces
                .get(index)
                .is_some_and(|interface| !interface.name.to_ascii_lowercase().contains("rustbox"))
        });
        if physical_changed || physical_added {
            let _ = sender.send(());
        }
    })
    .map_err(|error| error.to_string())?;
    Ok(Some(NetworkChangeMonitor {
        receiver,
        _handle: handle,
    }))
}

#[cfg(not(target_os = "windows"))]
pub struct NetworkChangeMonitor;

#[cfg(not(target_os = "windows"))]
impl NetworkChangeMonitor {
    pub async fn changed(&mut self) -> bool {
        std::future::pending().await
    }
}

#[cfg(not(target_os = "windows"))]
pub fn network_change_monitor() -> Result<Option<NetworkChangeMonitor>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    #[test]
    fn declared_tun_support_matches_factory() {
        assert_eq!(super::SUPPORTS_TUN, super::tun_capabilities().is_some());
    }
}
