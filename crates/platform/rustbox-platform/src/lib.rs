//! Current-target platform capability facade.
//!
//! This is the only place where an operating-system implementation is
//! selected. Consumers depend on this crate and never name a platform module.

use rustbox_kernel::{
    NetworkControl, NetworkMetadataLookup, PacketDeviceProvider, ProcessLookup,
    TransparentProxyProvider,
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

#[cfg(test)]
mod tests {
    #[test]
    fn declared_tun_support_matches_factory() {
        assert_eq!(super::SUPPORTS_TUN, super::tun_capabilities().is_some());
    }
}
