//! Current-target platform capability facade.
//!
//! OS selection belongs in this crate. Consumers depend only on the capability
//! traits and never name an OS-specific implementation crate.

use rustbox_host_api::{NetworkControl, PacketDeviceProvider, TransparentProxyProvider};
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

pub fn current_capabilities() -> PlatformCapabilities {
    #[cfg(target_os = "linux")]
    return PlatformCapabilities {
        platform: "Linux",
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Limited,
        transparent_proxy: CapabilitySupport::Limited,
        process_lookup: CapabilitySupport::Supported,
    };
    #[cfg(target_os = "windows")]
    return PlatformCapabilities {
        platform: "Windows",
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Supported,
        transparent_proxy: CapabilitySupport::Planned,
        process_lookup: CapabilitySupport::Supported,
    };
    #[cfg(target_os = "macos")]
    return PlatformCapabilities {
        platform: "macOS",
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Supported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    };
    #[allow(unreachable_code)]
    PlatformCapabilities {
        platform: "Unknown",
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    }
}

pub type TunCapabilities = (Arc<dyn PacketDeviceProvider>, Arc<dyn NetworkControl>);

pub const SUPPORTS_TUN: bool = cfg!(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos"
));

pub fn tun_capabilities() -> Option<TunCapabilities> {
    #[cfg(target_os = "linux")]
    {
        let platform = Arc::new(rustbox_platform_linux::LinuxPlatform::new());
        return Some((platform.clone(), platform));
    }
    #[cfg(target_os = "windows")]
    {
        let platform = Arc::new(rustbox_platform_windows::WindowsPlatform::new());
        return Some((platform.clone(), platform));
    }
    #[cfg(target_os = "macos")]
    {
        let platform = Arc::new(rustbox_platform_macos::MacosPlatform::new());
        return Some((platform.clone(), platform));
    }
    #[allow(unreachable_code)]
    None
}

pub fn transparent_proxy_provider() -> Option<Arc<dyn TransparentProxyProvider>> {
    #[cfg(target_os = "linux")]
    {
        return Some(Arc::new(rustbox_platform_linux::LinuxPlatform::new()));
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn declared_tun_support_matches_factory() {
        assert_eq!(super::SUPPORTS_TUN, super::tun_capabilities().is_some());
    }
}
