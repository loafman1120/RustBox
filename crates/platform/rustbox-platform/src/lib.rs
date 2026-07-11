//! Current-target platform capability facade.
//!
//! OS selection belongs in this crate. Consumers depend only on the capability
//! traits and never name an OS-specific implementation crate.

use rustbox_host_api::{NetworkControl, PacketDeviceProvider, TransparentProxyProvider};
use std::sync::Arc;

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
