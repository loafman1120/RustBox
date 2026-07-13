use crate::ComposeError;
use rustbox_config::ConfigError;
use rustbox_kernel::{NetworkControl, PacketDeviceProvider, TransparentProxyProvider};
use std::sync::Arc;

pub(crate) fn transparent_proxy_provider() -> Result<Arc<dyn TransparentProxyProvider>, ComposeError>
{
    rustbox_platform::transparent_proxy_provider().ok_or_else(|| {
        ComposeError::Config(ConfigError::new(
            "transparent inbound requires platform transparent-proxy capabilities",
        ))
    })
}

pub(crate) type TunPlatformCapabilities = (Arc<dyn PacketDeviceProvider>, Arc<dyn NetworkControl>);

pub(crate) fn tun_platform_capabilities() -> Result<TunPlatformCapabilities, ComposeError> {
    rustbox_platform::tun_capabilities().ok_or_else(|| {
        ComposeError::Config(ConfigError::new(
            "tun inbound requires platform packet-device capabilities",
        ))
    })
}
