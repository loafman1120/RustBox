//! Windows platform capability adapter boundary.
//!
//! The initial default HTTP proxy does not require Windows route control or
//! packet devices. These capabilities are explicit and currently unsupported,
//! so the kernel never infers platform support from `cfg(target_os)`.

use rustbox_host_api::{
    BoxFuture, NetworkControl, NetworkControlError, NetworkLease, NetworkTransaction,
    PacketDeviceConfig, PacketDeviceError, PacketDeviceProvider,
};
use rustbox_io::PacketDevice;

#[derive(Clone, Debug, Default)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn capability_matrix(&self) -> WindowsCapabilityMatrix {
        WindowsCapabilityMatrix {
            tcp_udp: CapabilitySupport::Supported,
            packet_device: CapabilitySupport::Planned,
            route_control: CapabilitySupport::Planned,
            transparent_proxy: CapabilitySupport::Planned,
            process_lookup: CapabilitySupport::Planned,
        }
    }
}

impl PacketDeviceProvider for WindowsPlatform {
    fn open(
        &self,
        _config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<Box<dyn PacketDevice>, PacketDeviceError>> {
        Box::pin(async {
            Err(PacketDeviceError::new(
                "Windows packet devices are not implemented yet",
            ))
        })
    }
}

impl NetworkControl for WindowsPlatform {
    fn apply(
        &self,
        _transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(async {
            Err(NetworkControlError::new(
                "Windows network control is not implemented yet",
            ))
        })
    }
}

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
