//! Windows 平台能力适配边界。
//!
//! 当前最小代理图不需要 Windows route control 或 packet device。
//! 这些能力以显式 planned error 暴露，内核不会通过 `cfg(target_os)` 推断平台能力。

use rustbox_host_api::{
    BoxFuture, NetworkControl, NetworkControlError, NetworkLease, NetworkTransaction,
    PacketDeviceConfig, PacketDeviceError, PacketDeviceProvider,
};
use rustbox_io::PacketDevice;

/// Windows 平台能力集合的占位实现。
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

/// Windows 能力矩阵，用于向组合层或控制面声明当前支持状态。
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
