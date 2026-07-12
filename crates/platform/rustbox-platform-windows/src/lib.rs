//! Windows 平台能力适配边界。
//!
//! Wintun packet I/O and transactional route control live here. Transparent
//! proxy and process lookup remain explicit planned capabilities.

#[cfg(target_os = "windows")]
use net_route::{Handle as RouteHandle, Route};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, NetworkControl, NetworkControlError, NetworkLease,
    NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceLease,
    PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError,
};
#[cfg(target_os = "windows")]
use rustbox_host_api::{InterfaceRef, NetworkOperation, PacketDeviceInfo, RollbackPolicy};
#[cfg(target_os = "windows")]
use rustbox_io::PacketDevice;
#[cfg(target_os = "windows")]
use rustbox_io::{IoError, IoErrorKind};
#[cfg(target_os = "windows")]
use rustbox_types::IpAddress;
#[cfg(target_os = "windows")]
use std::pin::Pin;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::task::{Context, Poll};
#[cfg(target_os = "windows")]
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// Windows 平台能力集合的占位实现。
#[derive(Clone, Debug, Default)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn capability_matrix(&self) -> WindowsCapabilityMatrix {
        windows_capability_matrix()
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

#[cfg(target_os = "windows")]
fn windows_capability_matrix() -> WindowsCapabilityMatrix {
    WindowsCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Supported,
        transparent_proxy: CapabilitySupport::Planned,
        process_lookup: CapabilitySupport::Supported,
    }
}

#[cfg(not(target_os = "windows"))]
fn windows_capability_matrix() -> WindowsCapabilityMatrix {
    WindowsCapabilityMatrix {
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    }
}

#[cfg(not(target_os = "windows"))]
fn packet_device_status_message() -> &'static str {
    "Windows packet devices are unavailable on this target"
}

#[cfg(not(target_os = "windows"))]
fn network_control_status_message() -> &'static str {
    "Windows network control is unavailable on this target"
}

#[cfg(target_os = "windows")]
fn process_lookup_status_message() -> &'static str {
    "Windows process lookup uses Get-NetTCPConnection/Get-NetUDPEndpoint"
}

mod network_control;
mod packet_device;
mod process;
