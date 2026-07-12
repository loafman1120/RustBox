//! Windows 平台能力适配边界。
//!
//! Wintun packet I/O and transactional route control live here. Transparent
//! proxy and process lookup remain explicit planned capabilities.

use net_route::{Handle as RouteHandle, Route};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, InterfaceRef, NetworkControl, NetworkControlError, NetworkLease,
    NetworkOperation, NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceInfo,
    PacketDeviceLease, PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError,
    RollbackPolicy,
};
use rustbox_io::PacketDevice;
use rustbox_io::{IoError, IoErrorKind};
use rustbox_types::IpAddress;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
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

fn windows_capability_matrix() -> WindowsCapabilityMatrix {
    WindowsCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Supported,
        transparent_proxy: CapabilitySupport::Planned,
        process_lookup: CapabilitySupport::Supported,
    }
}

fn process_lookup_status_message() -> &'static str {
    "Windows process lookup uses Get-NetTCPConnection/Get-NetUDPEndpoint"
}

mod network_control;
mod packet_device;
mod process;
