//! Linux 平台能力适配边界。
//!
//! 本 crate 只承载 Linux TUN、route control、redirect/TPROXY 和进程查询的
//! 平台边界。当前只接入 `tun-rs` packet device；netlink、nftables 和进程
//! 查询会继续隔离在这里，portable kernel 和协议模块不直接看到 OS 细节。

#[cfg(target_os = "linux")]
use net_route::{Handle as RouteHandle, Route};
#[cfg(target_os = "linux")]
use rustbox_host_api::{AcceptedTransparentStream, TransparentRedirectMode};
use rustbox_host_api::{
    BoxFuture, ConnectionKey, NetworkControl, NetworkControlError, NetworkLease,
    NetworkTransaction, PacketDeviceConfig, PacketDeviceError, PacketDeviceLease,
    PacketDeviceProvider, ProcessInfo, ProcessLookup, ProcessLookupError, TransparentProxyError,
    TransparentProxyProvider, TransparentStreamListener, TransparentTcpBind,
};
#[cfg(target_os = "linux")]
use rustbox_host_api::{InterfaceRef, NetworkOperation, PacketDeviceInfo, RollbackPolicy};
#[cfg(target_os = "linux")]
use rustbox_io::PacketDevice;
#[cfg(target_os = "linux")]
use rustbox_io::{IoError, IoErrorKind};
#[cfg(target_os = "linux")]
use rustbox_types::IpAddress;
#[cfg(target_os = "linux")]
use rustbox_types::{Endpoint, Host};
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::pin::Pin;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::task::{Context, Poll};
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

/// Linux 平台能力集合。
///
/// 当前实现先提供 typed capability 边界和明确诊断；真实实现应在后续小步中把
/// `tun-rs`/`rtnetlink`/`nftables` 等依赖限制在本 crate 内。
#[derive(Clone, Debug, Default)]
pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn capability_matrix(&self) -> LinuxCapabilityMatrix {
        linux_capability_matrix()
    }
}

/// Linux 能力矩阵，用于组合层在启动前给出早期诊断。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxCapabilityMatrix {
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

#[cfg(target_os = "linux")]
fn linux_capability_matrix() -> LinuxCapabilityMatrix {
    LinuxCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Limited,
        transparent_proxy: CapabilitySupport::Limited,
        process_lookup: CapabilitySupport::Supported,
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_capability_matrix() -> LinuxCapabilityMatrix {
    LinuxCapabilityMatrix {
        tcp_udp: CapabilitySupport::Unsupported,
        packet_device: CapabilitySupport::Unsupported,
        route_control: CapabilitySupport::Unsupported,
        transparent_proxy: CapabilitySupport::Unsupported,
        process_lookup: CapabilitySupport::Unsupported,
    }
}

#[cfg(not(target_os = "linux"))]
fn packet_device_status_message() -> &'static str {
    "Linux packet devices are unavailable on this target"
}

#[cfg(not(target_os = "linux"))]
fn network_control_status_message() -> &'static str {
    "Linux network control is unavailable on this target"
}

#[cfg(target_os = "linux")]
fn process_lookup_status_message() -> &'static str {
    "Linux process lookup uses ss process ownership data"
}

mod network_control;
mod packet_device;
mod process;
mod transparent;
