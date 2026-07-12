//! Linux 平台能力适配边界。
//!
//! 本 crate 只承载 Linux TUN、route control、redirect/TPROXY 和进程查询的
//! 平台边界。当前只接入 `tun-rs` packet device；netlink、nftables 和进程
//! 查询会继续隔离在这里，portable kernel 和协议模块不直接看到 OS 细节。

use net_route::{Handle as RouteHandle, Route};
use rustbox_host_api::{
    AcceptedTransparentStream, BoxFuture, ConnectionKey, InterfaceRef, NetworkControl,
    NetworkControlError, NetworkLease, NetworkOperation, NetworkTransaction, PacketDeviceConfig,
    PacketDeviceError, PacketDeviceInfo, PacketDeviceLease, PacketDeviceProvider, ProcessInfo,
    ProcessLookup, ProcessLookupError, RollbackPolicy, TransparentProxyError,
    TransparentProxyProvider, TransparentStreamListener, TransparentTcpBind,
};
use rustbox_io::PacketDevice;
use rustbox_io::{IoError, IoErrorKind};
use rustbox_types::IpAddress;
use rustbox_types::{Endpoint, Host};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
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

fn linux_capability_matrix() -> LinuxCapabilityMatrix {
    LinuxCapabilityMatrix {
        tcp_udp: CapabilitySupport::Supported,
        packet_device: CapabilitySupport::Supported,
        route_control: CapabilitySupport::Limited,
        transparent_proxy: CapabilitySupport::Limited,
        process_lookup: CapabilitySupport::Supported,
    }
}

fn process_lookup_status_message() -> &'static str {
    "Linux process lookup uses ss process ownership data"
}

mod network_control;
mod packet_device;
mod process;
mod transparent;
