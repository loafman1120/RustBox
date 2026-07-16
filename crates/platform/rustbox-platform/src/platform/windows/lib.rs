//! Windows 平台能力适配边界。
//!
//! Wintun packet I/O and transactional route control live here. Transparent
//! proxy and process lookup remain explicit planned capabilities.

use net_route::{Handle as RouteHandle, Route};
use rustbox_io::PacketDevice;
use rustbox_io::{IoError, IoErrorKind};
use rustbox_kernel::{
    BoxFuture, ConnectionKey, InterfaceRef, NetworkControl, NetworkControlError, NetworkLease,
    NetworkMetadataLookup, NetworkOperation, NetworkTransaction, PacketDeviceConfig,
    PacketDeviceError, PacketDeviceInfo, PacketDeviceLease, PacketDeviceProvider, ProcessInfo,
    ProcessLookup, ProcessLookupError, RollbackPolicy,
};
use rustbox_types::IpAddress;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

pub(super) const CAPABILITIES: crate::PlatformCapabilities = crate::PlatformCapabilities {
    platform: "Windows",
    tcp_udp: crate::CapabilitySupport::Supported,
    packet_device: crate::CapabilitySupport::Supported,
    route_control: crate::CapabilitySupport::Supported,
    transparent_proxy: crate::CapabilitySupport::Planned,
    process_lookup: crate::CapabilitySupport::Supported,
};

pub(super) fn tun() -> Option<crate::TunCapabilities> {
    let platform = std::sync::Arc::new(WindowsPlatform::new());
    Some((platform.clone(), platform))
}

pub(super) fn transparent() -> Option<std::sync::Arc<dyn rustbox_kernel::TransparentProxyProvider>>
{
    None
}

pub(super) fn process() -> Option<std::sync::Arc<dyn ProcessLookup>> {
    Some(std::sync::Arc::new(WindowsPlatform::new()))
}

pub(super) fn network_metadata() -> Option<std::sync::Arc<dyn NetworkMetadataLookup>> {
    Some(std::sync::Arc::new(
        network_metadata::NetworkMetadataProvider::default(),
    ))
}

/// Windows 平台能力集合的占位实现。
#[derive(Clone, Debug, Default)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

fn process_lookup_status_message() -> &'static str {
    "Windows process lookup uses Get-NetTCPConnection/Get-NetUDPEndpoint"
}

mod network_control;
mod network_metadata;
mod packet_device;
mod process;
