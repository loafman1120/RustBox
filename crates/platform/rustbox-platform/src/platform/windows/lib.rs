//! Windows 平台能力适配边界。
//!
//! Wintun packet I/O and transactional route control live here. Transparent
//! proxy and process lookup remain explicit planned capabilities.

use net_route::{Handle as RouteHandle, Route};
use rustbox_io::IoError;
use rustbox_io::PacketDevice;
use rustbox_kernel::{
    BoxFuture, ConnectionKey, InterfaceRef, NetworkControl, NetworkControlError, NetworkLease,
    NetworkMetadataLookup, NetworkOperation, NetworkTransaction, NetworkUndo, PacketDeviceConfig,
    PacketDeviceError, PacketDeviceInfo, PacketDeviceLease, PacketDeviceProvider, ProcessLookup,
    ProcessLookupError, RollbackPolicy,
};
use rustbox_types::{IpCidr, ProcessMetadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

pub(super) const CAPABILITIES: crate::PlatformCapabilities = crate::PlatformCapabilities {
    platform: "Windows",
    tcp_udp: crate::CapabilitySupport::Supported,
    packet_device: crate::CapabilitySupport::Supported,
    route_control: crate::CapabilitySupport::Supported,
    transparent_proxy: crate::CapabilitySupport::Planned,
    process_lookup: crate::CapabilitySupport::Supported,
    strict_route_requires_interface_binding: true,
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

pub(super) fn socket_policy() -> std::sync::Arc<dyn rustbox_kernel::TokioSocketPolicy> {
    std::sync::Arc::new(socket::WindowsSocketPolicy)
}

/// Windows 平台能力集合的占位实现。
#[derive(Clone, Default)]
pub struct WindowsPlatform {
    wfp_sessions: Arc<Mutex<HashMap<u64, wfp::FilterEngine>>>,
    process_cache: Arc<Mutex<WindowsProcessCache>>,
    watchdog: Arc<Mutex<Option<std::process::Child>>>,
}

#[derive(Default)]
struct WindowsProcessCache {
    sockets: Vec<netstat2::SocketInfo>,
    sockets_updated_at: Option<std::time::Instant>,
    process_paths: HashMap<u32, (std::time::Instant, Option<String>)>,
}

impl core::fmt::Debug for WindowsPlatform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsPlatform").finish_non_exhaustive()
    }
}

impl WindowsPlatform {
    pub fn new() -> Self {
        Self::default()
    }
}

mod interface;
mod network_control;
mod network_metadata;
mod packet_device;
mod process;
mod socket;

pub(super) fn default_route_interface() -> Option<InterfaceRef> {
    interface::default_route_interface_name().map(InterfaceRef::Name)
}

pub(super) fn default_route_interface_index() -> Option<u32> {
    interface::default_route_interface_index()
}

pub(super) async fn recover_stale_network_state() -> Result<(), String> {
    let platform = WindowsPlatform::new();
    let handle = RouteHandle::new().map_err(|error| error.to_string())?;
    network_control::recover_stale_network_journal(&platform, &handle)
        .await
        .map_err(|error| error.message)
}
