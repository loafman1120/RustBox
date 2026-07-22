use rustbox_kernel::{
    NetworkControl, NetworkMetadataLookup, NetworkProviderFactory, PacketDeviceProvider,
    ProcessLookup, TransparentProxyProvider,
};
use std::sync::Arc;

/// Host capabilities consumed while composing a RustBox runtime.
///
/// The default preserves the CLI/desktop behavior. Mobile embeddings can
/// replace individual ports with adapters backed by `VpnService`,
/// `NEPacketTunnelFlow`, or host callbacks. The value is retained by
/// [`crate::RustBox`] and reused for restart and reload.
#[derive(Clone)]
pub struct RuntimeCapabilities {
    pub(crate) network: Arc<dyn NetworkProviderFactory>,
    pub(crate) packet_device: Option<Arc<dyn PacketDeviceProvider>>,
    pub(crate) network_control: Option<Arc<dyn NetworkControl>>,
    pub(crate) transparent_proxy: Option<Arc<dyn TransparentProxyProvider>>,
    pub(crate) process_lookup: Option<Arc<dyn ProcessLookup>>,
    pub(crate) network_metadata: Option<Arc<dyn NetworkMetadataLookup>>,
}

impl RuntimeCapabilities {
    pub fn with_network(mut self, factory: Arc<dyn NetworkProviderFactory>) -> Self {
        self.network = factory;
        self
    }

    pub fn with_tun(
        mut self,
        packet_device: Arc<dyn PacketDeviceProvider>,
        network_control: Arc<dyn NetworkControl>,
    ) -> Self {
        self.packet_device = Some(packet_device);
        self.network_control = Some(network_control);
        self
    }

    pub fn with_transparent_proxy(mut self, provider: Arc<dyn TransparentProxyProvider>) -> Self {
        self.transparent_proxy = Some(provider);
        self
    }

    pub fn with_process_lookup(mut self, lookup: Arc<dyn ProcessLookup>) -> Self {
        self.process_lookup = Some(lookup);
        self
    }

    pub fn with_network_metadata(mut self, lookup: Arc<dyn NetworkMetadataLookup>) -> Self {
        self.network_metadata = Some(lookup);
        self
    }
}

impl Default for RuntimeCapabilities {
    fn default() -> Self {
        let tun = rustbox_platform::tun_capabilities();
        Self {
            network: rustbox_platform::network_provider_factory(),
            packet_device: tun.as_ref().map(|(provider, _)| provider.clone()),
            network_control: tun.map(|(_, control)| control),
            transparent_proxy: rustbox_platform::transparent_proxy_provider(),
            process_lookup: rustbox_platform::process_lookup_provider(),
            network_metadata: rustbox_platform::network_metadata_provider(),
        }
    }
}
