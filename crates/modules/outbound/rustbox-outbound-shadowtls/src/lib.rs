//! Kernel adapter for the shared ShadowTLS stream transport.

use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, NetworkProvider, Outbound, OutboundContext, OutboundError};
use rustbox_transport::{StreamTransport, TransportContext};
use rustbox_types::{Endpoint, OutboundId};
use std::sync::Arc;

pub struct ShadowTlsOutbound {
    id: OutboundId,
    transport: Arc<dyn StreamTransport>,
    network: Arc<dyn NetworkProvider>,
}

impl ShadowTlsOutbound {
    pub fn new(
        id: OutboundId,
        transport: Arc<dyn StreamTransport>,
        network: Arc<dyn NetworkProvider>,
    ) -> Self {
        Self {
            id,
            transport,
            network,
        }
    }
}

impl Outbound for ShadowTlsOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            self.transport
                .connect(
                    TransportContext {
                        network: &*self.network,
                    },
                    target,
                )
                .await
                .map_err(|error| OutboundError::new(error.message))
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async { Err(OutboundError::new("ShadowTLS is a TCP-only transport")) })
    }
}
