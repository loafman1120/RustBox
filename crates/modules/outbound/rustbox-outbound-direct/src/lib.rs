//! Direct outbound using the host network capability.

use rustbox_host_api::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, OutboundId};
use std::sync::Arc;

pub struct DirectOutbound {
    id: OutboundId,
    network: Arc<dyn NetworkProvider>,
}

impl DirectOutbound {
    pub fn new(id: OutboundId, network: Arc<dyn NetworkProvider>) -> Self {
        Self { id, network }
    }
}

impl Outbound for DirectOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            self.network
                .connect_tcp(TcpConnect { target })
                .await
                .map_err(|err| OutboundError::new(err.message))
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async { Err(OutboundError::new("direct UDP is not implemented yet")) })
    }
}
