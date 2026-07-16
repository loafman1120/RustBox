//! Outbound decorator for the shared Mux.Cool session pool.

use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError};
use rustbox_transport::MuxCoolPool;
use rustbox_types::{Endpoint, OutboundId};

pub struct MuxOutbound {
    id: OutboundId,
    pool: MuxCoolPool,
}

impl MuxOutbound {
    pub fn new(id: OutboundId, pool: MuxCoolPool) -> Self {
        Self { id, pool }
    }
}

impl Outbound for MuxOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            self.pool
                .open(target)
                .await
                .map_err(|error| OutboundError::new(error.message))
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            self.pool
                .open_datagram(target)
                .await
                .map_err(|error| OutboundError::new(error.message))
        })
    }
}
