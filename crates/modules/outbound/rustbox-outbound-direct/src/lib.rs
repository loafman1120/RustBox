//! Direct outbound using the host network capability.

use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect,
};
use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, OutboundId};
use std::sync::Arc;

pub struct DirectOutbound {
    id: OutboundId,
    network: Arc<dyn NetworkProvider>,
    observability: Arc<dyn ObservabilitySink>,
}

impl DirectOutbound {
    pub fn new(id: OutboundId, network: Arc<dyn NetworkProvider>) -> Self {
        Self {
            id,
            network,
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }
}

impl Outbound for DirectOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = Some(ctx.flow.id);
        let target_text = target.to_string();

        Box::pin(async move {
            self.observability
                .emit(Event::new(
                    EventLevel::Debug,
                    "rustbox.outbound.direct",
                    flow_id,
                    EventKind::OutboundConnecting {
                        outbound: outbound.clone(),
                        target: target_text.clone(),
                    },
                ))
                .await;

            let result = self
                .network
                .connect_tcp(TcpConnect { target })
                .await
                .map_err(|err| OutboundError::new(err.message));

            match &result {
                Ok(_) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Info,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundConnected {
                                outbound,
                                target: target_text,
                            },
                        ))
                        .await;
                }
                Err(err) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Error,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundFailed {
                                outbound,
                                target: target_text,
                                error: err.message.clone(),
                            },
                        ))
                        .await;
                }
            }

            result
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
