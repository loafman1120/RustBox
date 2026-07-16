//! Composable outbound dialing nodes.
//!
//! A node either opens a physical Tokio socket or asks an upstream outbound to
//! carry the connection.  The latter is what makes proxy chaining a graph
//! instead of a collection of protocols all pointing at the system dialer.

use crate::{
    BoxFuture, NetError, NetworkProvider, Outbound, OutboundContext, StreamListener, TcpBind,
    TcpConnect, UdpBind,
};
use rustbox_io::{ByteStream, DatagramSocket};
use std::sync::Arc;

#[derive(Clone)]
pub struct Dialer {
    route: DialRoute,
}

#[derive(Clone)]
enum DialRoute {
    Physical(Arc<dyn NetworkProvider>),
    Detour(Arc<dyn Outbound>),
}

impl Dialer {
    pub fn physical(network: Arc<dyn NetworkProvider>) -> Self {
        Self {
            route: DialRoute::Physical(network),
        }
    }

    pub fn detour(outbound: Arc<dyn Outbound>) -> Self {
        Self {
            route: DialRoute::Detour(outbound),
        }
    }
}

impl NetworkProvider for Dialer {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>> {
        Box::pin(async move {
            match &self.route {
                DialRoute::Physical(network) => network.connect_tcp(request).await,
                DialRoute::Detour(outbound) => outbound
                    .open_stream(OutboundContext::background(), request.target)
                    .await
                    .map_err(|error| NetError::new(error.message)),
            }
        })
    }

    fn bind_tcp(
        &self,
        request: TcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn StreamListener>, NetError>> {
        Box::pin(async move {
            match &self.route {
                DialRoute::Physical(network) => network.bind_tcp(request).await,
                DialRoute::Detour(_) => Err(NetError::new(
                    "a detour dialer cannot create an inbound TCP listener",
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        request: UdpBind,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, NetError>> {
        Box::pin(async move {
            match &self.route {
                DialRoute::Physical(network) => network.bind_udp(request).await,
                DialRoute::Detour(_) => Err(NetError::new(
                    "UDP detour requires a destination-aware datagram dial",
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutboundError, TcpConnect};
    use core::num::NonZeroU64;
    use rustbox_io::DatagramSocket;
    use rustbox_test_host::MemoryStream;
    use rustbox_types::{Endpoint, OutboundId};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RecordingOutbound {
        called: AtomicBool,
    }

    impl Outbound for RecordingOutbound {
        fn id(&self) -> OutboundId {
            OutboundId::new(NonZeroU64::new(1).expect("non-zero"))
        }

        fn open_stream(
            &self,
            ctx: OutboundContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
            assert!(ctx.flow.is_none());
            self.called.store(true, Ordering::Release);
            Box::pin(async { Ok(Box::new(MemoryStream::default()) as Box<dyn ByteStream>) })
        }

        fn open_datagram(
            &self,
            _ctx: OutboundContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
            Box::pin(async { Err(OutboundError::new("unused")) })
        }
    }

    #[tokio::test]
    async fn tcp_dial_is_carried_by_detour_outbound() {
        let outbound = Arc::new(RecordingOutbound {
            called: AtomicBool::new(false),
        });
        let dialer = Dialer::detour(outbound.clone());
        dialer
            .connect_tcp(TcpConnect {
                target: Endpoint::localhost_v4(443),
            })
            .await
            .expect("detour dial");
        assert!(outbound.called.load(Ordering::Acquire));
    }
}
