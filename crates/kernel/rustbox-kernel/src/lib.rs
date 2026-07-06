//! Portable RustBox kernel skeleton.

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_host_api::BoxFuture;
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind, stream_close};
use rustbox_route::Router;
use rustbox_types::{Endpoint, FlowMeta, Network, OutboundId, RejectReason, RouteDecision};
use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::Arc;

pub fn architecture_summary() -> &'static str {
    "RustBox: portable core + capability ports + host adapters + composition root"
}

pub struct Flow {
    pub meta: FlowMeta,
    pub payload: FlowPayload,
}

pub enum FlowPayload {
    Stream(Box<dyn ByteStream>),
    Datagram(Box<dyn DatagramSocket>),
}

pub trait FlowSink: Send + Sync {
    fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>>;
}

pub trait Service: Send {
    fn start(&mut self, ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>>;

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>>;
}

#[derive(Clone, Copy)]
pub struct ServiceContext<'a> {
    pub engine_name: &'a str,
}

pub trait Inbound: Service {
    fn id(&self) -> rustbox_types::InboundId;
}

pub trait Outbound: Send + Sync {
    fn id(&self) -> OutboundId;

    fn open_stream(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>>;

    fn open_datagram(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>>;
}

#[derive(Clone, Copy)]
pub struct OutboundContext<'a> {
    pub flow: &'a FlowMeta,
}

pub trait MetadataEnricher: Send + Sync {
    fn name(&self) -> &'static str;

    fn enrich(&self, meta: FlowMeta) -> BoxFuture<'_, Result<FlowMeta, InspectError>>;
}

#[derive(Clone, Default)]
pub struct EnrichmentPipeline {
    enrichers: Vec<Arc<dyn MetadataEnricher>>,
}

impl EnrichmentPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, enricher: Arc<dyn MetadataEnricher>) {
        self.enrichers.push(enricher);
    }

    pub async fn enrich(&self, mut meta: FlowMeta) -> Result<FlowMeta, InspectError> {
        for enricher in &self.enrichers {
            meta = enricher.enrich(meta).await?;
        }
        Ok(meta)
    }
}

pub struct Engine {
    router: Box<dyn Router>,
    enrichment: EnrichmentPipeline,
    outbounds: HashMap<OutboundId, Box<dyn Outbound>>,
}

impl Engine {
    pub fn builder(router: Box<dyn Router>) -> EngineBuilder {
        EngineBuilder {
            router,
            enrichment: EnrichmentPipeline::new(),
            outbounds: HashMap::new(),
        }
    }

    pub fn route(&self, meta: &FlowMeta) -> RouteDecision {
        self.router.route(meta)
    }

    pub fn outbound_count(&self) -> usize {
        self.outbounds.len()
    }

    async fn execute_flow(&self, flow: Flow) -> Result<FlowOutcome, FlowError> {
        let meta = self
            .enrichment
            .enrich(flow.meta)
            .await
            .map_err(FlowError::Inspect)?;
        let decision = self.router.route(&meta);
        match decision {
            RouteDecision::Forward(outbound_id) => {
                let outbound = self
                    .outbounds
                    .get(&outbound_id)
                    .ok_or(FlowError::MissingOutbound(outbound_id))?;
                let target = meta.destination.clone();
                let ctx = OutboundContext { flow: &meta };

                match flow.payload {
                    FlowPayload::Stream(inbound_stream) => {
                        let outbound_stream = outbound
                            .open_stream(ctx, target)
                            .await
                            .map_err(FlowError::Outbound)?;
                        let relay = relay_stream(inbound_stream, outbound_stream)
                            .await
                            .map_err(FlowError::Relay)?;
                        Ok(FlowOutcome::Forwarded {
                            outbound: outbound_id,
                            network: Network::Tcp,
                            relay: Some(relay),
                        })
                    }
                    FlowPayload::Datagram(_socket) => {
                        let _outbound_socket = outbound
                            .open_datagram(ctx, target)
                            .await
                            .map_err(FlowError::Outbound)?;
                        Ok(FlowOutcome::Forwarded {
                            outbound: outbound_id,
                            network: Network::Udp,
                            relay: None,
                        })
                    }
                }
            }
            RouteDecision::Reject(reason) => Ok(FlowOutcome::Rejected(reason)),
            RouteDecision::Hijack(service) => Ok(FlowOutcome::Hijacked(service)),
        }
    }
}

impl FlowSink for Engine {
    fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>> {
        Box::pin(self.execute_flow(flow))
    }
}

pub struct EngineBuilder {
    router: Box<dyn Router>,
    enrichment: EnrichmentPipeline,
    outbounds: HashMap<OutboundId, Box<dyn Outbound>>,
}

impl EngineBuilder {
    pub fn register_enricher(mut self, enricher: Arc<dyn MetadataEnricher>) -> Self {
        self.enrichment.push(enricher);
        self
    }

    pub fn register_outbound(mut self, outbound: Box<dyn Outbound>) -> Result<Self, EngineError> {
        let id = outbound.id();
        if self.outbounds.contains_key(&id) {
            return Err(EngineError::DuplicateOutbound(id));
        }
        self.outbounds.insert(id, outbound);
        Ok(self)
    }

    pub fn build(self) -> Result<Engine, EngineError> {
        Ok(Engine {
            router: self.router,
            enrichment: self.enrichment,
            outbounds: self.outbounds,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowOutcome {
    Forwarded {
        outbound: OutboundId,
        network: Network,
        relay: Option<RelayStats>,
    },
    Rejected(RejectReason),
    Hijacked(rustbox_types::ServiceId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowError {
    MissingOutbound(OutboundId),
    Inspect(InspectError),
    Outbound(OutboundError),
    Relay(RelayError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineError {
    DuplicateOutbound(OutboundId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundError {
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectError {
    pub message: String,
}

impl InspectError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl OutboundError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowErrorInfo {
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceError {
    pub message: String,
}

impl ServiceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    pub inbound_to_outbound_bytes: u64,
    pub outbound_to_inbound_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayError {
    pub message: String,
}

impl RelayError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub async fn relay_stream(
    mut inbound: Box<dyn ByteStream>,
    mut outbound: Box<dyn ByteStream>,
) -> Result<RelayStats, RelayError> {
    let mut inbound_to_outbound = CopyDirection::new();
    let mut outbound_to_inbound = CopyDirection::new();

    let result = poll_fn(|cx| {
        let first =
            poll_copy_direction(cx, &mut *inbound, &mut *outbound, &mut inbound_to_outbound);
        if let Poll::Ready(Err(err)) = first {
            return Poll::Ready(Err(err));
        }

        let second =
            poll_copy_direction(cx, &mut *outbound, &mut *inbound, &mut outbound_to_inbound);
        if let Poll::Ready(Err(err)) = second {
            return Poll::Ready(Err(err));
        }

        if inbound_to_outbound.done && outbound_to_inbound.done {
            Poll::Ready(Ok(RelayStats {
                inbound_to_outbound_bytes: inbound_to_outbound.bytes,
                outbound_to_inbound_bytes: outbound_to_inbound.bytes,
            }))
        } else {
            Poll::Pending
        }
    })
    .await
    .map_err(|err| RelayError::new(err.message));

    let _ = stream_close(&mut *inbound).await;
    let _ = stream_close(&mut *outbound).await;
    result
}

struct CopyDirection {
    buf: [u8; 8192],
    pos: usize,
    cap: usize,
    done: bool,
    bytes: u64,
}

impl CopyDirection {
    fn new() -> Self {
        Self {
            buf: [0; 8192],
            pos: 0,
            cap: 0,
            done: false,
            bytes: 0,
        }
    }
}

fn poll_copy_direction(
    cx: &mut Context<'_>,
    reader: &mut dyn ByteStream,
    writer: &mut dyn ByteStream,
    state: &mut CopyDirection,
) -> Poll<Result<(), IoError>> {
    if state.done {
        return Poll::Ready(Ok(()));
    }

    loop {
        if state.pos < state.cap {
            let written =
                match Pin::new(&mut *writer).poll_write(cx, &state.buf[state.pos..state.cap]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::Closed,
                            "relay write returned zero",
                        )));
                    }
                    Poll::Ready(Ok(written)) => written,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                };
            state.pos += written;
            state.bytes += written as u64;
            continue;
        }

        state.pos = 0;
        state.cap = 0;
        match Pin::new(&mut *reader).poll_read(cx, &mut state.buf) {
            Poll::Ready(Ok(0)) => match Pin::new(&mut *writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    state.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            },
            Poll::Ready(Ok(read)) => {
                state.cap = read;
                continue;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::num::NonZeroU64;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use rustbox_route::StaticRouter;
    use rustbox_test_host::MemoryStream;
    use rustbox_types::{FlowId, Host, InboundId, Network};

    #[test]
    fn forwards_stream_flow_to_selected_outbound() {
        let outbound_id = OutboundId::new(NonZeroU64::new(7).expect("non-zero id"));
        let engine = Engine::builder(Box::new(StaticRouter::new(outbound_id)))
            .register_outbound(Box::new(FakeOutbound { id: outbound_id }))
            .expect("register outbound")
            .build()
            .expect("build engine");

        let flow = Flow {
            meta: flow_meta(outbound_id),
            payload: FlowPayload::Stream(Box::new(MemoryStream::default())),
        };

        let outcome = block_on_ready(engine.submit(flow)).expect("flow outcome");

        assert_eq!(
            outcome,
            FlowOutcome::Forwarded {
                outbound: outbound_id,
                network: Network::Tcp,
                relay: Some(RelayStats::default()),
            }
        );
    }

    fn flow_meta(outbound_id: OutboundId) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero id")),
            network: Network::Tcp,
            source: Endpoint::new(Host::domain("client.test"), 12000),
            destination: Endpoint::new(Host::domain("example.test"), 443),
            inbound: InboundId::new(NonZeroU64::new(2).expect("non-zero id")),
            domain: Some(Host::domain(format!("outbound-{outbound_id}.test"))),
            protocol_hint: None,
        }
    }

    struct FakeOutbound {
        id: OutboundId,
    }

    impl Outbound for FakeOutbound {
        fn id(&self) -> OutboundId {
            self.id
        }

        fn open_stream(
            &self,
            _ctx: OutboundContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
            Box::pin(async { Ok(Box::new(MemoryStream::default()) as Box<dyn ByteStream>) })
        }

        fn open_datagram(
            &self,
            _ctx: OutboundContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
            Box::pin(async { Err(OutboundError::new("datagram unsupported in fake outbound")) })
        }
    }

    fn block_on_ready<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
