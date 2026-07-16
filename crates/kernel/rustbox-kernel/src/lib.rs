//! RustBox 可移植内核。
//!
//! 本 crate 位于 L2 Kernel，负责 Flow 生命周期、元数据增强、路由决策、
//! 出站分发和通用 relay。它不依赖具体运行时、平台适配器或协议入口。

pub mod host;
pub use host::*;

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoErrorKind};
use rustbox_route::Router;
use rustbox_types::{Endpoint, FlowId, FlowMeta, Network, OutboundId, RejectReason, RouteDecision};
use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// 数据面进入内核后的基本工作单元。
pub struct Flow {
    pub meta: FlowMeta,
    pub payload: FlowPayload,
}

/// Flow 的载荷形态。字节流、数据报保持分离，避免把 UDP 伪装成 TCP。
pub enum FlowPayload {
    Stream(Box<dyn ByteStream>),
    Datagram(Box<dyn DatagramSocket>),
}

/// inbound 向内核提交 Flow 的入口。
pub trait FlowSink: Send + Sync {
    fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>>;
}

/// 长生命周期组件的统一生命周期接口。
pub trait Service: Send {
    fn start(&mut self, ctx: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>>;

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>>;
}

#[derive(Clone, Default)]
pub struct ServiceContext {
    pub generation: u64,
    pub accept_tasks: TaskScope,
    pub session_tasks: TaskScope,
}

/// inbound 只负责接入外部连接并创建 Flow，不参与路由选择。
pub trait Inbound: Service {
    fn id(&self) -> rustbox_types::InboundId;
}

/// outbound 执行出站请求，但不拥有路由规则。
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

/// Flow 增强阶段在路由前运行，可观察并原样重放载荷前缀，同时补充元数据。
pub trait MetadataEnricher: Send + Sync {
    fn name(&self) -> &'static str;

    fn enrich(&self, flow: Flow) -> impl Future<Output = Result<Flow, InspectError>> + Send;
}

/// No-op stage used when a runtime does not install inspection.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEnricher;

impl MetadataEnricher for NoopEnricher {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn enrich(&self, flow: Flow) -> Result<Flow, InspectError> {
        Ok(flow)
    }
}

/// RustBox 的可移植执行核心，持有路由器、增强器、出站集合和观测端口。
pub struct Engine<E = NoopEnricher> {
    router: Box<dyn Router>,
    enrichment: E,
    outbounds: HashMap<OutboundId, Box<dyn Outbound>>,
    observability: Arc<dyn ObservabilitySink>,
}

impl Engine<NoopEnricher> {
    pub fn builder(router: Box<dyn Router>) -> EngineBuilder<NoopEnricher> {
        EngineBuilder {
            router,
            enrichment: NoopEnricher,
            outbounds: HashMap::new(),
            observability: Arc::new(NoopObservabilitySink),
        }
    }
}

impl<E: MetadataEnricher> Engine<E> {
    pub fn route(&self, meta: &FlowMeta) -> RouteDecision {
        self.router.route(meta)
    }

    pub fn outbound_count(&self) -> usize {
        self.outbounds.len()
    }

    async fn execute_flow(&self, flow: Flow) -> Result<FlowOutcome, FlowError> {
        let flow_id = flow.meta.id;
        let result = self.execute_flow_inner(flow).await;
        match &result {
            Ok(outcome) => {
                if let FlowOutcome::Forwarded {
                    relay: Some(relay), ..
                } = outcome
                {
                    self.emit(
                        EventLevel::Debug,
                        "rustbox.kernel.traffic",
                        Some(flow_id),
                        EventKind::TrafficRecorded {
                            inbound_to_outbound_bytes: relay.inbound_to_outbound_bytes,
                            outbound_to_inbound_bytes: relay.outbound_to_inbound_bytes,
                        },
                    )
                    .await;
                }
                self.emit(
                    EventLevel::Info,
                    "rustbox.kernel.flow",
                    Some(flow_id),
                    EventKind::FlowCompleted {
                        outcome: format!("{outcome:?}"),
                    },
                )
                .await;
            }
            Err(err) => {
                self.emit(
                    EventLevel::Error,
                    "rustbox.kernel.flow",
                    Some(flow_id),
                    EventKind::FlowFailed {
                        error: format!("{err:?}"),
                    },
                )
                .await;
            }
        }
        result
    }

    async fn execute_flow_inner(&self, flow: Flow) -> Result<FlowOutcome, FlowError> {
        // 关键数据面路径：接收 Flow -> 增强元数据 -> 路由 -> 打开 outbound -> relay。
        self.emit(
            EventLevel::Info,
            "rustbox.kernel.flow",
            Some(flow.meta.id),
            EventKind::FlowAccepted {
                source: flow.meta.source.to_string(),
                destination: flow.meta.destination.to_string(),
                network: format!("{:?}", flow.meta.network),
            },
        )
        .await;

        let flow = resolve_datagram_destination(flow).await?;
        let flow = self
            .enrichment
            .enrich(flow)
            .await
            .map_err(FlowError::Inspect)?;
        let meta = flow.meta;
        let decision = self.router.route(&meta);
        self.emit(
            EventLevel::Debug,
            "rustbox.kernel.route",
            Some(meta.id),
            EventKind::RouteSelected {
                decision: format!("{decision:?}"),
            },
        )
        .await;

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
                    FlowPayload::Datagram(inbound_socket) => {
                        let outbound_socket = outbound
                            .open_datagram(ctx, target)
                            .await
                            .map_err(FlowError::Outbound)?;
                        let relay = relay_datagram(inbound_socket, outbound_socket)
                            .await
                            .map_err(FlowError::Relay)?;
                        Ok(FlowOutcome::Forwarded {
                            outbound: outbound_id,
                            network: Network::Udp,
                            relay: Some(relay),
                        })
                    }
                }
            }
            RouteDecision::Reject(reason) => Ok(FlowOutcome::Rejected(reason)),
            RouteDecision::Hijack(service) => Ok(FlowOutcome::Hijacked(service)),
        }
    }

    async fn emit(
        &self,
        level: EventLevel,
        target: &'static str,
        flow_id: Option<FlowId>,
        kind: EventKind,
    ) {
        self.observability
            .emit(Event::new(level, target, flow_id, kind))
            .await;
    }
}

/// SOCKS5 UDP ASSOCIATE starts with an unspecified destination; the actual
/// destination is carried by its first packet. Resolve it before inspection,
/// routing, and outbound creation, then replay that packet into the relay.
async fn resolve_datagram_destination(mut flow: Flow) -> Result<Flow, FlowError> {
    if !endpoint_is_unspecified(&flow.meta.destination) {
        return Ok(flow);
    }
    let FlowPayload::Datagram(mut socket) = flow.payload else {
        return Ok(flow);
    };
    let mut payload = vec![0_u8; 65_535];
    let (length, target) = poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, &mut payload))
        .await
        .map_err(|error| FlowError::Relay(RelayError::new(error.message)))?;
    payload.truncate(length);
    flow.meta.destination = target.clone();
    flow.payload = FlowPayload::Datagram(Box::new(ReplayDatagram {
        inner: socket,
        first: Some((payload, target)),
    }));
    Ok(flow)
}

fn endpoint_is_unspecified(endpoint: &Endpoint) -> bool {
    if endpoint.port != 0 {
        return false;
    }
    match &endpoint.host {
        rustbox_types::Host::Ip(rustbox_types::IpAddress::V4(octets)) => {
            octets.iter().all(|byte| *byte == 0)
        }
        rustbox_types::Host::Ip(rustbox_types::IpAddress::V6(octets)) => {
            octets.iter().all(|byte| *byte == 0)
        }
        rustbox_types::Host::Domain(_) => false,
    }
}

struct ReplayDatagram {
    inner: Box<dyn DatagramSocket>,
    first: Option<(Vec<u8>, Endpoint)>,
}

impl DatagramSocket for ReplayDatagram {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_endpoint()
    }

    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), rustbox_io::IoError>> {
        if let Some((payload, source)) = self.first.take() {
            if payload.len() > output.len() {
                return Poll::Ready(Err(rustbox_io::IoError::new(
                    IoErrorKind::InvalidInput,
                    "replayed UDP payload exceeds receive buffer",
                )));
            }
            output[..payload.len()].copy_from_slice(&payload);
            return Poll::Ready(Ok((payload.len(), source)));
        }
        Pin::new(&mut *self.inner).poll_recv_from(cx, output)
    }

    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, rustbox_io::IoError>> {
        Pin::new(&mut *self.inner).poll_send_to(cx, payload, target)
    }
}

impl<E: MetadataEnricher> FlowSink for Engine<E> {
    fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>> {
        Box::pin(self.execute_flow(flow))
    }
}

/// 构造期专用 builder，用显式依赖注入替代全局上下文。
pub struct EngineBuilder<E = NoopEnricher> {
    router: Box<dyn Router>,
    enrichment: E,
    outbounds: HashMap<OutboundId, Box<dyn Outbound>>,
    observability: Arc<dyn ObservabilitySink>,
}

impl<E> EngineBuilder<E> {
    pub fn observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn with_enricher<N: MetadataEnricher>(self, enrichment: N) -> EngineBuilder<N> {
        EngineBuilder {
            router: self.router,
            enrichment,
            outbounds: self.outbounds,
            observability: self.observability,
        }
    }

    pub fn register_outbound(mut self, outbound: Box<dyn Outbound>) -> Result<Self, EngineError> {
        let id = outbound.id();
        if self.outbounds.contains_key(&id) {
            return Err(EngineError::DuplicateOutbound(id));
        }
        self.outbounds.insert(id, outbound);
        Ok(self)
    }

    pub fn build(self) -> Result<Engine<E>, EngineError> {
        Ok(Engine {
            router: self.router,
            enrichment: self.enrichment,
            outbounds: self.outbounds,
            observability: self.observability,
        })
    }
}

/// Flow 处理完成后的归一化结果，供控制面、测试和观测使用。
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

/// 通用双向流转发原语，协议模块不需要重复实现 copy loop。
pub async fn relay_stream(
    mut inbound: Box<dyn ByteStream>,
    mut outbound: Box<dyn ByteStream>,
) -> Result<RelayStats, RelayError> {
    let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map(
            |(inbound_to_outbound_bytes, outbound_to_inbound_bytes)| RelayStats {
                inbound_to_outbound_bytes,
                outbound_to_inbound_bytes,
            },
        )
        .map_err(|err| RelayError::new(err.to_string()));

    let _ = inbound.shutdown().await;
    let _ = outbound.shutdown().await;
    result
}

/// 通用双向数据报转发原语，保留每个 UDP 包的目标/来源 Endpoint。
pub async fn relay_datagram(
    mut inbound: Box<dyn DatagramSocket>,
    mut outbound: Box<dyn DatagramSocket>,
) -> Result<RelayStats, RelayError> {
    let mut inbound_to_outbound = DatagramDirection::new();
    let mut outbound_to_inbound = DatagramDirection::new();

    poll_fn(|cx| {
        loop {
            let first = poll_datagram_direction(
                cx,
                &mut *inbound,
                &mut *outbound,
                &mut inbound_to_outbound,
            );
            let first_progress = match first {
                Poll::Ready(Ok(DatagramPoll::Finished)) => {
                    return Poll::Ready(Ok(RelayStats {
                        inbound_to_outbound_bytes: inbound_to_outbound.bytes,
                        outbound_to_inbound_bytes: outbound_to_inbound.bytes,
                    }));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(DatagramPoll::Progress)) => true,
                _ => false,
            };

            let second = poll_datagram_direction(
                cx,
                &mut *outbound,
                &mut *inbound,
                &mut outbound_to_inbound,
            );
            let second_progress = match second {
                Poll::Ready(Ok(DatagramPoll::Finished)) => {
                    return Poll::Ready(Ok(RelayStats {
                        inbound_to_outbound_bytes: inbound_to_outbound.bytes,
                        outbound_to_inbound_bytes: outbound_to_inbound.bytes,
                    }));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(DatagramPoll::Progress)) => true,
                _ => false,
            };

            if first_progress || second_progress {
                continue;
            }

            return Poll::Pending;
        }
    })
    .await
}

struct DatagramDirection {
    buf: Vec<u8>,
    len: usize,
    target: Option<Endpoint>,
    bytes: u64,
}

impl DatagramDirection {
    fn new() -> Self {
        Self {
            buf: vec![0; 65_535],
            len: 0,
            target: None,
            bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatagramPoll {
    Pending,
    Progress,
    Finished,
}

fn poll_datagram_direction(
    cx: &mut Context<'_>,
    reader: &mut dyn DatagramSocket,
    writer: &mut dyn DatagramSocket,
    state: &mut DatagramDirection,
) -> Poll<Result<DatagramPoll, RelayError>> {
    loop {
        if let Some(target) = &state.target {
            match Pin::new(&mut *writer).poll_send_to(cx, &state.buf[..state.len], target) {
                Poll::Ready(Ok(written)) if written == state.len => {
                    state.bytes = state.bytes.saturating_add(written as u64);
                    state.target = None;
                    state.len = 0;
                    return Poll::Ready(Ok(DatagramPoll::Progress));
                }
                Poll::Ready(Ok(written)) => {
                    return Poll::Ready(Err(RelayError::new(format!(
                        "datagram relay wrote {written} of {} bytes",
                        state.len
                    ))));
                }
                Poll::Ready(Err(err)) if err.kind == IoErrorKind::Closed => {
                    return Poll::Ready(Ok(DatagramPoll::Finished));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(RelayError::new(err.message))),
                Poll::Pending => return Poll::Pending,
            }
        }

        match Pin::new(&mut *reader).poll_recv_from(cx, &mut state.buf) {
            Poll::Ready(Ok((len, target))) => {
                state.len = len;
                state.target = Some(target);
            }
            Poll::Ready(Err(err)) if err.kind == IoErrorKind::Closed => {
                return Poll::Ready(Ok(DatagramPoll::Finished));
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(RelayError::new(err.message))),
            Poll::Pending => return Poll::Ready(Ok(DatagramPoll::Pending)),
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

    #[tokio::test]
    async fn resolves_and_replays_unspecified_udp_destination() {
        let outbound_id = OutboundId::new(NonZeroU64::new(7).expect("non-zero id"));
        let target = Endpoint::localhost_v4(53);
        let mut meta = flow_meta(outbound_id);
        meta.network = Network::Udp;
        meta.destination = Endpoint::new(Host::Ip(rustbox_types::IpAddress::V4([0; 4])), 0);
        let flow = resolve_datagram_destination(Flow {
            meta,
            payload: FlowPayload::Datagram(Box::new(OneDatagram {
                packet: Some((b"dns".to_vec(), target.clone())),
            })),
        })
        .await
        .expect("resolve destination");

        assert_eq!(flow.meta.destination, target);
        let FlowPayload::Datagram(mut socket) = flow.payload else {
            panic!("expected datagram payload");
        };
        let mut output = [0_u8; 8];
        let (length, replayed_target) =
            poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, &mut output))
                .await
                .expect("read replayed datagram");
        assert_eq!(replayed_target, target);
        assert_eq!(&output[..length], b"dns");
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

    struct OneDatagram {
        packet: Option<(Vec<u8>, Endpoint)>,
    }

    impl DatagramSocket for OneDatagram {
        fn poll_recv_from(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<Result<(usize, Endpoint), rustbox_io::IoError>> {
            let Some((packet, target)) = self.packet.take() else {
                return Poll::Pending;
            };
            output[..packet.len()].copy_from_slice(&packet);
            Poll::Ready(Ok((packet.len(), target)))
        }

        fn poll_send_to(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
            _target: &Endpoint,
        ) -> Poll<Result<usize, rustbox_io::IoError>> {
            Poll::Pending
        }
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
