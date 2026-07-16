//! User-space packet-to-flow stack boundary.
//!
//! A TUN `PacketDevice` enters RustBox here. The concrete adapter wraps the
//! open-source `ipstack` userspace TCP/IP stack, then translates accepted TCP
//! and UDP sessions into kernel `Flow`s.

use core::pin::Pin;
use core::task::{Context, Poll};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use rustbox_io::{DatagramSocket, IoError, IoErrorKind, PacketDevice};
use rustbox_kernel::net::socket_addr_to_endpoint;
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NoopObservabilitySink, ObservabilitySink,
};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, TaskScope};
use rustbox_types::{Endpoint, FlowId, FlowMeta, InboundId, Network};
#[cfg(test)]
use rustbox_types::{Host, IpAddress};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Packet device to FlowSink bridge.
pub trait NetworkStack: Send + Sync {
    fn attach(
        &mut self,
        device: Box<dyn PacketDevice>,
        sink: Arc<dyn FlowSink>,
        sessions: TaskScope,
    ) -> BoxFuture<'_, Result<(), StackError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackError {
    pub message: String,
}

impl StackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// `ipstack` backed packet-to-flow adapter.
pub struct PacketFlowStack {
    inbound: InboundId,
    observability: Arc<dyn ObservabilitySink>,
    mtu: u16,
    interface: Option<String>,
}

impl PacketFlowStack {
    pub fn new(inbound: InboundId) -> Self {
        Self {
            inbound,
            observability: Arc::new(NoopObservabilitySink),
            mtu: 1500,
            interface: None,
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.clamp(1280, u16::MAX as usize) as u16;
        self
    }

    pub fn with_interface(mut self, interface: Option<String>) -> Self {
        self.interface = interface;
        self
    }

    async fn attach_inner(
        &mut self,
        device: Box<dyn PacketDevice>,
        sink: Arc<dyn FlowSink>,
        sessions: TaskScope,
    ) -> Result<(), StackError> {
        self.emit(
            EventLevel::Info,
            EventKind::ServiceStarted {
                service: format!("packet-stack/{}", self.inbound),
            },
        )
        .await;

        let mut config = IpStackConfig::default();
        config
            .mtu(self.mtu)
            .map_err(|err| StackError::new(format!("invalid stack MTU: {err}")))?;
        let mut stack = IpStack::new(config, PacketDeviceAsyncIo::new(device));

        loop {
            let stream = stack
                .accept()
                .await
                .map_err(|err| StackError::new(format!("ipstack accept failed: {err}")))?;
            match flow_from_ipstack_stream(self.inbound, self.interface.as_deref(), stream) {
                Ok(flow) => {
                    self.emit(
                        EventLevel::Debug,
                        EventKind::ConnectionAccepted {
                            listener: format!("tun/{}", self.inbound),
                            peer: flow.meta.source.to_string(),
                        },
                    )
                    .await;
                    let flow_sink = sink.clone();
                    let observability = self.observability.clone();
                    sessions.spawn(async move {
                        if let Err(err) = flow_sink.submit(flow).await {
                            observability
                                .emit(Event::new(
                                    EventLevel::Warn,
                                    "rustbox.stack.packet",
                                    None,
                                    EventKind::Diagnostic(format!(
                                        "TUN flow dispatch failed: {err:?}"
                                    )),
                                ))
                                .await;
                        }
                    });
                }
                Err(err) => {
                    self.emit(
                        EventLevel::Warn,
                        EventKind::Diagnostic(format!("packet drop: {}", err.message)),
                    )
                    .await;
                }
            }
        }
    }

    async fn emit(&self, level: EventLevel, kind: EventKind) {
        self.observability
            .emit(Event::new(level, "rustbox.stack.packet", None, kind))
            .await;
    }
}

impl NetworkStack for PacketFlowStack {
    fn attach(
        &mut self,
        device: Box<dyn PacketDevice>,
        sink: Arc<dyn FlowSink>,
        sessions: TaskScope,
    ) -> BoxFuture<'_, Result<(), StackError>> {
        Box::pin(self.attach_inner(device, sink, sessions))
    }
}

/// Placeholder stack retained for explicit unsupported diagnostics.
#[derive(Default)]
pub struct PlannedStack;

impl PlannedStack {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkStack for PlannedStack {
    fn attach(
        &mut self,
        _device: Box<dyn PacketDevice>,
        _sink: Arc<dyn FlowSink>,
        _sessions: TaskScope,
    ) -> BoxFuture<'_, Result<(), StackError>> {
        Box::pin(async {
            Err(StackError::new(
                "packet-to-flow network stack is not implemented yet",
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackCapability {
    pub supports_tcp: bool,
    pub supports_udp: bool,
    pub supports_ipv4: bool,
    pub supports_ipv6: bool,
}

fn flow_from_ipstack_stream(
    inbound: InboundId,
    interface: Option<&str>,
    stream: IpStackStream,
) -> Result<Flow, StackError> {
    match stream {
        IpStackStream::Tcp(stream) => {
            let source = socket_addr_to_endpoint(stream.local_addr());
            let destination = socket_addr_to_endpoint(stream.peer_addr());
            Ok(Flow {
                meta: flow_meta(inbound, interface, Network::Tcp, source, destination),
                payload: FlowPayload::Stream(Box::new(stream)),
            })
        }
        IpStackStream::Udp(stream) => {
            let source = socket_addr_to_endpoint(stream.local_addr());
            let destination = socket_addr_to_endpoint(stream.peer_addr());
            Ok(Flow {
                meta: flow_meta(
                    inbound,
                    interface,
                    Network::Udp,
                    source,
                    destination.clone(),
                ),
                payload: FlowPayload::Datagram(Box::new(IpStackDatagram {
                    inner: stream,
                    destination,
                })),
            })
        }
        IpStackStream::UnknownTransport(_) => Err(StackError::new("unsupported transport packet")),
        IpStackStream::UnknownNetwork(_) => Err(StackError::new("unsupported network packet")),
    }
}

fn flow_meta(
    inbound: InboundId,
    interface: Option<&str>,
    network: Network,
    source: Endpoint,
    destination: Endpoint,
) -> FlowMeta {
    FlowMeta {
        id: FlowId::new(core::num::NonZeroU64::new(next_flow_id()).expect("non-zero flow id")),
        network,
        source,
        destination,
        inbound,
        domain: None,
        protocol_hint: None,
        platform: rustbox_types::PlatformMetadata {
            interface: interface.map(str::to_owned),
            ..Default::default()
        },
    }
}

fn next_flow_id() -> u64 {
    static NEXT_FLOW_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    NEXT_FLOW_ID
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .max(1)
}

struct PacketDeviceAsyncIo {
    device: Box<dyn PacketDevice>,
}

impl PacketDeviceAsyncIo {
    fn new(device: Box<dyn PacketDevice>) -> Self {
        Self { device }
    }
}

impl AsyncRead for PacketDeviceAsyncIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match Pin::new(&mut *self.device).poll_recv_packet(cx, dst) {
            Poll::Ready(Ok(len)) => {
                buf.advance(len);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(std_io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketDeviceAsyncIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.device)
            .poll_send_packet(cx, buf)
            .map_err(std_io_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct IpStackDatagram {
    inner: ipstack::IpStackUdpStream,
    destination: Endpoint,
}

impl DatagramSocket for IpStackDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let len = read_buf.filled().len();
                Poll::Ready(Ok((len, self.destination.clone())))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(io_error)
    }
}

fn io_error(err: std::io::Error) -> IoError {
    let kind = match err.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::UnexpectedEof => IoErrorKind::Closed,
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
            IoErrorKind::Interrupted
        }
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            IoErrorKind::InvalidInput
        }
        std::io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, err.to_string())
}

fn std_io_error(err: IoError) -> std::io::Error {
    std::io::Error::new(std_io_error_kind(err.kind), err.message)
}

fn std_io_error_kind(kind: IoErrorKind) -> std::io::ErrorKind {
    match kind {
        IoErrorKind::Closed => std::io::ErrorKind::UnexpectedEof,
        IoErrorKind::Interrupted => std::io::ErrorKind::WouldBlock,
        IoErrorKind::InvalidInput => std::io::ErrorKind::InvalidInput,
        IoErrorKind::Unsupported => std::io::ErrorKind::Unsupported,
        IoErrorKind::Other => std::io::ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_kernel::{FlowError, FlowOutcome};
    use rustbox_types::RejectReason;
    use std::sync::Mutex;

    type RecordedDatagram = (FlowMeta, Vec<u8>, Endpoint);

    struct OnePacketDevice {
        packet: Option<Vec<u8>>,
    }

    impl PacketDevice for OnePacketDevice {
        fn poll_recv_packet(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize, IoError>> {
            let Some(packet) = self.packet.take() else {
                return Poll::Pending;
            };
            buf[..packet.len()].copy_from_slice(&packet);
            Poll::Ready(Ok(packet.len()))
        }

        fn poll_send_packet(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            packet: &[u8],
        ) -> Poll<Result<usize, IoError>> {
            Poll::Ready(Ok(packet.len()))
        }
    }

    struct RecordingSink {
        sender: Mutex<Option<tokio::sync::oneshot::Sender<RecordedDatagram>>>,
    }

    impl FlowSink for RecordingSink {
        fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>> {
            Box::pin(async move {
                let Flow {
                    meta,
                    payload: FlowPayload::Datagram(mut socket),
                } = flow
                else {
                    panic!("expected UDP datagram flow");
                };
                let mut buf = [0_u8; 64];
                let (len, destination) =
                    std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, &mut buf))
                        .await
                        .expect("read UDP payload");
                if let Some(sender) = self.sender.lock().expect("recording sink lock").take() {
                    let _ = sender.send((meta, buf[..len].to_vec(), destination));
                }
                Ok(FlowOutcome::Rejected(RejectReason::Policy))
            })
        }
    }

    #[test]
    fn converts_socket_addr_to_endpoint() {
        let endpoint = socket_addr_to_endpoint("127.0.0.1:53".parse().expect("socket addr"));

        assert_eq!(
            endpoint,
            Endpoint::new(Host::Ip(IpAddress::V4([127, 0, 0, 1])), 53)
        );
    }

    #[test]
    fn maps_io_error_kinds() {
        assert_eq!(
            std_io_error_kind(IoErrorKind::Closed),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            io_error(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported"
            ))
            .kind,
            IoErrorKind::Unsupported
        );
    }

    #[tokio::test]
    async fn turns_ipv4_udp_packet_into_datagram_flow() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0x00, 0x00,
            b'h', b'i',
        ];
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sink = Arc::new(RecordingSink {
            sender: Mutex::new(Some(sender)),
        });
        let inbound = InboundId::new(core::num::NonZeroU64::new(7).expect("inbound id"));
        let mut stack = PacketFlowStack::new(inbound);
        let task = tokio::spawn(async move {
            stack
                .attach(
                    Box::new(OnePacketDevice {
                        packet: Some(packet),
                    }),
                    sink,
                    TaskScope::new(),
                )
                .await
        });

        let (meta, payload, destination) =
            tokio::time::timeout(core::time::Duration::from_secs(2), receiver)
                .await
                .expect("packet-to-flow timeout")
                .expect("recorded flow");
        task.abort();

        assert_eq!(meta.inbound, inbound);
        assert_eq!(meta.network, Network::Udp);
        assert_eq!(
            meta.source,
            Endpoint::new(Host::Ip(IpAddress::V4([10, 0, 0, 2])), 12_345)
        );
        assert_eq!(
            meta.destination,
            Endpoint::new(Host::Ip(IpAddress::V4([1, 1, 1, 1])), 53)
        );
        assert_eq!(destination, meta.destination);
        assert_eq!(payload, b"hi");
    }
}
