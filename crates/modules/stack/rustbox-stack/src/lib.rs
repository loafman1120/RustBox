//! User-space packet-to-flow stack boundary.
//!
//! A TUN `PacketDevice` enters RustBox here. The concrete adapter wraps the
//! open-source `ipstack` userspace TCP/IP stack, then translates accepted TCP
//! and UDP sessions into kernel `Flow`s.

use core::pin::Pin;
use core::task::{Context, Poll};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use rustbox_io::{DatagramSocket, IoError, PacketDevice};
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NoopObservabilitySink, ObservabilitySink,
};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, TaskScope};
#[cfg(test)]
use rustbox_types::Host;
use rustbox_types::{Endpoint, FlowId, FlowMeta, InboundId, Network};
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
    icmp_interface_index: Option<std::num::NonZeroU32>,
}

impl PacketFlowStack {
    pub fn new(inbound: InboundId) -> Self {
        Self {
            inbound,
            observability: Arc::new(NoopObservabilitySink),
            mtu: 1500,
            interface: None,
            icmp_interface_index: None,
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

    pub fn with_icmp_interface_index(mut self, index: Option<u32>) -> Self {
        self.icmp_interface_index = index.and_then(std::num::NonZeroU32::new);
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
            let stream = match stream {
                IpStackStream::UnknownTransport(packet)
                    if self.icmp_interface_index.is_some()
                        && matches!(
                            packet.ip_protocol(),
                            etherparse::IpNumber::ICMP | etherparse::IpNumber::IPV6_ICMP
                        ) =>
                {
                    let interface_index = self.icmp_interface_index.expect("checked above");
                    let observability = self.observability.clone();
                    sessions.spawn(async move {
                        if let Err(error) = forward_icmp_echo(packet, interface_index).await {
                            observability
                                .emit(Event::new(
                                    EventLevel::Debug,
                                    "rustbox.stack.icmp",
                                    None,
                                    EventKind::Diagnostic(error.message),
                                ))
                                .await;
                        }
                    });
                    continue;
                }
                stream => stream,
            };
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

async fn forward_icmp_echo(
    packet: ipstack::IpStackUnknownTransport,
    interface_index: std::num::NonZeroU32,
) -> Result<(), StackError> {
    let destination = packet.dst_addr();
    let (identifier, sequence, payload) = match destination {
        std::net::IpAddr::V4(_) => {
            let (header, payload) = etherparse::Icmpv4Header::from_slice(packet.payload())
                .map_err(|error| StackError::new(format!("parse ICMPv4 packet: {error}")))?;
            let etherparse::Icmpv4Type::EchoRequest(echo) = header.icmp_type else {
                return Err(StackError::new("unsupported ICMPv4 control message"));
            };
            (echo.id, echo.seq, payload.to_vec())
        }
        std::net::IpAddr::V6(_) => {
            let (header, payload) = etherparse::Icmpv6Header::from_slice(packet.payload())
                .map_err(|error| StackError::new(format!("parse ICMPv6 packet: {error}")))?;
            let etherparse::Icmpv6Type::EchoRequest(echo) = header.icmp_type else {
                return Err(StackError::new("unsupported ICMPv6 control message"));
            };
            (echo.id, echo.seq, payload.to_vec())
        }
    };

    let mut builder = surge_ping::Config::builder().interface_index(interface_index);
    if destination.is_ipv6() {
        builder = builder.kind(surge_ping::ICMP::V6);
    }
    let client = surge_ping::Client::new(&builder.build())
        .map_err(|error| StackError::new(format!("open bound ICMP socket: {error}")))?;
    let mut pinger = client
        .pinger(destination, surge_ping::PingIdentifier(identifier))
        .await;
    pinger.timeout(std::time::Duration::from_secs(2));
    pinger
        .ping(surge_ping::PingSequence(sequence), &payload)
        .await
        .map_err(|error| StackError::new(format!("ICMP echo failed: {error}")))?;

    let response = build_icmp_echo_reply(
        packet.src_addr(),
        packet.dst_addr(),
        identifier,
        sequence,
        &payload,
    )?;
    packet
        .send(response)
        .map_err(|error| StackError::new(format!("inject ICMP echo reply: {error}")))
}

fn build_icmp_echo_reply(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, StackError> {
    let mut response = match (source, destination) {
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => {
            let echo = etherparse::IcmpEchoHeader {
                id: identifier,
                seq: sequence,
            };
            let mut header = etherparse::Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
            header.update_checksum(payload);
            header.to_bytes().to_vec()
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            let echo = etherparse::IcmpEchoHeader {
                id: identifier,
                seq: sequence,
            };
            etherparse::Icmpv6Header::with_checksum(
                etherparse::Icmpv6Type::EchoReply(echo),
                destination.octets(),
                source.octets(),
                payload,
            )
            .map_err(|error| StackError::new(format!("build ICMPv6 reply: {error}")))?
            .to_bytes()
            .to_vec()
        }
        _ => return Err(StackError::new("ICMP address families differ")),
    };
    response.extend_from_slice(payload);
    Ok(response)
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
    pub supports_icmp_echo: bool,
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
            let source: Endpoint = stream.local_addr().into();
            let destination: Endpoint = stream.peer_addr().into();
            Ok(Flow {
                meta: flow_meta(inbound, interface, Network::Tcp, source, destination),
                payload: FlowPayload::Stream(Box::new(stream)),
            })
        }
        IpStackStream::Udp(stream) => {
            let source: Endpoint = stream.local_addr().into();
            let destination: Endpoint = stream.peer_addr().into();
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
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
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
            .map_err(Into::into)
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
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
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
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_io::IoErrorKind;
    use rustbox_kernel::{FlowError, FlowOutcome};
    use rustbox_types::RejectReason;
    use std::net::IpAddr;
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
        let endpoint: Endpoint = "127.0.0.1:53"
            .parse::<std::net::SocketAddr>()
            .expect("socket addr")
            .into();

        assert_eq!(
            endpoint,
            Endpoint::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 53)
        );
    }

    #[test]
    fn builds_icmpv4_echo_reply_with_original_identity_and_payload() {
        let payload = b"rustbox-ping";
        let reply = build_icmp_echo_reply(
            "10.0.0.2".parse().expect("source"),
            "1.1.1.1".parse().expect("destination"),
            77,
            9,
            payload,
        )
        .expect("reply");
        let (header, reply_payload) =
            etherparse::Icmpv4Header::from_slice(&reply).expect("ICMPv4 reply");

        assert!(matches!(
            header.icmp_type,
            etherparse::Icmpv4Type::EchoReply(etherparse::IcmpEchoHeader { id: 77, seq: 9 })
        ));
        assert_eq!(reply_payload, payload);
    }

    #[test]
    fn maps_io_error_kinds() {
        assert_eq!(
            std::io::Error::from(IoError::new(IoErrorKind::Closed, "closed")).kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            IoError::from(std::io::Error::new(
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
            Endpoint::new(Host::Ip(IpAddr::from([10, 0, 0, 2])), 12_345)
        );
        assert_eq!(
            meta.destination,
            Endpoint::new(Host::Ip(IpAddr::from([1, 1, 1, 1])), 53)
        );
        assert_eq!(destination, meta.destination);
        assert_eq!(payload, b"hi");
    }
}
