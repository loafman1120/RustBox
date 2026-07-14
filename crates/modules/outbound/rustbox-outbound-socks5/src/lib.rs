//! SOCKS5 outbound。
//!
//! 本模块把 RustBox outbound 请求转成对上游 SOCKS5 代理的 CONNECT/UDP ASSOCIATE。
//! SOCKS 协议由 `fast-socks5` 执行，RustBox 只负责能力注入、观测和 trait 适配。

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use fast_socks5::client::{Config as SocksClientConfig, Socks5Datagram, Socks5Stream};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{AuthenticationMethod, new_udp_header, parse_udp_request};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect,
};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

/// 上游 SOCKS5 代理出站。
pub struct Socks5Outbound {
    id: OutboundId,
    proxy: Endpoint,
    credentials: Option<Socks5Credentials>,
    network: Arc<dyn NetworkProvider>,
    observability: Arc<dyn ObservabilitySink>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Credentials {
    pub username: String,
    pub password: String,
}

impl Socks5Outbound {
    pub fn new(id: OutboundId, proxy: Endpoint, network: Arc<dyn NetworkProvider>) -> Self {
        Self {
            id,
            proxy,
            credentials: None,
            network,
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub fn with_credentials(mut self, credentials: Socks5Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }
}

impl Outbound for Socks5Outbound {
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
            self.emit_connecting(flow_id, outbound.clone(), target_text.clone())
                .await;

            let proxy_stream = self
                .network
                .connect_tcp(TcpConnect {
                    target: self.proxy.clone(),
                })
                .await
                .map_err(|err| OutboundError::new(err.message))?;
            let auth =
                self.credentials
                    .as_ref()
                    .map(|credentials| AuthenticationMethod::Password {
                        username: credentials.username.clone(),
                        password: credentials.password.clone(),
                    });
            let mut socks_stream =
                Socks5Stream::use_stream(proxy_stream, auth, SocksClientConfig::default())
                    .await
                    .map_err(|err| OutboundError::new(err.to_string()))?;
            socks_stream
                .request(
                    fast_socks5::Socks5Command::TCPConnect,
                    endpoint_to_target_addr(&target),
                )
                .await
                .map_err(|err| OutboundError::new(err.to_string()))?;

            self.emit_result(flow_id, outbound, target_text, Ok(()))
                .await?;
            Ok(Box::new(socks_stream) as Box<dyn ByteStream>)
        })
    }

    fn open_datagram(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = Some(ctx.flow.id);
        let target_text = target.to_string();

        Box::pin(async move {
            self.emit_connecting(flow_id, outbound.clone(), target_text.clone())
                .await;

            let proxy_stream = self
                .network
                .connect_tcp(TcpConnect {
                    target: self.proxy.clone(),
                })
                .await
                .map_err(|err| OutboundError::new(err.message))?;
            let udp_socket = bind_udp_for_target(&target)
                .await
                .map_err(|err| OutboundError::new(err.to_string()))?;
            let datagram = match &self.credentials {
                Some(credentials) => {
                    Socks5Datagram::use_socket_with_password(
                        proxy_stream,
                        udp_socket,
                        &credentials.username,
                        &credentials.password,
                    )
                    .await
                }
                None => Socks5Datagram::use_socket(proxy_stream, udp_socket).await,
            }
            .map_err(|err| OutboundError::new(err.to_string()))?;

            self.emit_result(flow_id, outbound, target_text, Ok(()))
                .await?;
            Ok(Box::new(Socks5DatagramSocket::new(datagram)) as Box<dyn DatagramSocket>)
        })
    }
}

impl Socks5Outbound {
    async fn emit_connecting(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.outbound.socks5",
                flow_id,
                EventKind::OutboundConnecting { outbound, target },
            ))
            .await;
    }

    async fn emit_result(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
        result: Result<(), OutboundError>,
    ) -> Result<(), OutboundError> {
        match result {
            Ok(()) => {
                self.observability
                    .emit(Event::new(
                        EventLevel::Info,
                        "rustbox.outbound.socks5",
                        flow_id,
                        EventKind::OutboundConnected { outbound, target },
                    ))
                    .await;
                Ok(())
            }
            Err(err) => {
                self.observability
                    .emit(Event::new(
                        EventLevel::Error,
                        "rustbox.outbound.socks5",
                        flow_id,
                        EventKind::OutboundFailed {
                            outbound,
                            target,
                            error: err.message.clone(),
                        },
                    ))
                    .await;
                Err(err)
            }
        }
    }
}

struct Socks5DatagramSocket {
    inner: Socks5Datagram<Box<dyn ByteStream>>,
    recv_buf: Vec<u8>,
}

impl Socks5DatagramSocket {
    fn new(inner: Socks5Datagram<Box<dyn ByteStream>>) -> Self {
        Self {
            inner,
            recv_buf: vec![0; 65_535],
        }
    }
}

impl DatagramSocket for Socks5DatagramSocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner
            .get_ref()
            .local_addr()
            .ok()
            .map(socket_addr_to_endpoint)
    }

    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let this = &mut *self;
        let mut read_buf = ReadBuf::new(&mut this.recv_buf);
        match this.inner.get_ref().poll_recv(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let packet_len = read_buf.filled().len();
                let mut parsed = Box::pin(parse_udp_request(&this.recv_buf[..packet_len]));
                let (frag, target, data) = match ready_or_error(parsed.as_mut().poll(cx)) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        return Poll::Ready(Err(io_error(io::Error::other(err.to_string()))));
                    }
                };
                if frag != 0 {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::Unsupported,
                        "SOCKS5 UDP fragmentation is not supported",
                    )));
                }
                if data.len() > buf.len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "SOCKS5 UDP payload exceeds relay buffer",
                    )));
                }
                buf[..data.len()].copy_from_slice(data);
                Poll::Ready(Ok((data.len(), target_addr_to_endpoint(target))))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        let mut packet = match new_udp_header(endpoint_to_target_addr(target)) {
            Ok(header) => header,
            Err(err) => return Poll::Ready(Err(io_error(io::Error::other(err.to_string())))),
        };
        packet.extend_from_slice(buf);
        match self.get_mut().inner.get_ref().poll_send(cx, &packet) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn bind_udp_for_target(target: &Endpoint) -> io::Result<UdpSocket> {
    let bind = match &target.host {
        Host::Ip(IpAddress::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    UdpSocket::bind(bind).await
}

fn endpoint_to_target_addr(endpoint: &Endpoint) -> TargetAddr {
    match &endpoint.host {
        Host::Domain(domain) => TargetAddr::Domain(domain.clone(), endpoint.port),
        Host::Ip(ip) => TargetAddr::Ip(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
    }
}

fn target_addr_to_endpoint(target: TargetAddr) -> Endpoint {
    match target {
        TargetAddr::Domain(domain, port) => Endpoint::new(Host::Domain(domain), port),
        TargetAddr::Ip(addr) => socket_addr_to_endpoint(addr),
    }
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> Endpoint {
    let host = match addr.ip() {
        IpAddr::V4(ip) => Host::Ip(IpAddress::V4(ip.octets())),
        IpAddr::V6(ip) => Host::Ip(IpAddress::V6(ip.octets())),
    };
    Endpoint::new(host, addr.port())
}

fn ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

fn ready_or_error<T, E>(poll: Poll<Result<T, E>>) -> Result<T, E> {
    match poll {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fast-socks5 slice UDP parser unexpectedly returned Pending"),
    }
}

fn io_error(err: io::Error) -> IoError {
    let kind = match err.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof => IoErrorKind::Closed,
        io::ErrorKind::Interrupted => IoErrorKind::Interrupted,
        io::ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
        io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_inbound_socks5::Socks5Inbound;
    use rustbox_kernel::TokioNetworkProvider;
    use rustbox_kernel::{Engine, FlowSink, Service, ServiceContext};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_types::{FlowId, FlowMeta, InboundId, Network};
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn socks5_outbound_connects_stream_through_socks5_inbound() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_listener.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.expect("echo accept");
            let mut buf = [0_u8; 4];
            socket.read_exact(&mut buf).await.expect("echo read");
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.expect("echo write");
        });

        let (host, proxy) = start_socks5_proxy().await;
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = Socks5Outbound::new(outbound_id, proxy, host);
        let meta = flow_meta(
            outbound_id,
            Endpoint::localhost_v4(echo_addr.port()),
            Network::Tcp,
        );
        let mut stream = outbound
            .open_stream(
                OutboundContext { flow: &meta },
                Endpoint::localhost_v4(echo_addr.port()),
            )
            .await
            .expect("open socks stream");

        stream.write_all(b"ping").await.expect("write ping");
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await.expect("read pong");
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn socks5_outbound_relays_udp_through_socks5_inbound() {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_socket.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (len, peer) = echo_socket.recv_from(&mut buf).await.expect("echo recv");
            assert_eq!(&buf[..len], b"ping");
            echo_socket.send_to(b"pong", peer).await.expect("echo send");
        });

        let (host, proxy) = start_socks5_proxy().await;
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = Socks5Outbound::new(outbound_id, proxy, host.clone());
        let target = Endpoint::localhost_v4(echo_addr.port());
        let meta = flow_meta(outbound_id, target.clone(), Network::Udp);
        let mut socket = outbound
            .open_datagram(OutboundContext { flow: &meta }, target.clone())
            .await
            .expect("open socks datagram");

        datagram_send(&mut *socket, b"ping", &target)
            .await
            .expect("send ping");
        let mut buf = [0_u8; 64];
        let (len, source) = datagram_recv(&mut *socket, &mut buf)
            .await
            .expect("recv pong");
        assert_eq!(source, target);
        assert_eq!(&buf[..len], b"pong");
    }

    async fn start_socks5_proxy() -> (Arc<TokioNetworkProvider>, Endpoint) {
        let host = Arc::new(TokioNetworkProvider::new());
        let direct_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(direct_id)))
                .register_outbound(Box::new(DirectOutbound::new(direct_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = Socks5Inbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            sink,
        );
        inbound
            .start(ServiceContext::default())
            .await
            .expect("start socks5 inbound");
        (host, inbound.local_endpoint().expect("proxy endpoint"))
    }

    fn flow_meta(outbound_id: OutboundId, destination: Endpoint, network: Network) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero flow id")),
            network,
            source: Endpoint::localhost_v4(12000),
            destination,
            inbound: InboundId::new(NonZeroU64::new(2).expect("non-zero inbound id")),
            domain: Some(Host::domain(format!("outbound-{outbound_id}.test"))),
            protocol_hint: None,
        }
    }

    async fn datagram_send(
        socket: &mut dyn DatagramSocket,
        buf: &[u8],
        target: &Endpoint,
    ) -> Result<usize, IoError> {
        poll_fn(|cx| Pin::new(&mut *socket).poll_send_to(cx, buf, target)).await
    }

    async fn datagram_recv(
        socket: &mut dyn DatagramSocket,
        buf: &mut [u8],
    ) -> Result<(usize, Endpoint), IoError> {
        poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, buf)).await
    }
}
