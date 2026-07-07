//! Shadowsocks outbound.
//!
//! Protocol framing and AEAD/2022 cipher handling are delegated to the
//! `shadowsocks` crate from shadowsocks-rust. RustBox keeps responsibility for
//! capability injection, routing integration, and observability.

use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect,
};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context as ShadowsocksContext, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as ShadowUdpSocket;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks::relay::udprelay::proxy_socket::ProxySocket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Upstream Shadowsocks proxy outbound.
pub struct ShadowsocksOutbound {
    id: OutboundId,
    server: ServerConfig,
    server_endpoint: Endpoint,
    network: Arc<dyn NetworkProvider>,
    context: SharedContext,
    observability: Arc<dyn ObservabilitySink>,
}

impl ShadowsocksOutbound {
    pub fn new(
        id: OutboundId,
        server_endpoint: Endpoint,
        method: &str,
        password: &str,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self, ShadowsocksConfigError> {
        let cipher = CipherKind::from_str(method).map_err(|_| ShadowsocksConfigError {
            message: format!("unsupported shadowsocks method `{method}`"),
        })?;
        let server = ServerConfig::new(
            endpoint_to_address(&server_endpoint),
            password.to_string(),
            cipher,
        )
        .map_err(|err| ShadowsocksConfigError {
            message: err.to_string(),
        })?;

        Ok(Self {
            id,
            server,
            server_endpoint,
            network,
            context: ShadowsocksContext::new_shared(ServerType::Local),
            observability: Arc::new(NoopObservabilitySink),
        })
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksConfigError {
    pub message: String,
}

impl Outbound for ShadowsocksOutbound {
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

            let result = async {
                let server_stream = self
                    .network
                    .connect_tcp(TcpConnect {
                        target: self.server_endpoint.clone(),
                    })
                    .await
                    .map_err(|err| OutboundError::new(err.message))?;
                let stream = ProxyClientStream::from_stream(
                    self.context.clone(),
                    RustBoxAsyncStream::new(server_stream),
                    &self.server,
                    endpoint_to_address(&target),
                );
                Ok(Box::new(AsyncIoByteStream::new(stream)) as Box<dyn ByteStream>)
            }
            .await;

            match result {
                Ok(stream) => {
                    self.emit_connected(flow_id, outbound, target_text).await;
                    Ok(stream)
                }
                Err(err) => {
                    self.emit_failed(flow_id, outbound, target_text, &err).await;
                    Err(err)
                }
            }
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

            let result = ProxySocket::connect(self.context.clone(), &self.server)
                .await
                .map(|socket| {
                    Box::new(ShadowsocksDatagramSocket::new(socket)) as Box<dyn DatagramSocket>
                })
                .map_err(|err| OutboundError::new(err.to_string()));

            match result {
                Ok(socket) => {
                    self.emit_connected(flow_id, outbound, target_text).await;
                    Ok(socket)
                }
                Err(err) => {
                    self.emit_failed(flow_id, outbound, target_text, &err).await;
                    Err(err)
                }
            }
        })
    }
}

impl ShadowsocksOutbound {
    async fn emit_connecting(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.outbound.shadowsocks",
                flow_id,
                EventKind::OutboundConnecting { outbound, target },
            ))
            .await;
    }

    async fn emit_connected(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Info,
                "rustbox.outbound.shadowsocks",
                flow_id,
                EventKind::OutboundConnected { outbound, target },
            ))
            .await;
    }

    async fn emit_failed(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
        err: &OutboundError,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Error,
                "rustbox.outbound.shadowsocks",
                flow_id,
                EventKind::OutboundFailed {
                    outbound,
                    target,
                    error: err.message.clone(),
                },
            ))
            .await;
    }
}

struct ShadowsocksDatagramSocket {
    inner: ProxySocket<ShadowUdpSocket>,
    recv_buf: Vec<u8>,
}

impl ShadowsocksDatagramSocket {
    fn new(inner: ProxySocket<ShadowUdpSocket>) -> Self {
        Self {
            inner,
            recv_buf: vec![0; 65_535],
        }
    }
}

impl DatagramSocket for ShadowsocksDatagramSocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(socket_addr_to_endpoint)
    }

    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let this = &mut *self;
        let mut read_buf = ReadBuf::new(&mut this.recv_buf);
        match this.inner.poll_recv(cx, &mut read_buf) {
            Poll::Ready(Ok((payload_len, target, packet_len))) => {
                if payload_len > packet_len || packet_len > read_buf.filled().len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "shadowsocks UDP payload length exceeds packet buffer",
                    )));
                }
                let payload = &read_buf.filled()[..payload_len];
                if payload.len() > buf.len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "shadowsocks UDP payload exceeds relay buffer",
                    )));
                }
                buf[..payload.len()].copy_from_slice(payload);
                Poll::Ready(Ok((payload.len(), address_to_endpoint(target))))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err.into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        self.get_mut()
            .inner
            .poll_send(&endpoint_to_address(target), buf, cx)
            .map_err(|err| io_error(err.into()))
    }
}

struct RustBoxAsyncStream {
    inner: Box<dyn ByteStream>,
}

impl RustBoxAsyncStream {
    fn new(inner: Box<dyn ByteStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for RustBoxAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let dst = buf.initialize_unfilled();
        match Pin::new(&mut *self.inner).poll_read(cx, dst) {
            Poll::Ready(Ok(read)) => {
                buf.set_filled(before + read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error_to_std(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for RustBoxAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner)
            .poll_write(cx, buf)
            .map_err(io_error_to_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner)
            .poll_flush(cx)
            .map_err(io_error_to_std)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner)
            .poll_close(cx)
            .map_err(io_error_to_std)
    }
}

struct AsyncIoByteStream<T> {
    inner: T,
}

impl<T> AsyncIoByteStream<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> ByteStream for AsyncIoByteStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(io_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(io_error)
    }
}

fn endpoint_to_address(endpoint: &Endpoint) -> Address {
    match &endpoint.host {
        Host::Domain(domain) => Address::DomainNameAddress(domain.clone(), endpoint.port),
        Host::Ip(ip) => Address::SocketAddress(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
    }
}

fn address_to_endpoint(address: Address) -> Endpoint {
    match address {
        Address::DomainNameAddress(domain, port) => Endpoint::new(Host::Domain(domain), port),
        Address::SocketAddress(addr) => socket_addr_to_endpoint(addr),
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

fn io_error_to_std(err: IoError) -> io::Error {
    let kind = match err.kind {
        IoErrorKind::Closed => io::ErrorKind::UnexpectedEof,
        IoErrorKind::Interrupted => io::ErrorKind::Interrupted,
        IoErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        IoErrorKind::Unsupported => io::ErrorKind::Unsupported,
        IoErrorKind::Other => io::ErrorKind::Other,
    };
    io::Error::new(kind, err.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_runtime_tokio::TokioHost;
    use rustbox_types::{FlowId, FlowMeta, InboundId, Network};
    use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const METHOD: &str = "aes-128-gcm";
    const PASSWORD: &str = "test-password";

    #[tokio::test]
    async fn shadowsocks_outbound_connects_stream_through_proxy_server() {
        let (host, server) = start_shadowsocks_tcp_server().await;
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = ShadowsocksOutbound::new(outbound_id, server, METHOD, PASSWORD, host)
            .expect("create shadowsocks outbound");
        let target = Endpoint::new(Host::domain("example.test"), 443);
        let meta = flow_meta(target.clone(), Network::Tcp);

        let mut stream = outbound
            .open_stream(OutboundContext { flow: &meta }, target)
            .await
            .expect("open shadowsocks stream");
        rustbox_io::stream_write_all(&mut *stream, b"ping")
            .await
            .expect("write ping");
        let mut buf = [0_u8; 4];
        rustbox_io::stream_read(&mut *stream, &mut buf)
            .await
            .expect("read pong");

        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn shadowsocks_outbound_relays_udp_through_proxy_server() {
        let (host, server) = start_shadowsocks_udp_server().await;
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = ShadowsocksOutbound::new(outbound_id, server, METHOD, PASSWORD, host)
            .expect("create shadowsocks outbound");
        let target = Endpoint::new(Host::domain("example.test"), 443);
        let meta = flow_meta(target.clone(), Network::Udp);
        let mut socket = outbound
            .open_datagram(OutboundContext { flow: &meta }, target.clone())
            .await
            .expect("open shadowsocks datagram");

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

    #[test]
    fn rejects_unknown_shadowsocks_method() {
        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let error = match ShadowsocksOutbound::new(
            outbound_id,
            Endpoint::localhost_v4(8388),
            "not-a-method",
            PASSWORD,
            host,
        ) {
            Ok(_) => panic!("expected unknown shadowsocks method to fail"),
            Err(error) => error,
        };

        assert!(error.message.contains("unsupported shadowsocks method"));
    }

    async fn start_shadowsocks_tcp_server() -> (Arc<TokioHost>, Endpoint) {
        let host = Arc::new(TokioHost::new());
        let config = server_config(Endpoint::localhost_v4(0));
        let context = ShadowsocksContext::new_shared(ServerType::Server);
        let listener = ProxyListener::bind(context, &config)
            .await
            .expect("bind shadowsocks tcp listener");
        let server = socket_addr_to_endpoint(listener.local_addr().expect("server local addr"));

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept shadowsocks tcp");
            let target = stream.handshake().await.expect("shadowsocks handshake");
            assert_eq!(
                address_to_endpoint(target),
                Endpoint::new(Host::domain("example.test"), 443)
            );

            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).await.expect("server read ping");
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.expect("server write pong");
        });

        (host, server)
    }

    async fn start_shadowsocks_udp_server() -> (Arc<TokioHost>, Endpoint) {
        let host = Arc::new(TokioHost::new());
        let config = server_config(Endpoint::localhost_v4(0));
        let context = ShadowsocksContext::new_shared(ServerType::Server);
        let socket = ProxySocket::bind(context, &config)
            .await
            .expect("bind shadowsocks udp socket");
        let server = socket_addr_to_endpoint(socket.local_addr().expect("server local addr"));

        tokio::spawn(async move {
            let mut buf = vec![0_u8; 65_535];
            let (len, peer, target, _) = socket.recv_from(&mut buf).await.expect("server recv udp");
            assert_eq!(&buf[..len], b"ping");
            assert_eq!(
                address_to_endpoint(target.clone()),
                Endpoint::new(Host::domain("example.test"), 443)
            );
            socket
                .send_to(peer, &target, b"pong")
                .await
                .expect("server send udp");
        });

        (host, server)
    }

    fn server_config(endpoint: Endpoint) -> ServerConfig {
        let method = CipherKind::from_str(METHOD).expect("parse method");
        ServerConfig::new(endpoint_to_address(&endpoint), PASSWORD.to_string(), method)
            .expect("server config")
    }

    fn flow_meta(destination: Endpoint, network: Network) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero flow id")),
            network,
            source: Endpoint::localhost_v4(12000),
            destination,
            inbound: InboundId::new(NonZeroU64::new(2).expect("non-zero inbound id")),
            domain: None,
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
