use super::{
    BoxFuture, DialOptions, DomainResolver, NetError, NetworkProvider, NetworkProviderFactory,
    NetworkProviderPurpose, StreamListener, TcpBind, TcpConnect, UdpBind,
};
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::{Endpoint, Host};
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::ReadBuf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// Platform-owned socket behavior used by the portable Tokio adapter.
///
/// Implementations live in `rustbox-platform`; the kernel only coordinates
/// address resolution, socket lifetimes, and platform-neutral dial options.
pub trait TokioSocketPolicy: Send + Sync {
    fn bind_interface(
        &self,
        _socket: &Socket,
        interface: &str,
        _destination: IpAddr,
    ) -> Result<(), NetError> {
        Err(NetError::new(format!(
            "bind_interface `{interface}` is unsupported on this platform"
        )))
    }

    fn set_routing_mark(&self, _socket: &Socket, mark: u32) -> Result<(), NetError> {
        Err(NetError::new(format!(
            "routing_mark {mark} is unsupported on this platform"
        )))
    }

    fn bind_udp_socket(
        &self,
        socket: &Socket,
        requested: SocketAddr,
        options: &DialOptions,
    ) -> Result<(), NetError> {
        if let Some(mark) = options.routing_mark {
            self.set_routing_mark(socket, mark)?;
        }
        if let Some(interface) = &options.bind_interface {
            self.bind_interface(socket, interface, requested.ip())?;
        }
        bind_udp_local_address(socket, requested, options)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultTokioSocketPolicy;

impl TokioSocketPolicy for DefaultTokioSocketPolicy {}

/// RustBox 默认使用的 Tokio 网络能力实现。
#[derive(Clone)]
pub struct TokioNetworkProvider {
    options: DialOptions,
    resolver: Option<Arc<dyn DomainResolver>>,
    socket_policy: Arc<dyn TokioSocketPolicy>,
}

impl TokioNetworkProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: DialOptions) -> Self {
        Self {
            options,
            resolver: None,
            socket_policy: Arc::new(DefaultTokioSocketPolicy),
        }
    }

    pub fn with_resolver(mut self, resolver: Arc<dyn DomainResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_socket_policy(mut self, socket_policy: Arc<dyn TokioSocketPolicy>) -> Self {
        self.socket_policy = socket_policy;
        self
    }
}

impl Default for TokioNetworkProvider {
    fn default() -> Self {
        Self::with_options(DialOptions::default())
    }
}

/// Default factory used by CLI and desktop embeddings.
#[derive(Clone)]
pub struct TokioNetworkProviderFactory {
    socket_policy: Arc<dyn TokioSocketPolicy>,
}

impl TokioNetworkProviderFactory {
    pub fn new(socket_policy: Arc<dyn TokioSocketPolicy>) -> Self {
        Self { socket_policy }
    }
}

impl Default for TokioNetworkProviderFactory {
    fn default() -> Self {
        Self::new(Arc::new(DefaultTokioSocketPolicy))
    }
}

impl NetworkProviderFactory for TokioNetworkProviderFactory {
    fn create(
        &self,
        _purpose: NetworkProviderPurpose,
        options: DialOptions,
        resolver: Option<Arc<dyn DomainResolver>>,
    ) -> Arc<dyn NetworkProvider> {
        let mut provider = TokioNetworkProvider::with_options(options)
            .with_socket_policy(self.socket_policy.clone());
        if let Some(resolver) = resolver {
            provider = provider.with_resolver(resolver);
        }
        Arc::new(provider)
    }
}

impl NetworkProvider for TokioNetworkProvider {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>> {
        Box::pin(async move {
            let addresses = self.resolve_endpoint(&request.target).await?;
            let connect = connect_first(addresses, &self.options, self.socket_policy.as_ref());
            let stream = match self.options.connect_timeout {
                Some(limit) => timeout(limit, connect).await.map_err(|_| {
                    NetError::new(format!(
                        "connect to {} timed out after {limit:?}",
                        request.target
                    ))
                })??,
                None => connect.await?,
            };
            Ok(Box::new(stream) as Box<dyn ByteStream>)
        })
    }

    fn bind_tcp(
        &self,
        request: TcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn StreamListener>, NetError>> {
        Box::pin(async move {
            let addr = endpoint_to_socket_addr(&request.listen)?;
            let listener = TcpListener::bind(addr).await.map_err(net_error)?;
            Ok(Box::new(TokioTcpListener { inner: listener }) as Box<dyn StreamListener>)
        })
    }

    fn bind_udp(
        &self,
        request: UdpBind,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, NetError>> {
        Box::pin(async move {
            let addr = endpoint_to_socket_addr(&request.listen)?;
            let socket = bind_udp_socket(addr, &self.options, self.socket_policy.as_ref())?;
            Ok(Box::new(TokioUdpSocket { inner: socket }) as Box<dyn DatagramSocket>)
        })
    }
}

fn bind_udp_socket(
    address: SocketAddr,
    options: &DialOptions,
    socket_policy: &dyn TokioSocketPolicy,
) -> Result<UdpSocket, NetError> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(net_error)?;
    socket.set_nonblocking(true).map_err(net_error)?;
    socket_policy.bind_udp_socket(&socket, address, options)?;

    UdpSocket::from_std(socket.into()).map_err(net_error)
}

fn bind_udp_local_address(
    socket: &Socket,
    requested: SocketAddr,
    options: &DialOptions,
) -> Result<(), NetError> {
    let configured = if requested.is_ipv4() {
        options.inet4_bind_address
    } else {
        options.inet6_bind_address
    };
    let address = configured.map_or(requested, |source| {
        SocketAddr::new(source, requested.port())
    });
    if address.is_ipv4() != requested.is_ipv4() {
        return Err(NetError::new(
            "UDP source and listener address families differ",
        ));
    }
    socket.bind(&SockAddr::from(address)).map_err(net_error)
}

impl TokioNetworkProvider {
    async fn resolve_endpoint(&self, endpoint: &Endpoint) -> Result<Vec<SocketAddr>, NetError> {
        match &endpoint.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, endpoint.port)]),
            Host::Domain(domain) => match &self.resolver {
                Some(resolver) => resolver.resolve(domain.clone()).await.map(|addresses| {
                    addresses
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, endpoint.port))
                        .collect()
                }),
                None => tokio::net::lookup_host((domain.as_str(), endpoint.port))
                    .await
                    .map(|items| items.collect())
                    .map_err(net_error),
            },
        }
    }
}

async fn connect_first(
    addresses: Vec<SocketAddr>,
    options: &DialOptions,
    socket_policy: &dyn TokioSocketPolicy,
) -> Result<TcpStream, NetError> {
    if addresses.is_empty() {
        return Err(NetError::new("domain resolver returned no addresses"));
    }
    let mut last_error = None;
    for address in addresses {
        match connect_one(address, options, socket_policy).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| NetError::new("no address could be connected")))
}

async fn connect_one(
    address: SocketAddr,
    options: &DialOptions,
    socket_policy: &dyn TokioSocketPolicy,
) -> Result<TcpStream, NetError> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(net_error)?;
    socket.set_nonblocking(true).map_err(net_error)?;
    apply_socket_options(&socket, address.ip(), options, socket_policy)?;
    match socket.connect(&SockAddr::from(address)) {
        Ok(()) => {}
        Err(error) if connect_in_progress(&error) => {}
        Err(error) => return Err(net_error(error)),
    }
    let stream = TcpStream::from_std(socket.into()).map_err(net_error)?;
    stream.writable().await.map_err(net_error)?;
    if let Some(error) = stream.take_error().map_err(net_error)? {
        return Err(net_error(error));
    }
    Ok(stream)
}

fn apply_socket_options(
    socket: &Socket,
    destination: IpAddr,
    options: &DialOptions,
    socket_policy: &dyn TokioSocketPolicy,
) -> Result<(), NetError> {
    if let Some(interface) = &options.bind_interface {
        socket_policy.bind_interface(socket, interface, destination)?;
    }
    if let Some(mark) = options.routing_mark {
        socket_policy.set_routing_mark(socket, mark)?;
    }
    let source = match destination {
        IpAddr::V4(_) => options.inet4_bind_address,
        IpAddr::V6(_) => options.inet6_bind_address,
    };
    if let Some(source) = source {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(NetError::new(
                "source and destination address families differ",
            ));
        }
        socket
            .bind(&SockAddr::from(SocketAddr::new(source, 0)))
            .map_err(net_error)?;
    }
    if let Some(keepalive) = &options.tcp_keepalive {
        match keepalive {
            None => socket.set_keepalive(false).map_err(net_error)?,
            Some(config) => {
                socket.set_keepalive(true).map_err(net_error)?;
                let keepalive = config.interval.map_or_else(
                    || TcpKeepalive::new().with_time(config.idle),
                    |interval| {
                        TcpKeepalive::new()
                            .with_time(config.idle)
                            .with_interval(interval)
                    },
                );
                socket.set_tcp_keepalive(&keepalive).map_err(net_error)?;
            }
        }
    }
    Ok(())
}

fn connect_in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(
            error.raw_os_error(),
            // EINPROGRESS/EALREADY on macOS and Linux, plus Winsock's
            // WSAEWOULDBLOCK/WSAEINPROGRESS/WSAEALREADY.
            Some(36 | 37 | 114 | 115 | 10035 | 10036 | 10037)
        )
}

struct TokioTcpListener {
    inner: TcpListener,
}

impl StreamListener for TokioTcpListener {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(Endpoint::from)
    }

    fn accept(&mut self) -> BoxFuture<'_, Result<(Box<dyn ByteStream>, Endpoint), NetError>> {
        Box::pin(async move {
            let (stream, peer) = self.inner.accept().await.map_err(net_error)?;
            Ok((Box::new(stream) as Box<dyn ByteStream>, peer.into()))
        })
    }
}

struct TokioUdpSocket {
    inner: UdpSocket,
}

impl DatagramSocket for TokioUdpSocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(Endpoint::from)
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let mut read_buf = ReadBuf::new(buf);
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(addr)) => Poll::Ready(Ok((read_buf.filled().len(), addr.into()))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        let addr = match endpoint_to_socket_addr(target) {
            Ok(addr) => addr,
            Err(err) => {
                return Poll::Ready(Err(IoError::new(IoErrorKind::InvalidInput, err.message)));
            }
        };
        self.inner.poll_send_to(cx, buf, addr).map_err(Into::into)
    }
}

fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Result<SocketAddr, NetError> {
    endpoint.socket_addr().ok_or_else(|| match &endpoint.host {
        Host::Domain(domain) => NetError::new(format!(
            "cannot bind UDP/TCP listener to domain host {domain}"
        )),
        Host::Ip(_) => unreachable!("IP endpoint conversion must succeed"),
    })
}

fn net_error(err: io::Error) -> NetError {
    NetError::new(err.to_string())
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    #[test]
    fn recognizes_linux_nonblocking_connect_states() {
        assert!(connect_in_progress(&io::Error::from_raw_os_error(115)));
        assert!(connect_in_progress(&io::Error::from_raw_os_error(114)));
        assert!(!connect_in_progress(&io::Error::from_raw_os_error(111)));
    }
}
