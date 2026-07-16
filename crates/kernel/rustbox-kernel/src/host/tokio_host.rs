use super::net::{
    endpoint_to_socket_addr as try_endpoint_to_socket_addr, ip_address_to_std as ip_to_std,
    socket_addr_to_endpoint,
};
use super::{
    BoxFuture, DialOptions, DomainResolver, NetError, NetworkProvider, StreamListener, TcpBind,
    TcpConnect, UdpBind,
};
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::{Endpoint, Host};
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::ReadBuf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// RustBox 默认使用的 Tokio 网络能力实现。
#[derive(Clone, Default)]
pub struct TokioNetworkProvider {
    options: DialOptions,
    resolver: Option<std::sync::Arc<dyn DomainResolver>>,
}

impl TokioNetworkProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: DialOptions) -> Self {
        Self {
            options,
            resolver: None,
        }
    }

    pub fn with_resolver(mut self, resolver: std::sync::Arc<dyn DomainResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }
}

impl NetworkProvider for TokioNetworkProvider {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>> {
        Box::pin(async move {
            let addresses = self.resolve_endpoint(&request.target).await?;
            let connect = connect_first(addresses, &self.options);
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
            let socket = UdpSocket::bind(addr).await.map_err(net_error)?;
            Ok(Box::new(TokioUdpSocket { inner: socket }) as Box<dyn DatagramSocket>)
        })
    }
}

impl TokioNetworkProvider {
    async fn resolve_endpoint(&self, endpoint: &Endpoint) -> Result<Vec<SocketAddr>, NetError> {
        match &endpoint.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(ip_to_std(*ip), endpoint.port)]),
            Host::Domain(domain) => match &self.resolver {
                Some(resolver) => resolver.resolve(domain.clone()).await.map(|addresses| {
                    addresses
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip_to_std(ip), endpoint.port))
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
) -> Result<TcpStream, NetError> {
    if addresses.is_empty() {
        return Err(NetError::new("domain resolver returned no addresses"));
    }
    let mut last_error = None;
    for address in addresses {
        match connect_one(address, options).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| NetError::new("no address could be connected")))
}

async fn connect_one(address: SocketAddr, options: &DialOptions) -> Result<TcpStream, NetError> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(net_error)?;
    socket.set_nonblocking(true).map_err(net_error)?;
    apply_socket_options(&socket, address.ip(), options)?;
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
) -> Result<(), NetError> {
    if let Some(interface) = &options.bind_interface {
        bind_interface(socket, interface)?;
    }
    if let Some(mark) = options.routing_mark {
        set_routing_mark(socket, mark)?;
    }
    let source = match destination {
        IpAddr::V4(_) => options.inet4_bind_address,
        IpAddr::V6(_) => options.inet6_bind_address,
    };
    if let Some(source) = source {
        let source = ip_to_std(source);
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

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_interface(socket: &Socket, interface: &str) -> Result<(), NetError> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(net_error)
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_interface(_socket: &Socket, interface: &str) -> Result<(), NetError> {
    Err(NetError::new(format!(
        "bind_interface `{interface}` is unsupported on this platform"
    )))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn set_routing_mark(socket: &Socket, mark: u32) -> Result<(), NetError> {
    socket.set_mark(mark).map_err(net_error)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn set_routing_mark(_socket: &Socket, mark: u32) -> Result<(), NetError> {
    Err(NetError::new(format!(
        "routing_mark {mark} is supported only on Linux/Android"
    )))
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
        self.inner.local_addr().ok().map(socket_addr_to_endpoint)
    }

    fn accept(&mut self) -> BoxFuture<'_, Result<(Box<dyn ByteStream>, Endpoint), NetError>> {
        Box::pin(async move {
            let (stream, peer) = self.inner.accept().await.map_err(net_error)?;
            Ok((
                Box::new(stream) as Box<dyn ByteStream>,
                socket_addr_to_endpoint(peer),
            ))
        })
    }
}

struct TokioUdpSocket {
    inner: UdpSocket,
}

impl DatagramSocket for TokioUdpSocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(socket_addr_to_endpoint)
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let mut read_buf = ReadBuf::new(buf);
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(addr)) => {
                Poll::Ready(Ok((read_buf.filled().len(), socket_addr_to_endpoint(addr))))
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
        let addr = match endpoint_to_socket_addr(target) {
            Ok(addr) => addr,
            Err(err) => {
                return Poll::Ready(Err(IoError::new(IoErrorKind::InvalidInput, err.message)));
            }
        };
        self.inner.poll_send_to(cx, buf, addr).map_err(io_error)
    }
}

fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Result<SocketAddr, NetError> {
    try_endpoint_to_socket_addr(endpoint).ok_or_else(|| match &endpoint.host {
        Host::Domain(domain) => NetError::new(format!(
            "cannot bind UDP/TCP listener to domain host {domain}"
        )),
        Host::Ip(_) => unreachable!("IP endpoint conversion must succeed"),
    })
}

fn net_error(err: io::Error) -> NetError {
    NetError::new(err.to_string())
}

fn io_error(err: io::Error) -> IoError {
    let kind = match err.kind() {
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionAborted => IoErrorKind::Closed,
        io::ErrorKind::Interrupted => IoErrorKind::Interrupted,
        io::ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
        io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, err.to_string())
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
