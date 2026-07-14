use super::net::{
    endpoint_to_socket_addr as try_endpoint_to_socket_addr, ip_address_to_std as ip_to_std,
    socket_addr_to_endpoint,
};
use super::{BoxFuture, NetError, NetworkProvider, StreamListener, TcpBind, TcpConnect, UdpBind};
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::{Endpoint, Host};
use std::io;
use std::net::SocketAddr;
use tokio::io::ReadBuf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// RustBox 默认使用的 Tokio 网络能力实现。
#[derive(Clone, Default)]
pub struct TokioNetworkProvider;

impl TokioNetworkProvider {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkProvider for TokioNetworkProvider {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>> {
        Box::pin(async move {
            let stream = match request.target.host {
                Host::Domain(domain) => TcpStream::connect((domain.as_str(), request.target.port))
                    .await
                    .map_err(net_error)?,
                Host::Ip(ip) => {
                    TcpStream::connect(SocketAddr::new(ip_to_std(ip), request.target.port))
                        .await
                        .map_err(net_error)?
                }
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
