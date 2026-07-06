//! Tokio-backed host capability implementation.

use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};
use rustbox_host_api::{
    BoxFuture, Clock, Entropy, EntropyError, HostInstant, NetError, NetworkProvider, SpawnError,
    StreamListener, TaskHandle, TaskName, TaskSpawner, TcpBind, TcpConnect, UdpBind,
};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::{Endpoint, Host, IpAddress};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Clone)]
pub struct TokioHost {
    inner: Arc<TokioHostInner>,
}

impl TokioHost {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TokioHostInner {
                started_at: Instant::now(),
                next_task_id: AtomicU64::new(1),
            }),
        }
    }
}

impl Default for TokioHost {
    fn default() -> Self {
        Self::new()
    }
}

struct TokioHostInner {
    started_at: Instant,
    next_task_id: AtomicU64,
}

impl NetworkProvider for TokioHost {
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
            Ok(Box::new(TokioTcpStream { inner: stream }) as Box<dyn ByteStream>)
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

impl Clock for TokioHost {
    fn now(&self) -> HostInstant {
        HostInstant::from_millis(self.inner.started_at.elapsed().as_millis() as u64)
    }

    fn sleep_until(&self, deadline: HostInstant) -> BoxFuture<'_, ()> {
        let now = self.now();
        Box::pin(async move {
            let millis = deadline.as_millis().saturating_sub(now.as_millis());
            tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
        })
    }
}

impl Entropy for TokioHost {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::getrandom(output).map_err(|err| EntropyError::new(err.to_string()))
    }
}

impl TaskSpawner for TokioHost {
    fn spawn(
        &self,
        _name: TaskName,
        task: BoxFuture<'static, ()>,
    ) -> Result<TaskHandle, SpawnError> {
        let id = self.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(task);
        Ok(TaskHandle { id })
    }
}

pub struct TokioTcpListener {
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
                Box::new(TokioTcpStream { inner: stream }) as Box<dyn ByteStream>,
                socket_addr_to_endpoint(peer),
            ))
        })
    }
}

pub struct TokioTcpStream {
    inner: TcpStream,
}

impl ByteStream for TokioTcpStream {
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

pub struct TokioUdpSocket {
    inner: UdpSocket,
}

impl DatagramSocket for TokioUdpSocket {
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
    match &endpoint.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
        Host::Domain(domain) => Err(NetError::new(format!(
            "cannot bind UDP/TCP listener to domain host {domain}"
        ))),
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
