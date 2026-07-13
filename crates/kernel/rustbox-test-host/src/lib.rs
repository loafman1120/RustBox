//! 用于测试的确定性宿主能力实现。
//!
//! 本 crate 让核心和模块测试不依赖真实 socket、真实时间或系统随机源。

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{
    BoxFuture, Clock, Entropy, EntropyError, HostInstant, NetError, NetworkProvider,
    StreamListener, TcpBind, TcpConnect, UdpBind,
};
use rustbox_types::Endpoint;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 可注入内存流和虚拟时钟的测试宿主。
#[derive(Clone, Default)]
pub struct TestHost {
    inner: Arc<Mutex<TestHostState>>,
}

impl TestHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_tcp_stream(&self, stream: MemoryStream) {
        self.inner
            .lock()
            .expect("test host lock")
            .tcp_streams
            .push_back(stream);
    }

    pub fn connected_tcp_targets(&self) -> Vec<Endpoint> {
        self.inner
            .lock()
            .expect("test host lock")
            .connected_tcp_targets
            .clone()
    }

    pub fn push_udp_socket(&self, socket: MemoryDatagramSocket) {
        self.inner
            .lock()
            .expect("test host lock")
            .udp_sockets
            .push_back(socket);
    }

    pub fn bound_udp_endpoints(&self) -> Vec<Endpoint> {
        self.inner
            .lock()
            .expect("test host lock")
            .bound_udp_endpoints
            .clone()
    }

    pub fn advance_clock(&self, millis: u64) {
        let mut state = self.inner.lock().expect("test host lock");
        state.now = state.now.saturating_add(millis);
    }
}

#[derive(Default)]
struct TestHostState {
    now: u64,
    entropy_counter: u8,
    tcp_streams: VecDeque<MemoryStream>,
    connected_tcp_targets: Vec<Endpoint>,
    udp_sockets: VecDeque<MemoryDatagramSocket>,
    bound_udp_endpoints: Vec<Endpoint>,
}

impl Clock for TestHost {
    fn now(&self) -> HostInstant {
        HostInstant::from_millis(self.inner.lock().expect("test host lock").now)
    }

    fn sleep_until(&self, _deadline: HostInstant) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl Entropy for TestHost {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        let mut state = self.inner.lock().expect("test host lock");
        for byte in output {
            *byte = state.entropy_counter;
            state.entropy_counter = state.entropy_counter.wrapping_add(1);
        }
        Ok(())
    }
}

impl NetworkProvider for TestHost {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("test host lock");
            state.connected_tcp_targets.push(request.target);
            let stream = state.tcp_streams.pop_front().unwrap_or_default();
            Ok(Box::new(stream) as Box<dyn ByteStream>)
        })
    }

    fn bind_tcp(
        &self,
        _request: TcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn rustbox_kernel::StreamListener>, NetError>> {
        Box::pin(async {
            Err(NetError::new(
                "test host does not implement tcp listeners yet",
            ))
        })
    }

    fn bind_udp(
        &self,
        request: UdpBind,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, NetError>> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("test host lock");
            state.bound_udp_endpoints.push(request.listen);
            let socket = state.udp_sockets.pop_front().unwrap_or_default();
            Ok(Box::new(socket) as Box<dyn DatagramSocket>)
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryDatagramSocket {
    inner: Arc<Mutex<MemoryDatagramState>>,
}

#[derive(Debug, Default)]
struct MemoryDatagramState {
    local: Option<Endpoint>,
    incoming: VecDeque<(Vec<u8>, Endpoint)>,
    sent: Vec<(Vec<u8>, Endpoint)>,
    closed: bool,
}

impl MemoryDatagramSocket {
    pub fn bound(local: Endpoint) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryDatagramState {
                local: Some(local),
                ..MemoryDatagramState::default()
            })),
        }
    }

    pub fn push_incoming(&self, payload: impl Into<Vec<u8>>, source: Endpoint) {
        self.inner
            .lock()
            .expect("memory datagram lock")
            .incoming
            .push_back((payload.into(), source));
    }

    pub fn sent(&self) -> Vec<(Vec<u8>, Endpoint)> {
        self.inner
            .lock()
            .expect("memory datagram lock")
            .sent
            .clone()
    }

    pub fn close(&self) {
        self.inner.lock().expect("memory datagram lock").closed = true;
    }
}

impl DatagramSocket for MemoryDatagramSocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner
            .lock()
            .expect("memory datagram lock")
            .local
            .clone()
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let mut state = self.inner.lock().expect("memory datagram lock");
        if let Some((payload, source)) = state.incoming.pop_front() {
            if payload.len() > buf.len() {
                return Poll::Ready(Err(IoError::new(
                    IoErrorKind::InvalidInput,
                    "incoming datagram exceeds receive buffer",
                )));
            }
            buf[..payload.len()].copy_from_slice(&payload);
            return Poll::Ready(Ok((payload.len(), source)));
        }
        if state.closed {
            Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "datagram socket is closed",
            )))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        let mut state = self.inner.lock().expect("memory datagram lock");
        if state.closed {
            return Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "datagram socket is closed",
            )));
        }
        state.sent.push((buf.to_vec(), target.clone()));
        Poll::Ready(Ok(buf.len()))
    }
}

#[derive(Default)]
pub struct EmptyListener;

impl StreamListener for EmptyListener {
    fn local_endpoint(&self) -> Option<Endpoint> {
        None
    }

    fn accept(&mut self) -> BoxFuture<'_, Result<(Box<dyn ByteStream>, Endpoint), NetError>> {
        Box::pin(async { Err(NetError::new("test listener has no pending streams")) })
    }
}

/// 简单内存字节流，用于 relay、outbound 和能力测试。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryStream {
    read: VecDeque<u8>,
    written: Vec<u8>,
    write_closed: bool,
}

impl MemoryStream {
    pub fn with_read_data(data: impl Into<Vec<u8>>) -> Self {
        Self {
            read: data.into().into(),
            written: Vec::new(),
            write_closed: false,
        }
    }

    pub fn written(&self) -> &[u8] {
        &self.written
    }
}

impl AsyncRead for MemoryStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut count = 0;
        while count < buf.remaining() {
            let Some(byte) = self.read.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
            count += 1;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is closed",
            )));
        }

        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::Host;
    use std::future::poll_fn;

    #[tokio::test]
    async fn memory_udp_socket_preserves_datagram_boundaries_and_targets() {
        let host = TestHost::new();
        let local = Endpoint::localhost_v4(5300);
        let source = Endpoint::new(Host::domain("dns.example"), 53);
        let socket = MemoryDatagramSocket::bound(local.clone());
        socket.push_incoming(b"answer".to_vec(), source.clone());
        host.push_udp_socket(socket.clone());

        let mut bound = host
            .bind_udp(UdpBind {
                listen: local.clone(),
            })
            .await
            .expect("bind memory udp");
        assert_eq!(bound.local_endpoint(), Some(local.clone()));
        assert_eq!(host.bound_udp_endpoints(), vec![local]);

        let mut buf = [0_u8; 16];
        let (len, peer) = poll_fn(|cx| Pin::new(&mut *bound).poll_recv_from(cx, &mut buf))
            .await
            .expect("receive memory datagram");
        assert_eq!(&buf[..len], b"answer");
        assert_eq!(peer, source);

        let target = Endpoint::new(Host::domain("resolver.example"), 53);
        let len = poll_fn(|cx| Pin::new(&mut *bound).poll_send_to(cx, b"query", &target))
            .await
            .expect("send memory datagram");
        assert_eq!(len, 5);
        assert_eq!(socket.sent(), vec![(b"query".to_vec(), target)]);
    }
}
