//! Deterministic host capability implementations for tests.

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_host_api::{
    BoxFuture, Clock, Entropy, EntropyError, HostInstant, NetError, NetworkProvider,
    StreamListener, TcpBind, TcpConnect, UdpBind,
};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::Endpoint;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
    ) -> BoxFuture<'_, Result<Box<dyn rustbox_host_api::StreamListener>, NetError>> {
        Box::pin(async {
            Err(NetError::new(
                "test host does not implement tcp listeners yet",
            ))
        })
    }

    fn bind_udp(
        &self,
        _request: UdpBind,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, NetError>> {
        Box::pin(async {
            Err(NetError::new(
                "test host does not implement udp sockets yet",
            ))
        })
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryStream {
    read: VecDeque<u8>,
    written: Vec<u8>,
    closed: bool,
}

impl MemoryStream {
    pub fn with_read_data(data: impl Into<Vec<u8>>) -> Self {
        Self {
            read: data.into().into(),
            written: Vec::new(),
            closed: false,
        }
    }

    pub fn written(&self) -> &[u8] {
        &self.written
    }
}

impl ByteStream for MemoryStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        if self.closed {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Closed, "stream is closed")));
        }

        let mut count = 0;
        while count < buf.len() {
            let Some(byte) = self.read.pop_front() else {
                break;
            };
            buf[count] = byte;
            count += 1;
        }
        Poll::Ready(Ok(count))
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        if self.closed {
            return Poll::Ready(Err(IoError::new(IoErrorKind::Closed, "stream is closed")));
        }

        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}
