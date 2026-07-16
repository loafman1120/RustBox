use crate::protocol::{DnsQueryMeta, dns_response_addresses};
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_dns_core::ReverseDns;
use rustbox_io::{ByteStream, DatagramSocket, IoError};
use rustbox_types::Endpoint;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct ObservedStream {
    inner: Box<dyn ByteStream>,
    prefix: Vec<u8>,
    position: usize,
    query: Option<DnsQueryMeta>,
    response: Vec<u8>,
    reverse: Arc<ReverseDns>,
}
impl ObservedStream {
    pub fn new(
        inner: Box<dyn ByteStream>,
        prefix: Vec<u8>,
        query: Option<DnsQueryMeta>,
        reverse: Arc<ReverseDns>,
    ) -> Self {
        Self {
            inner,
            prefix,
            position: 0,
            query,
            response: Vec::new(),
            reverse,
        }
    }
    fn observe(&mut self) {
        let Some(query) = &self.query else { return };
        if self.response.len() < 2 {
            return;
        }
        let len = usize::from(u16::from_be_bytes([self.response[0], self.response[1]]));
        if let Some(packet) = self.response.get(2..2 + len) {
            self.reverse
                .record(&query.name, &dns_response_addresses(packet, query.id));
            self.query = None;
        }
    }
}
impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() {
            let len = buf.remaining().min(self.prefix.len() - self.position);
            buf.put_slice(&self.prefix[self.position..self.position + len]);
            self.position += len;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut *self.inner).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut *self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(len)) => {
                if self.query.is_some() && self.response.len() < 65_537 {
                    self.response.extend_from_slice(&buf[..len]);
                    self.observe();
                }
                Poll::Ready(Ok(len))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

pub(crate) struct ObservedDatagram {
    pub inner: Box<dyn DatagramSocket>,
    pub replay: VecDeque<(Vec<u8>, Endpoint)>,
    pub query: Option<DnsQueryMeta>,
    pub reverse: Arc<ReverseDns>,
}
impl DatagramSocket for ObservedDatagram {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_endpoint()
    }
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        if let Some((packet, endpoint)) = self.replay.pop_front() {
            if packet.len() > buf.len() {
                return Poll::Ready(Err(IoError::new(
                    rustbox_io::IoErrorKind::InvalidInput,
                    "replay datagram exceeds buffer",
                )));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Poll::Ready(Ok((packet.len(), endpoint)))
        } else {
            Pin::new(&mut *self.inner).poll_recv_from(cx, buf)
        }
    }
    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        let result = Pin::new(&mut *self.inner).poll_send_to(cx, buf, target);
        if let Poll::Ready(Ok(len)) = result
            && let Some(query) = &self.query
        {
            self.reverse
                .record(&query.name, &dns_response_addresses(&buf[..len], query.id));
        }
        result
    }
}
