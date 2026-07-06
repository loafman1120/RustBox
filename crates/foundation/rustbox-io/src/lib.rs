//! Runtime-neutral asynchronous I/O contracts.

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_types::Endpoint;
use std::future::poll_fn;

pub trait ByteStream: Send + Unpin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>>;

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>>;

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>>;

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>>;
}

pub trait DatagramSocket: Send + Unpin {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>>;

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>>;
}

pub trait PacketDevice: Send + Unpin {
    fn poll_recv_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>>;

    fn poll_send_packet(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<Result<usize, IoError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoError {
    pub kind: IoErrorKind,
    pub message: String,
}

impl IoError {
    pub fn new(kind: IoErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoErrorKind {
    Closed,
    Interrupted,
    InvalidInput,
    Unsupported,
    Other,
}

pub async fn stream_read(stream: &mut dyn ByteStream, buf: &mut [u8]) -> Result<usize, IoError> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, buf)).await
}

pub async fn stream_write_all(stream: &mut dyn ByteStream, mut buf: &[u8]) -> Result<(), IoError> {
    while !buf.is_empty() {
        let written = poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, buf)).await?;
        if written == 0 {
            return Err(IoError::new(
                IoErrorKind::Closed,
                "stream write returned zero",
            ));
        }
        buf = &buf[written..];
    }
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush(cx)).await
}

pub async fn stream_close(stream: &mut dyn ByteStream) -> Result<(), IoError> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_close(cx)).await
}
