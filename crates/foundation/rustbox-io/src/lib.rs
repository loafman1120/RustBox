//! 代理模块共享的异步 I/O 契约。
//!
//! 这些 trait 用来统一 TCP、TLS、代理隧道、测试内存流和平台包设备，不用于
//! 替换 Tokio runtime。

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_types::Endpoint;
use std::future::poll_fn;

/// 面向 TCP/TLS/代理隧道等有序字节流的最小异步接口。
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

/// 面向 UDP 等无连接数据报的接口，和字节流保持独立。
pub trait DatagramSocket: Send + Unpin {
    fn local_endpoint(&self) -> Option<Endpoint> {
        None
    }

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

/// 面向 TUN/用户态网络栈的三层包设备接口。
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

/// I/O 层的可移植错误，不暴露 `std::io::Error` 或平台错误码。
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

/// 将 `ByteStream` 的 poll 接口包装成 async 读操作，供模块代码复用。
pub async fn stream_read(stream: &mut dyn ByteStream, buf: &mut [u8]) -> Result<usize, IoError> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, buf)).await
}

/// 写完整个缓冲区，并在末尾 flush，避免各协议模块重复实现写循环。
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
