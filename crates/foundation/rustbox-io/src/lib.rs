//! 代理模块共享的异步 I/O 契约。
//!
//! 字节流直接使用 Tokio `AsyncRead + AsyncWrite`；这里只为常用的 trait object
//! 组合保留一个轻量标记 trait。数据报和包设备仍有各自的消息边界契约。

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_types::Endpoint;
use std::any::Any;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod uot;

/// 可装入 trait object 的 Tokio 有序字节流。
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T> ByteStream for T
where
    T: AsyncRead + AsyncWrite + Send + Unpin + Any,
{
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
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

impl From<std::io::Error> for IoError {
    fn from(error: std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof => IoErrorKind::Closed,
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
                IoErrorKind::Interrupted
            }
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
                IoErrorKind::InvalidInput
            }
            std::io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
            _ => IoErrorKind::Other,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<IoError> for std::io::Error {
    fn from(error: IoError) -> Self {
        let kind = match error.kind {
            IoErrorKind::Closed => std::io::ErrorKind::UnexpectedEof,
            IoErrorKind::Interrupted => std::io::ErrorKind::WouldBlock,
            IoErrorKind::InvalidInput => std::io::ErrorKind::InvalidInput,
            IoErrorKind::Unsupported => std::io::ErrorKind::Unsupported,
            IoErrorKind::Other => std::io::ErrorKind::Other,
        };
        Self::new(kind, error.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_std_io_error_kinds_consistently() {
        let cases = [
            (std::io::ErrorKind::ConnectionReset, IoErrorKind::Closed),
            (std::io::ErrorKind::WouldBlock, IoErrorKind::Interrupted),
            (std::io::ErrorKind::InvalidData, IoErrorKind::InvalidInput),
            (std::io::ErrorKind::Unsupported, IoErrorKind::Unsupported),
            (std::io::ErrorKind::PermissionDenied, IoErrorKind::Other),
        ];

        for (source, expected) in cases {
            assert_eq!(
                IoError::from(std::io::Error::new(source, "test")).kind,
                expected
            );
        }
    }

    #[test]
    fn maps_portable_io_error_back_to_std() {
        let error = std::io::Error::from(IoError::new(IoErrorKind::Closed, "closed"));

        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(error.to_string(), "closed");
    }
}
