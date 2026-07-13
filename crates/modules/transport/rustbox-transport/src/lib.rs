//! transport 契约和基础 TCP transport。
//!
//! transport 描述字节如何到达对端，和 outbound 协议语义分离。

use rustbox_io::ByteStream;
use rustbox_kernel::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_types::Endpoint;
use std::sync::Arc;

/// 流式 transport 接口，可用于 TCP、TLS、WebSocket、QUIC 等链式组合。
pub trait StreamTransport: Send + Sync {
    fn connect(
        &self,
        ctx: TransportContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, TransportError>>;
}

#[derive(Clone, Copy)]
pub struct TransportContext<'a> {
    pub network: &'a dyn NetworkProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    pub message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 最小 TCP transport，通过注入的网络能力建立字节流。
#[derive(Clone)]
pub struct TcpTransport {
    network: Arc<dyn NetworkProvider>,
}

impl TcpTransport {
    pub fn new(network: Arc<dyn NetworkProvider>) -> Self {
        Self { network }
    }
}

impl StreamTransport for TcpTransport {
    fn connect(
        &self,
        _ctx: TransportContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            self.network
                .connect_tcp(TcpConnect { target })
                .await
                .map_err(|err| TransportError::new(err.message))
        })
    }
}
