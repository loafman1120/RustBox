//! Transport contracts and baseline TCP transport.

use rustbox_host_api::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_io::ByteStream;
use rustbox_types::Endpoint;
use std::sync::Arc;

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
