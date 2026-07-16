//! NaiveProxy HTTP/2 CONNECT outbound.
//!
//! HTTP/2 session ownership, multiplexing and padding framing live in the
//! shared transport crate; this module only supplies proxy authentication and
//! implements the kernel outbound contract.

use base64::Engine as _;
use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError};
use rustbox_transport::{H2TunnelOptions, H2TunnelPool};
use rustbox_types::{Endpoint, OutboundId};

#[derive(Clone)]
pub struct NaiveOutbound {
    id: OutboundId,
    pool: H2TunnelPool,
    options: H2TunnelOptions,
}

impl NaiveOutbound {
    pub fn new(
        id: OutboundId,
        pool: H2TunnelPool,
        username: &str,
        password: &str,
        headers: Vec<(String, String)>,
    ) -> Self {
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        let mut headers = headers;
        headers.push(("proxy-authorization".into(), format!("Basic {token}")));
        Self {
            id,
            pool,
            options: H2TunnelOptions {
                headers,
                negotiate_naive_padding: true,
            },
        }
    }
}

impl Outbound for NaiveOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            self.pool
                .connect(target, self.options.clone())
                .await
                .map_err(|error| OutboundError::new(error.message))
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async {
            Err(OutboundError::new(
                "NaiveProxy HTTP/2 CONNECT does not carry UDP datagrams",
            ))
        })
    }
}
