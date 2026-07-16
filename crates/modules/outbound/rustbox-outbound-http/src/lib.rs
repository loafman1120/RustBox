//! HTTP CONNECT outbound.
//!
//! RustBox performs the CONNECT handshake itself because the protocol surface is
//! small and existing HTTP proxy crates are either server-focused or tied to a
//! concrete async runtime. The implementation keeps capability injection intact
//! by opening the upstream proxy through `NetworkProvider`.

use base64::Engine;
use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect,
};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, OutboundId};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;

/// Optional HTTP proxy Basic authentication credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProxyCredentials {
    pub username: String,
    pub password: String,
}

/// Upstream HTTP CONNECT proxy outbound.
pub struct HttpProxyOutbound {
    id: OutboundId,
    proxy: Endpoint,
    credentials: Option<HttpProxyCredentials>,
    network: Arc<dyn NetworkProvider>,
    observability: Arc<dyn ObservabilitySink>,
}

impl HttpProxyOutbound {
    pub fn new(id: OutboundId, proxy: Endpoint, network: Arc<dyn NetworkProvider>) -> Self {
        Self {
            id,
            proxy,
            credentials: None,
            network,
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub fn with_credentials(mut self, credentials: HttpProxyCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }
}

impl Outbound for HttpProxyOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = ctx.flow_id();
        let target_text = target.to_string();

        Box::pin(async move {
            self.emit_connecting(flow_id, outbound.clone(), target_text.clone())
                .await;

            let result = async {
                let proxy_stream = self
                    .network
                    .connect_tcp(TcpConnect {
                        target: self.proxy.clone(),
                    })
                    .await
                    .map_err(|err| OutboundError::new(err.message))?;
                connect_tunnel(proxy_stream, &target, self.credentials.as_ref()).await
            }
            .await;

            match result {
                Ok(stream) => {
                    self.emit_connected(flow_id, outbound, target_text).await;
                    Ok(Box::new(stream) as Box<dyn ByteStream>)
                }
                Err(err) => {
                    self.emit_failed(flow_id, outbound, target_text, &err).await;
                    Err(err)
                }
            }
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async {
            Err(OutboundError::new(
                "http outbound does not support UDP datagrams",
            ))
        })
    }
}

impl HttpProxyOutbound {
    async fn emit_connecting(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.outbound.http",
                flow_id,
                EventKind::OutboundConnecting { outbound, target },
            ))
            .await;
    }

    async fn emit_connected(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Info,
                "rustbox.outbound.http",
                flow_id,
                EventKind::OutboundConnected { outbound, target },
            ))
            .await;
    }

    async fn emit_failed(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
        err: &OutboundError,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Error,
                "rustbox.outbound.http",
                flow_id,
                EventKind::OutboundFailed {
                    outbound,
                    target,
                    error: err.message.clone(),
                },
            ))
            .await;
    }
}

async fn connect_tunnel(
    mut proxy_stream: Box<dyn ByteStream>,
    target: &Endpoint,
    credentials: Option<&HttpProxyCredentials>,
) -> Result<HttpTunnelStream, OutboundError> {
    let request = connect_request(target, credentials);
    proxy_stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| OutboundError::new(err.to_string()))?;

    let response = read_connect_response(&mut *proxy_stream).await?;
    let header_end = find_header_end(&response).expect("response reader returns complete headers");
    validate_connect_response(&response[..header_end])?;

    Ok(HttpTunnelStream {
        inner: proxy_stream,
        pending: response[header_end + 4..].to_vec(),
    })
}

fn connect_request(target: &Endpoint, credentials: Option<&HttpProxyCredentials>) -> String {
    let authority = endpoint_authority(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(credentials) = credentials {
        let raw = format!("{}:{}", credentials.username, credentials.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

fn endpoint_authority(endpoint: &Endpoint) -> String {
    match &endpoint.host {
        Host::Ip(rustbox_types::IpAddress::V6(_)) => {
            format!("[{}]:{}", endpoint.host, endpoint.port)
        }
        _ => endpoint.to_string(),
    }
}

async fn read_connect_response(stream: &mut dyn ByteStream) -> Result<Vec<u8>, OutboundError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        if response.len() >= MAX_CONNECT_RESPONSE_BYTES {
            return Err(OutboundError::new(
                "http proxy CONNECT response exceeded header limit",
            ));
        }
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| OutboundError::new(err.to_string()))?;
        if read == 0 {
            return Err(OutboundError::new(
                "http proxy closed before CONNECT response completed",
            ));
        }
        response.extend_from_slice(&buf[..read]);
        if find_header_end(&response).is_some() {
            return Ok(response);
        }
    }
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn validate_connect_response(header: &[u8]) -> Result<(), OutboundError> {
    let header_text = std::str::from_utf8(header)
        .map_err(|_| OutboundError::new("http proxy CONNECT response is not valid UTF-8"))?;
    let status_line = header_text
        .lines()
        .next()
        .ok_or_else(|| OutboundError::new("http proxy CONNECT response is empty"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(OutboundError::new(format!(
            "http proxy CONNECT response has invalid status line `{status_line}`"
        )));
    }
    if code != "200" {
        return Err(OutboundError::new(format!(
            "http proxy CONNECT failed with status `{status_line}`"
        )));
    }
    Ok(())
}

struct HttpTunnelStream {
    inner: Box<dyn ByteStream>,
    pending: Vec<u8>,
}

impl AsyncRead for HttpTunnelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.pending.is_empty() && buf.remaining() > 0 {
            let len = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..len]);
            self.pending.drain(..len);
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpTunnelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_kernel::TokioNetworkProvider;
    use rustbox_types::{FlowId, FlowMeta, InboundId, Network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_outbound_connects_stream_through_connect_proxy() {
        let proxy = start_http_connect_proxy().await;
        let host = Arc::new(TokioNetworkProvider::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = HttpProxyOutbound::new(outbound_id, proxy, host);
        let target = Endpoint::new(Host::domain("example.test"), 443);
        let meta = flow_meta(target.clone());

        let mut stream = outbound
            .open_stream(OutboundContext::for_flow(&meta), target)
            .await
            .expect("open http tunnel");
        let mut buf = [0_u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .expect("read prebuffered bytes");
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn http_outbound_rejects_non_200_connect_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let proxy = Endpoint::localhost_v4(listener.local_addr().expect("local addr").port());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept proxy");
            read_http_headers(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .expect("write response");
        });

        let host = Arc::new(TokioNetworkProvider::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = HttpProxyOutbound::new(outbound_id, proxy, host);
        let target = Endpoint::new(Host::domain("example.test"), 443);
        let meta = flow_meta(target.clone());

        let error = match outbound
            .open_stream(OutboundContext::for_flow(&meta), target)
            .await
        {
            Ok(_) => panic!("expected non-200 CONNECT response to fail"),
            Err(error) => error,
        };

        assert!(error.message.contains("407"));
    }

    async fn start_http_connect_proxy() -> Endpoint {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let proxy = Endpoint::localhost_v4(listener.local_addr().expect("local addr").port());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept proxy");
            let request = read_http_headers(&mut socket).await;
            assert!(String::from_utf8_lossy(&request).starts_with("CONNECT example.test:443 "));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\npong")
                .await
                .expect("write response");
        });
        proxy
    }

    async fn read_http_headers(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buf = [0_u8; 128];
        loop {
            let read = socket.read(&mut buf).await.expect("read request");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return request;
            }
        }
    }

    fn flow_meta(destination: Endpoint) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero flow id")),
            network: Network::Tcp,
            source: Endpoint::localhost_v4(12000),
            destination,
            inbound: InboundId::new(NonZeroU64::new(2).expect("non-zero inbound id")),
            domain: None,
            protocol_hint: None,
            platform: Default::default(),
        }
    }
}
