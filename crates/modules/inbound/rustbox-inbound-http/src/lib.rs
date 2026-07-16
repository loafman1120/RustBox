//! HTTP CONNECT inbound。
//!
//! 本模块把外部 HTTP CONNECT 隧道请求转换成内核 `Flow`。
//! 它只负责接入、握手和提交 Flow，不选择 outbound，也不执行路由规则。

use base64::Engine;
use core::num::NonZeroU64;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use rustbox_io::ByteStream;
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, StreamListener, TaskScope, TcpBind,
};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{
    Endpoint, FlowId, FlowMeta, Host, InboundId, IpAddress, Network, ProtocolHint,
};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_HEADER_BYTES: usize = 8192;

/// Optional inbound HTTP proxy Basic authentication credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpInboundCredentials {
    pub username: String,
    pub password: String,
}

/// HTTP CONNECT 入口服务，监听 TCP 并把每个成功 CONNECT 转交给 `FlowSink`。
pub struct HttpProxyInbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    credentials: Option<HttpInboundCredentials>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl HttpProxyInbound {
    pub fn new(
        id: InboundId,
        listen: Endpoint,
        network: Arc<dyn NetworkProvider>,
        sink: Arc<dyn FlowSink>,
    ) -> Self {
        Self {
            id,
            listen,
            network,
            sink,
            credentials: None,
            observability: Arc::new(NoopObservabilitySink),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            local_endpoint: Arc::new(Mutex::new(None)),
            started: AtomicBool::new(false),
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn with_credentials(mut self, credentials: HttpInboundCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("http inbound endpoint lock")
            .clone()
    }
}

impl Inbound for HttpProxyInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for HttpProxyInbound {
    fn start(&mut self, ctx: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("http inbound already started"));
            }

            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.http",
                    None,
                    EventKind::ServiceStarting {
                        service: format!("http-connect/{}", self.id),
                    },
                ))
                .await;

            let listener = self
                .network
                .bind_tcp(TcpBind {
                    listen: self.listen.clone(),
                })
                .await
                .map_err(|err| ServiceError::new(err.message))?;
            let local_endpoint = listener
                .local_endpoint()
                .unwrap_or_else(|| self.listen.clone());
            let local_endpoint_text = local_endpoint.to_string();
            *self
                .local_endpoint
                .lock()
                .expect("http inbound endpoint lock") = Some(local_endpoint);

            let id = self.id;
            let sink = Arc::clone(&self.sink);
            let sessions = ctx.session_tasks.clone();
            let observability = Arc::clone(&self.observability);
            let credentials = self.credentials.clone();
            let next_flow_id = Arc::clone(&self.next_flow_id);
            ctx.accept_tasks.spawn(async move {
                accept_loop(
                    id,
                    listener,
                    sink,
                    sessions,
                    observability,
                    credentials,
                    next_flow_id,
                )
                .await;
            });
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.http",
                    None,
                    EventKind::ServiceStarted {
                        service: format!("http-connect/{id}@{local_endpoint_text}"),
                    },
                ))
                .await;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.http",
                    None,
                    EventKind::ServiceStopping {
                        service: format!("http-connect/{}", self.id),
                    },
                ))
                .await;
            self.started.store(false, Ordering::SeqCst);
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.http",
                    None,
                    EventKind::ServiceStopped {
                        service: format!("http-connect/{}", self.id),
                    },
                ))
                .await;
            Ok(())
        })
    }
}

async fn accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn StreamListener>,
    sink: Arc<dyn FlowSink>,
    sessions: TaskScope,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<HttpInboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
) {
    // accept loop 只接受连接并派生连接处理任务，Flow 生命周期交给内核。
    let listener_endpoint = listener
        .local_endpoint()
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            break;
        };

        observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.inbound.http",
                None,
                EventKind::ConnectionAccepted {
                    listener: listener_endpoint.clone(),
                    peer: peer.to_string(),
                },
            ))
            .await;

        let sink = Arc::clone(&sink);
        let observability = Arc::clone(&observability);
        let credentials = credentials.clone();
        let next_flow_id = Arc::clone(&next_flow_id);
        sessions.spawn(async move {
            let _ = handle_http_proxy_connection(
                inbound_id,
                peer,
                stream,
                sink,
                observability,
                credentials,
                next_flow_id,
            )
            .await;
        });
    }
}

pub async fn handle_http_proxy_connection(
    inbound_id: InboundId,
    peer: Endpoint,
    mut stream: Box<dyn ByteStream>,
    sink: Arc<dyn FlowSink>,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<HttpInboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
) -> Result<(), ServiceError> {
    // 关键转换点：HTTP proxy request -> FlowMeta.destination + FlowPayload::Stream。
    let request = match read_proxy_request(&mut *stream, credentials.as_ref()).await {
        Ok(request) => request,
        Err(err) if err.message == "HTTP proxy authentication required" => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"RustBox\"\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
            return Err(err);
        }
        Err(err) => {
            observability
                .emit(Event::new(
                    EventLevel::Warn,
                    "rustbox.inbound.http",
                    None,
                    EventKind::Diagnostic(format!(
                        "invalid HTTP CONNECT request from {peer}: {}",
                        err.message
                    )),
                ))
                .await;
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };

    if request.is_connect {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|err| ServiceError::new(err.to_string()))?;
    }

    let flow_id_raw = next_flow_id.fetch_add(1, Ordering::Relaxed);
    let flow_id = FlowId::new(NonZeroU64::new(flow_id_raw.max(1)).expect("non-zero flow id"));
    let meta = FlowMeta {
        id: flow_id,
        network: Network::Tcp,
        source: peer,
        destination: request.target.clone(),
        inbound: inbound_id,
        domain: Some(request.target.host.clone()),
        protocol_hint: Some(ProtocolHint::Http),
        platform: Default::default(),
    };
    let flow = Flow {
        meta,
        payload: FlowPayload::Stream(Box::new(PrefixedByteStream::new(stream, request.prefix))),
    };

    sink.submit(flow)
        .await
        .map(|_| ())
        .map_err(|err| ServiceError::new(format!("{err:?}")))
}

struct HttpProxyRequest {
    target: Endpoint,
    is_connect: bool,
    prefix: Vec<u8>,
}

async fn read_proxy_request(
    stream: &mut dyn ByteStream,
    credentials: Option<&HttpInboundCredentials>,
) -> Result<HttpProxyRequest, ServiceError> {
    // 入口层只读取握手头部，握手完成后的字节流原样交给 relay。
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 512];
    while bytes.len() < MAX_HEADER_BYTES {
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|err| ServiceError::new(err.to_string()))?;
        if read == 0 {
            return Err(ServiceError::new("connection closed before HTTP headers"));
        }
        bytes.extend_from_slice(&scratch[..read]);
        if let Some(header_end) = find_header_end(&bytes) {
            return parse_proxy_request(&bytes, header_end, credentials);
        }
    }

    Err(ServiceError::new("HTTP proxy headers exceeded limit"))
}

fn parse_proxy_request(
    bytes: &[u8],
    header_end: usize,
    credentials: Option<&HttpInboundCredentials>,
) -> Result<HttpProxyRequest, ServiceError> {
    let header = &bytes[..header_end];
    let leftover = &bytes[header_end + 4..];
    let text = std::str::from_utf8(header)
        .map_err(|_| ServiceError::new("HTTP proxy request is not valid UTF-8"))?;
    let first_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| ServiceError::new("HTTP proxy request is empty"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let request_target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if !version.starts_with("HTTP/") {
        return Err(ServiceError::new("HTTP proxy request has invalid version"));
    }
    if let Some(credentials) = credentials
        && !headers_contain_valid_proxy_auth(text, credentials)
    {
        return Err(ServiceError::new("HTTP proxy authentication required"));
    }

    if method == "CONNECT" {
        let mut prefix = Vec::new();
        prefix.extend_from_slice(leftover);
        return Ok(HttpProxyRequest {
            target: parse_authority(request_target)?,
            is_connect: true,
            prefix,
        });
    }

    let (target, origin_form) = parse_absolute_form_target(request_target)?;
    let mut prefix = Vec::new();
    prefix.extend_from_slice(format!("{method} {origin_form} {version}\r\n").as_bytes());
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let header_name = line.split_once(':').map(|(name, _)| name).unwrap_or(line);
        if header_name.eq_ignore_ascii_case("proxy-authorization")
            || header_name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        prefix.extend_from_slice(line.as_bytes());
        prefix.extend_from_slice(b"\r\n");
    }
    prefix.extend_from_slice(b"\r\n");
    prefix.extend_from_slice(leftover);

    Ok(HttpProxyRequest {
        target,
        is_connect: false,
        prefix,
    })
}

fn parse_authority(authority: &str) -> Result<Endpoint, ServiceError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(ServiceError::new("invalid bracketed IPv6 authority"));
        };
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return Err(ServiceError::new(
                "HTTP CONNECT authority must include a port",
            ));
        };
        (host, port)
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| ServiceError::new("HTTP CONNECT port is invalid"))?;
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Host::Ip(IpAddress::V4(ip.octets())),
        Ok(IpAddr::V6(ip)) => Host::Ip(IpAddress::V6(ip.octets())),
        Err(_) => Host::Domain(host.to_string()),
    };
    Ok(Endpoint::new(host, port))
}

fn parse_absolute_form_target(value: &str) -> Result<(Endpoint, String), ServiceError> {
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(ServiceError::new(
            "HTTP proxy request target must use absolute-form",
        ));
    };
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(ServiceError::new(
                "HTTP proxy request scheme is unsupported",
            ));
        }
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(ServiceError::new("HTTP proxy request authority is empty"));
    }
    let endpoint = parse_authority_with_default_port(authority, default_port)?;
    let origin_form = if authority_end == rest.len() {
        "/".to_string()
    } else if rest[authority_end..].starts_with('?') {
        format!("/{}", &rest[authority_end..])
    } else {
        rest[authority_end..].to_string()
    };
    Ok((endpoint, origin_form))
}

fn parse_authority_with_default_port(
    authority: &str,
    default_port: u16,
) -> Result<Endpoint, ServiceError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(ServiceError::new("invalid bracketed IPv6 authority"));
        };
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .map(str::parse::<u16>)
            .transpose()
            .map_err(|_| ServiceError::new("HTTP proxy port is invalid"))?
            .unwrap_or(default_port);
        return Ok(Endpoint::new(parse_host(host), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| ServiceError::new("HTTP proxy port is invalid"))?,
        ),
        None => (authority, default_port),
    };
    Ok(Endpoint::new(parse_host(host), port))
}

fn parse_host(host: &str) -> Host {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Host::Ip(IpAddress::V4(ip.octets())),
        Ok(IpAddr::V6(ip)) => Host::Ip(IpAddress::V6(ip.octets())),
        Err(_) => Host::Domain(host.to_string()),
    }
}

fn headers_contain_valid_proxy_auth(text: &str, credentials: &HttpInboundCredentials) -> bool {
    text.split("\r\n").skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let value = value.trim();
        let Some(encoded) = value.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        decoded == format!("{}:{}", credentials.username, credentials.password).as_bytes()
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

struct PrefixedByteStream {
    inner: Box<dyn ByteStream>,
    prefix: Vec<u8>,
    offset: usize,
}

impl PrefixedByteStream {
    fn new(inner: Box<dyn ByteStream>, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

impl AsyncRead for PrefixedByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let len = (self.prefix.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.prefix[self.offset..self.offset + len]);
            self.offset += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_kernel::TokioNetworkProvider;
    use rustbox_kernel::{Engine, Service};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_types::OutboundId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn http_connect_tunnels_bytes_to_direct_outbound() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_listener.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.expect("echo accept");
            let mut buf = [0_u8; 4];
            socket.read_exact(&mut buf).await.expect("echo read");
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.expect("echo write");
        });

        let host = Arc::new(TokioNetworkProvider::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = HttpProxyInbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            sink,
        );
        inbound
            .start(ServiceContext::default())
            .await
            .expect("start http inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = match proxy.host {
            Host::Ip(IpAddress::V4(octets)) => std::net::SocketAddr::from((octets, proxy.port)),
            _ => panic!("expected IPv4 proxy endpoint"),
        };

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    echo_addr.port(),
                    echo_addr.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write connect");

        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.expect("read response");
            response.push(byte[0]);
        }
        assert!(
            std::str::from_utf8(&response)
                .expect("utf8 response")
                .starts_with("HTTP/1.1 200")
        );

        client
            .write_all(b"ping")
            .await
            .expect("write tunneled data");
        let mut tunnel_response = [0_u8; 4];
        client
            .read_exact(&mut tunnel_response)
            .await
            .expect("read tunneled data");
        assert_eq!(&tunnel_response, b"pong");
    }

    #[tokio::test]
    async fn http_absolute_form_request_is_forwarded_as_origin_form() {
        let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("http bind");
        let http_addr = http_listener.local_addr().expect("http local addr");
        tokio::spawn(async move {
            let (mut socket, _) = http_listener.accept().await.expect("http accept");
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).await.expect("read request");
                request.push(byte[0]);
            }
            let request = std::str::from_utf8(&request).expect("request utf8");
            assert!(request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("proxy-connection:"));
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write response");
        });

        let host = Arc::new(TokioNetworkProvider::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = HttpProxyInbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            sink,
        );
        inbound
            .start(ServiceContext::default())
            .await
            .expect("start http inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = match proxy.host {
            Host::Ip(IpAddress::V4(octets)) => std::net::SocketAddr::from((octets, proxy.port)),
            _ => panic!("expected IPv4 proxy endpoint"),
        };

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
                    http_addr.port(),
                    http_addr.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write request");

        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.expect("read response");
            response.push(byte[0]);
        }
        assert!(
            std::str::from_utf8(&response)
                .expect("utf8 response")
                .starts_with("HTTP/1.1 204")
        );
    }

    #[tokio::test]
    async fn http_inbound_requires_basic_auth_when_configured() {
        let host = Arc::new(TokioNetworkProvider::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = HttpProxyInbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            sink,
        )
        .with_credentials(HttpInboundCredentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        });
        inbound
            .start(ServiceContext::default())
            .await
            .expect("start http inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = match proxy.host {
            Host::Ip(IpAddress::V4(octets)) => std::net::SocketAddr::from((octets, proxy.port)),
            _ => panic!("expected IPv4 proxy endpoint"),
        };

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");

        assert!(
            std::str::from_utf8(&response)
                .expect("utf8 response")
                .starts_with("HTTP/1.1 407")
        );
    }
}
