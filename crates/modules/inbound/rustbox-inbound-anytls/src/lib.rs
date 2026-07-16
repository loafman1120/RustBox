//! Native RustBox AnyTLS server inbound.
//!
//! TLS acceptance and authentication live at the inbound boundary. The
//! multiplexing protocol, client/server session engine, and UOT codec come
//! from the vendored `rustbox-anytls` workspace crate.

use anytls::core::PaddingFactory;
use anytls::proxy::session::{Stream, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{BoxFuture, NetworkProvider, StreamListener, TaskScope, TcpBind};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{Endpoint, FlowId, FlowMeta, Host, InboundId, IpAddress, Network};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;

const UOT_SENTINEL: &str = rustbox_io::uot::SENTINEL;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsServerConfig {
    pub password: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsInboundConfigError {
    pub message: String,
}

pub struct AnyTlsInbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    acceptor: TlsAcceptor,
    password_hash: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl AnyTlsInbound {
    pub fn new(
        id: InboundId,
        listen: Endpoint,
        config: AnyTlsServerConfig,
        network: Arc<dyn NetworkProvider>,
        sink: Arc<dyn FlowSink>,
    ) -> Result<Self, AnyTlsInboundConfigError> {
        if config.password.is_empty() {
            return Err(AnyTlsInboundConfigError {
                message: "anytls inbound password must not be empty".into(),
            });
        }
        let tls = server_tls_config(&config)?;
        Ok(Self {
            id,
            listen,
            network,
            sink,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            password_hash: Sha256::digest(config.password.as_bytes()).into(),
            padding: DefaultPaddingFactory::load(),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            local_endpoint: Arc::new(Mutex::new(None)),
            started: AtomicBool::new(false),
        })
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("anytls endpoint lock")
            .clone()
    }
}

impl Inbound for AnyTlsInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for AnyTlsInbound {
    fn start(&mut self, ctx: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("anytls inbound already started"));
            }
            let listener = self
                .network
                .bind_tcp(TcpBind {
                    listen: self.listen.clone(),
                })
                .await
                .map_err(|error| ServiceError::new(error.message))?;
            let local = listener
                .local_endpoint()
                .unwrap_or_else(|| self.listen.clone());
            *self.local_endpoint.lock().expect("anytls endpoint lock") = Some(local);
            let id = self.id;
            let acceptor = self.acceptor.clone();
            let hash = self.password_hash;
            let padding = self.padding.clone();
            let sink = self.sink.clone();
            let sessions = ctx.session_tasks.clone();
            let next_flow_id = self.next_flow_id.clone();
            ctx.accept_tasks.spawn(async move {
                accept_loop(
                    id,
                    listener,
                    acceptor,
                    hash,
                    padding,
                    sink,
                    sessions,
                    next_flow_id,
                )
                .await;
            });
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            self.started.store(false, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    inbound: InboundId,
    mut listener: Box<dyn StreamListener>,
    acceptor: TlsAcceptor,
    password_hash: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    sink: Arc<dyn FlowSink>,
    sessions: TaskScope,
    next_flow_id: Arc<AtomicU64>,
) {
    while let Ok((stream, peer)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let padding = padding.clone();
        let sink = sink.clone();
        let stream_sessions = sessions.clone();
        let next_flow_id = next_flow_id.clone();
        sessions.spawn(async move {
            let Ok(mut tls) = acceptor.accept(SharedByteStream::new(stream)).await else {
                return;
            };
            let mut received = [0_u8; 32];
            if tls.read_exact(&mut received).await.is_err() || received != password_hash {
                return;
            }
            let Ok(padding_length) = tls.read_u16().await else {
                return;
            };
            let mut auth_padding = vec![0_u8; usize::from(padding_length)];
            if tls.read_exact(&mut auth_padding).await.is_err() {
                return;
            }
            let callback = Box::new(move |stream: Arc<Stream>| {
                let sink = sink.clone();
                let peer = peer.clone();
                let next_flow_id = next_flow_id.clone();
                stream_sessions.spawn(async move {
                    if let Err(error) =
                        submit_stream(inbound, peer, stream.clone(), sink, next_flow_id).await
                    {
                        let _ = stream.handshake_failure(&error.to_string()).await;
                        let _ = stream.close().await;
                    }
                });
            });
            let session = new_server_session(Box::new(tls), callback, padding).await;
            let _ = session.run().await;
        });
    }
}

async fn submit_stream(
    inbound: InboundId,
    peer: Endpoint,
    stream: Arc<Stream>,
    sink: Arc<dyn FlowSink>,
    next_flow_id: Arc<AtomicU64>,
) -> io::Result<()> {
    let target = read_socks_target(&stream).await?;
    let id = next_flow_id.fetch_add(1, Ordering::Relaxed).max(1);
    let flow_id = FlowId::new(NonZeroU64::new(id).expect("flow id nonzero"));
    if target.host == Host::domain(UOT_SENTINEL) {
        let mut mode = [0_u8; 1];
        read_stream_bytes(&stream, &mut mode).await?;
        if mode[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only AnyTLS UOT datagram mode is supported",
            ));
        }
        let initial = read_socks_target(&stream).await?;
        stream.handshake_success().await?;
        let meta = FlowMeta {
            id: flow_id,
            network: Network::Udp,
            source: peer,
            destination: initial,
            inbound,
            domain: None,
            protocol_hint: None,
            platform: Default::default(),
        };
        sink.submit(Flow {
            meta,
            payload: FlowPayload::Datagram(Box::new(AnyTlsInboundDatagram::new(stream))),
        })
        .await
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    } else {
        stream.handshake_success().await?;
        let domain = matches!(target.host, Host::Domain(_)).then(|| target.host.clone());
        let meta = FlowMeta {
            id: flow_id,
            network: Network::Tcp,
            source: peer,
            destination: target,
            inbound,
            domain,
            protocol_hint: None,
            platform: Default::default(),
        };
        sink.submit(Flow {
            meta,
            payload: FlowPayload::Stream(Box::new(AnyTlsInboundStream::new(stream))),
        })
        .await
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    }
    Ok(())
}

type ReadFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

struct SharedByteStream {
    inner: Mutex<Box<dyn ByteStream>>,
}
impl SharedByteStream {
    fn new(inner: Box<dyn ByteStream>) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}
impl AsyncRead for SharedByteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().expect("anytls inbound stream lock");
        Pin::new(&mut **inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for SharedByteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock().expect("anytls inbound stream lock");
        Pin::new(&mut **inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().expect("anytls inbound stream lock");
        Pin::new(&mut **inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().expect("anytls inbound stream lock");
        Pin::new(&mut **inner).poll_shutdown(cx)
    }
}

struct AnyTlsInboundStream {
    stream: Arc<Stream>,
    read: Option<ReadFuture>,
    write: Option<WriteFuture>,
}
impl AnyTlsInboundStream {
    fn new(stream: Arc<Stream>) -> Self {
        Self {
            stream,
            read: None,
            write: None,
        }
    }
}
impl Drop for AnyTlsInboundStream {
    fn drop(&mut self) {
        close_stream(self.stream.clone());
    }
}
impl AsyncRead for AnyTlsInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read.is_none() {
            let stream = self.stream.clone();
            let length = buf.remaining();
            self.read = Some(Box::pin(async move {
                let mut data = vec![0; length];
                let read = stream.read(&mut data).await?;
                data.truncate(read);
                Ok(data)
            }));
        }
        match self.read.as_mut().expect("read future").as_mut().poll(cx) {
            Poll::Ready(Ok(data)) => {
                self.read = None;
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.read = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for AnyTlsInboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write.is_none() {
            let stream = self.stream.clone();
            let data = buf.to_vec();
            self.write = Some(Box::pin(async move { stream.write(&data).await }));
        }
        match self.write.as_mut().expect("write future").as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.write = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        close_stream(self.stream.clone());
        Poll::Ready(Ok(()))
    }
}

type DatagramReadFuture = Pin<Box<dyn Future<Output = io::Result<(Vec<u8>, Endpoint)>> + Send>>;
type DatagramWriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;
struct AnyTlsInboundDatagram {
    stream: Arc<Stream>,
    read: Option<DatagramReadFuture>,
    write: Option<DatagramWriteFuture>,
}
impl AnyTlsInboundDatagram {
    fn new(stream: Arc<Stream>) -> Self {
        Self {
            stream,
            read: None,
            write: None,
        }
    }
}
impl Drop for AnyTlsInboundDatagram {
    fn drop(&mut self) {
        close_stream(self.stream.clone());
    }
}
impl DatagramSocket for AnyTlsInboundDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        if self.read.is_none() {
            let stream = self.stream.clone();
            self.read = Some(Box::pin(async move { read_uot_datagram(&stream).await }));
        }
        match self.read.as_mut().expect("datagram read").as_mut().poll(cx) {
            Poll::Ready(Ok((payload, endpoint))) => {
                self.read = None;
                let length = payload.len().min(buf.len());
                buf[..length].copy_from_slice(&payload[..length]);
                Poll::Ready(Ok((length, endpoint)))
            }
            Poll::Ready(Err(error)) => {
                self.read = None;
                Poll::Ready(Err(io_error(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        if self.write.is_none() {
            let stream = self.stream.clone();
            let target = target.clone();
            let payload = buf.to_vec();
            self.write = Some(Box::pin(async move {
                let frame = encode_uot_datagram(&target, &payload)?;
                stream.write(&frame).await?;
                Ok(payload.len())
            }));
        }
        match self
            .write
            .as_mut()
            .expect("datagram write")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(result) => {
                self.write = None;
                Poll::Ready(result.map_err(io_error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn server_tls_config(
    config: &AnyTlsServerConfig,
) -> Result<ServerConfig, AnyTlsInboundConfigError> {
    let mut cert_reader = io::BufReader::new(config.certificate_pem.as_bytes());
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|error| AnyTlsInboundConfigError {
            message: format!("read AnyTLS certificate: {error}"),
        })?;
    let mut key_reader = io::BufReader::new(config.private_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| AnyTlsInboundConfigError {
            message: format!("read AnyTLS private key: {error}"),
        })?
        .ok_or_else(|| AnyTlsInboundConfigError {
            message: "AnyTLS private key is missing".into(),
        })?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| AnyTlsInboundConfigError {
            message: format!("select AnyTLS server TLS protocol versions: {error}"),
        })?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| AnyTlsInboundConfigError {
            message: format!("build AnyTLS server TLS config: {error}"),
        })?;
    tls.alpn_protocols = config
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(tls)
}

fn close_stream(stream: Arc<Stream>) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        drop(handle.spawn(async move {
            let _ = stream.close().await;
        }));
    }
}
async fn read_stream_bytes(stream: &Stream, mut output: &mut [u8]) -> io::Result<()> {
    while !output.is_empty() {
        let read = stream.read(output).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        output = &mut output[read..];
    }
    Ok(())
}
async fn read_socks_target(stream: &Stream) -> io::Result<Endpoint> {
    let mut kind = [0];
    read_stream_bytes(stream, &mut kind).await?;
    let host = match kind[0] {
        1 => {
            let mut value = [0; 4];
            read_stream_bytes(stream, &mut value).await?;
            Host::Ip(IpAddress::V4(value))
        }
        3 => {
            let mut length = [0];
            read_stream_bytes(stream, &mut length).await?;
            let mut value = vec![0; usize::from(length[0])];
            read_stream_bytes(stream, &mut value).await?;
            Host::domain(
                String::from_utf8(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        }
        4 => {
            let mut value = [0; 16];
            read_stream_bytes(stream, &mut value).await?;
            Host::Ip(IpAddress::V6(value))
        }
        value => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {value}"),
            ));
        }
    };
    let mut port = [0; 2];
    read_stream_bytes(stream, &mut port).await?;
    Ok(Endpoint::new(host, u16::from_be_bytes(port)))
}
fn encode_uot_datagram(target: &Endpoint, payload: &[u8]) -> io::Result<Vec<u8>> {
    rustbox_io::uot::encode_datagram(target, payload)
}
async fn read_uot_datagram(stream: &Stream) -> io::Result<(Vec<u8>, Endpoint)> {
    rustbox_io::uot::read_datagram(&mut UotStreamReader(stream)).await
}

struct UotStreamReader<'a>(&'a Stream);

impl rustbox_io::uot::Reader for UotStreamReader<'_> {
    async fn read_exact<'a>(&'a mut self, output: &'a mut [u8]) -> io::Result<()> {
        read_stream_bytes(self.0, output).await
    }
}
fn io_error(error: io::Error) -> IoError {
    let kind = match error.kind() {
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof => IoErrorKind::Closed,
        io::ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
        io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustbox_kernel::TokioNetworkProvider;
    use rustbox_kernel::{Engine, Outbound, Service};
    use rustbox_outbound_anytls::{AnyTlsOutbound, AnyTlsTlsConfig};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_types::OutboundId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn inbound_and_outbound_relay_tcp_through_kernel() {
        let certificate =
            generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        let host = Arc::new(TokioNetworkProvider::new());
        let direct_id = OutboundId::new(NonZeroU64::new(1).unwrap());
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(direct_id)))
                .register_outbound(Box::new(DirectOutbound::new(direct_id, host.clone())))
                .unwrap()
                .build()
                .unwrap(),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let inbound_id = InboundId::new(NonZeroU64::new(1).unwrap());
        let mut inbound = AnyTlsInbound::new(
            inbound_id,
            Endpoint::localhost_v4(0),
            AnyTlsServerConfig {
                password: "secret".into(),
                certificate_pem: certificate.cert.pem(),
                private_key_pem: certificate.signing_key.serialize_pem(),
                alpn: Vec::new(),
            },
            host.clone(),
            sink,
        )
        .expect("inbound");
        inbound
            .start(ServiceContext::default())
            .await
            .expect("start inbound");
        let server = inbound.local_endpoint().expect("listen endpoint");

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Endpoint::localhost_v4(echo.local_addr().unwrap().port());
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = AnyTlsOutbound::new(
            OutboundId::new(NonZeroU64::new(2).unwrap()),
            server,
            // codeql[rust/hard-coded-cryptographic-value]: test-only value, never used in production
            "secret",
            AnyTlsTlsConfig {
                server_name: Some("localhost".into()),
                insecure: true,
                alpn: Vec::new(),
            },
            host,
        )
        .expect("outbound");
        let meta = FlowMeta {
            id: FlowId::new(NonZeroU64::new(2).unwrap()),
            network: Network::Tcp,
            source: Endpoint::localhost_v4(12345),
            destination: target.clone(),
            inbound: inbound_id,
            domain: None,
            protocol_hint: None,
            platform: Default::default(),
        };
        let mut stream = outbound
            .open_stream(rustbox_kernel::OutboundContext::for_flow(&meta), target)
            .await
            .expect("open");
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    }
}
