//! AnyTLS outbound backed by the protocol-compatible `anytls 0.2.3` client.
//!
//! The pinned `anytls` crate owns protocol framing, its single-active-stream
//! session pool, and session state. RustBox keeps responsibility for routing,
//! host-provided TCP connectivity, TLS policy, target-address framing, and
//! observability.
//!
//! The selected crate version retains canonical stream creation (`cmdSYN`),
//! monotonically increasing stream IDs, session pooling, and `cmdSYNACK`
//! handling. Upgrade gates live in `scripts/ci/sing-box-smoke.ps1` and the
//! interop contract is described in `docs/architecture.md#anytls`.

use anytls::core::PaddingFactory;
use anytls::proxy::session::{Client, Stream};
use anytls::runtime::DefaultPaddingFactory;
use anytls::{AsyncReadWrite, DialOutFunc};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect,
};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsConnector;

const IDLE_SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const UOT_SENTINEL: &str = "sp.v2.udp-over-tcp.arpa";

/// Peer implementation profile covered by RustBox's unit and process-level
/// end-to-end tests.
pub const SUPPORTED_ANYTLS_PROFILE: &str = "canonical-anytls-v2/rustbox-anytls-0.2.3";

/// TLS policy used by an AnyTLS outbound.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnyTlsTlsConfig {
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

/// Configuration error detected before the outbound is registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsConfigError {
    pub message: String,
}

/// AnyTLS upstream proxy outbound.
pub struct AnyTlsOutbound {
    id: OutboundId,
    server: Endpoint,
    network: Arc<dyn NetworkProvider>,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    password_hash: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    client: tokio::sync::OnceCell<Arc<Client>>,
    observability: Arc<dyn ObservabilitySink>,
}

impl AnyTlsOutbound {
    pub fn new(
        id: OutboundId,
        server: Endpoint,
        password: &str,
        tls: AnyTlsTlsConfig,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self, AnyTlsConfigError> {
        if password.is_empty() {
            return Err(AnyTlsConfigError {
                message: "anytls password must not be empty".to_string(),
            });
        }

        let server_name = tls_server_name(tls.server_name.as_deref(), &server)?;
        let tls_config = tls_client_config(&tls)?;
        let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        Ok(Self {
            id,
            server,
            network,
            server_name,
            tls_config,
            password_hash,
            padding: DefaultPaddingFactory::load(),
            client: tokio::sync::OnceCell::new(),
            observability: Arc::new(NoopObservabilitySink),
        })
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    async fn client(&self) -> Arc<Client> {
        self.client
            .get_or_init(|| async {
                let network = self.network.clone();
                let server = self.server.clone();
                let server_name = self.server_name.clone();
                let tls_config = self.tls_config.clone();
                let padding = self.padding.clone();
                let password_hash = self.password_hash;
                let dial_out: DialOutFunc = Box::new(move || {
                    let network = network.clone();
                    let server = server.clone();
                    let server_name = server_name.clone();
                    let tls_config = tls_config.clone();
                    let padding = padding.clone();
                    Box::pin(async move {
                        dial_server(
                            network,
                            server,
                            server_name,
                            tls_config,
                            padding,
                            password_hash,
                        )
                        .await
                    })
                });
                Arc::new(Client::new(
                    dial_out,
                    self.padding.clone(),
                    IDLE_SESSION_CHECK_INTERVAL,
                    IDLE_SESSION_TIMEOUT,
                    0,
                ))
            })
            .await
            .clone()
    }
}

impl Outbound for AnyTlsOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = Some(ctx.flow.id);
        let target_text = target.to_string();

        Box::pin(async move {
            self.emit_connecting(flow_id, outbound.clone(), target_text.clone())
                .await;

            let result = async {
                let address = encode_target(&target)?;
                let stream = self
                    .client()
                    .await
                    .create_stream()
                    .await
                    .map_err(outbound_io_error)?;
                stream.write(&address).await.map_err(outbound_io_error)?;
                Ok(Box::new(AnyTlsByteStream::new(stream)) as Box<dyn ByteStream>)
            }
            .await;

            match result {
                Ok(stream) => {
                    self.emit_connected(flow_id, outbound, target_text).await;
                    Ok(stream)
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
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = Some(ctx.flow.id);
        let target_text = target.to_string();

        Box::pin(async move {
            self.emit_connecting(flow_id, outbound.clone(), target_text.clone())
                .await;

            let result = async {
                let stream = self
                    .client()
                    .await
                    .create_stream()
                    .await
                    .map_err(outbound_io_error)?;
                let sentinel = encode_target(&Endpoint::new(Host::domain(UOT_SENTINEL), 0))?;
                stream.write(&sentinel).await.map_err(outbound_io_error)?;

                // UOT datagram mode followed by an unspecified SOCKS address.
                stream
                    .write(&[0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .map_err(outbound_io_error)?;
                Ok(Box::new(AnyTlsDatagramSocket::new(stream)) as Box<dyn DatagramSocket>)
            }
            .await;

            match result {
                Ok(socket) => {
                    self.emit_connected(flow_id, outbound, target_text).await;
                    Ok(socket)
                }
                Err(err) => {
                    self.emit_failed(flow_id, outbound, target_text, &err).await;
                    Err(err)
                }
            }
        })
    }
}

impl Drop for AnyTlsOutbound {
    fn drop(&mut self) {
        if let Some(client) = self.client.get()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let client = client.clone();
            drop(handle.spawn(async move {
                let _ = client.close().await;
            }));
        }
    }
}

impl AnyTlsOutbound {
    async fn emit_connecting(
        &self,
        flow_id: Option<rustbox_types::FlowId>,
        outbound: String,
        target: String,
    ) {
        self.observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.outbound.anytls",
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
                "rustbox.outbound.anytls",
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
                "rustbox.outbound.anytls",
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

async fn dial_server(
    network: Arc<dyn NetworkProvider>,
    server: Endpoint,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    password_hash: [u8; 32],
) -> io::Result<Box<dyn AsyncReadWrite>> {
    let stream = network
        .connect_tcp(TcpConnect { target: server })
        .await
        .map_err(|err| io::Error::other(err.message))?;
    let connector = TlsConnector::from(tls_config);
    let mut tls_stream = connector
        .connect(server_name, SharedByteStream::new(stream))
        .await?;

    let padding_length = {
        let padding = padding.read().await;
        padding
            .generate_record_payload_sizes(0)
            .first()
            .copied()
            .unwrap_or(0)
    };
    let padding_length = u16::try_from(padding_length.max(0))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "anytls padding is too large"))?;

    let authentication_length = 34 + usize::from(padding_length);
    let mut authentication = Vec::with_capacity(authentication_length);
    authentication.extend_from_slice(&password_hash);
    authentication.extend_from_slice(&padding_length.to_be_bytes());
    authentication.resize(authentication_length, 0);
    tls_stream.write_all(&authentication).await?;
    tls_stream.flush().await?;

    Ok(Box::new(tls_stream))
}

fn tls_client_config(tls: &AnyTlsTlsConfig) -> Result<Arc<ClientConfig>, AnyTlsConfigError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|err| AnyTlsConfigError {
            message: format!("failed to select anytls TLS protocol versions: {err}"),
        })?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();

    if tls.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification {
                supported: provider.signature_verification_algorithms,
            }));
    }
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn tls_server_name(
    configured: Option<&str>,
    server: &Endpoint,
) -> Result<ServerName<'static>, AnyTlsConfigError> {
    let host = configured
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| server.host.to_string());
    ServerName::try_from(host.clone()).map_err(|err| AnyTlsConfigError {
        message: format!("invalid anytls TLS server name `{host}`: {err}"),
    })
}

fn encode_target(target: &Endpoint) -> Result<Vec<u8>, OutboundError> {
    let mut encoded = Vec::new();
    match &target.host {
        Host::Ip(IpAddress::V4(octets)) => {
            encoded.push(0x01);
            encoded.extend_from_slice(octets);
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| OutboundError::new("anytls target domain exceeds 255 bytes"))?;
            encoded.push(0x03);
            encoded.push(length);
            encoded.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddress::V6(octets)) => {
            encoded.push(0x04);
            encoded.extend_from_slice(octets);
        }
    }
    encoded.extend_from_slice(&target.port.to_be_bytes());
    Ok(encoded)
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;
type CloseFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type DatagramSendFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;
type DatagramRecvFuture = Pin<Box<dyn Future<Output = io::Result<(Vec<u8>, Endpoint)>> + Send>>;

/// `anytls::AsyncReadWrite` additionally requires `Sync`; ordinary byte-stream
/// consumers do not, so the synchronization stays local to this adapter.
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
        let mut inner = self.inner.lock().expect("anytls stream mutex poisoned");
        Pin::new(&mut **inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedByteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock().expect("anytls stream mutex poisoned");
        Pin::new(&mut **inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().expect("anytls stream mutex poisoned");
        Pin::new(&mut **inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().expect("anytls stream mutex poisoned");
        Pin::new(&mut **inner).poll_shutdown(cx)
    }
}

struct AnyTlsByteStream {
    stream: Arc<Stream>,
    read: Option<ReadFuture>,
    write: Option<WriteFuture>,
    close: Option<CloseFuture>,
    closed: bool,
}

impl AnyTlsByteStream {
    fn new(stream: Arc<Stream>) -> Self {
        Self {
            stream,
            read: None,
            write: None,
            close: None,
            closed: false,
        }
    }
}

impl AsyncRead for AnyTlsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read.is_none() {
            let stream = self.stream.clone();
            let capacity = buf.remaining();
            self.read = Some(Box::pin(async move {
                let mut bytes = vec![0_u8; capacity];
                let result = stream.read(&mut bytes).await;
                (bytes, result)
            }));
        }

        let future = self.read.as_mut().expect("read future initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready((bytes, Ok(read))) => {
                self.read = None;
                buf.put_slice(&bytes[..read]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready((_, Err(err))) => {
                self.read = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write.is_none() {
            let stream = self.stream.clone();
            let bytes = buf.to_vec();
            self.write = Some(Box::pin(async move { stream.write(&bytes).await }));
        }

        let future = self.write.as_mut().expect("write future initialized");
        match future.as_mut().poll(cx) {
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.close.is_none() {
            let stream = self.stream.clone();
            self.close = Some(Box::pin(async move { stream.close().await }));
        }

        let future = self.close.as_mut().expect("close future initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.close = None;
                if result.is_ok() {
                    self.closed = true;
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AnyTlsByteStream {
    fn drop(&mut self) {
        if !self.closed {
            close_stream_in_background(self.stream.clone());
        }
    }
}

struct AnyTlsDatagramSocket {
    stream: Arc<Stream>,
    send: Option<DatagramSendFuture>,
    recv: Option<DatagramRecvFuture>,
}

impl AnyTlsDatagramSocket {
    fn new(stream: Arc<Stream>) -> Self {
        Self {
            stream,
            send: None,
            recv: None,
        }
    }
}

impl Drop for AnyTlsDatagramSocket {
    fn drop(&mut self) {
        close_stream_in_background(self.stream.clone());
    }
}

impl DatagramSocket for AnyTlsDatagramSocket {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        if self.recv.is_none() {
            let stream = self.stream.clone();
            self.recv = Some(Box::pin(async move { read_uot_datagram(&stream).await }));
        }

        let future = self.recv.as_mut().expect("datagram receive initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok((payload, source))) => {
                self.recv = None;
                let read = payload.len().min(buf.len());
                buf[..read].copy_from_slice(&payload[..read]);
                Poll::Ready(Ok((read, source)))
            }
            Poll::Ready(Err(err)) => {
                self.recv = None;
                Poll::Ready(Err(std_io_error(err)))
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
        if self.send.is_none() {
            let stream = self.stream.clone();
            let target = target.clone();
            let payload = buf.to_vec();
            self.send = Some(Box::pin(async move {
                let frame = encode_uot_datagram(&target, &payload)?;
                stream.write(&frame).await?;
                Ok(payload.len())
            }));
        }

        let future = self.send.as_mut().expect("datagram send initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.send = None;
                Poll::Ready(result.map_err(std_io_error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn close_stream_in_background(stream: Arc<Stream>) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        drop(handle.spawn(async move {
            let _ = stream.close().await;
        }));
    }
}

fn encode_uot_datagram(target: &Endpoint, payload: &[u8]) -> io::Result<Vec<u8>> {
    let payload_length = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UOT packet is too large"))?;
    let mut frame = encode_target(target)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.message))?;
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

async fn read_uot_datagram(stream: &Stream) -> io::Result<(Vec<u8>, Endpoint)> {
    let source = read_socks_target(stream).await?;
    let mut payload_length = [0_u8; 2];
    read_stream_bytes(stream, &mut payload_length).await?;
    let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(payload_length))];
    read_stream_bytes(stream, &mut payload).await?;
    Ok((payload, source))
}

async fn read_socks_target(stream: &Stream) -> io::Result<Endpoint> {
    let mut kind = [0_u8; 1];
    read_stream_bytes(stream, &mut kind).await?;
    let host = match kind[0] {
        0x01 => {
            let mut octets = [0_u8; 4];
            read_stream_bytes(stream, &mut octets).await?;
            Host::Ip(IpAddress::V4(octets))
        }
        0x03 => {
            let mut length = [0_u8; 1];
            read_stream_bytes(stream, &mut length).await?;
            let mut domain = vec![0_u8; usize::from(length[0])];
            read_stream_bytes(stream, &mut domain).await?;
            Host::domain(
                String::from_utf8(domain)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            )
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            read_stream_bytes(stream, &mut octets).await?;
            Host::Ip(IpAddress::V6(octets))
        }
        value => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {value}"),
            ));
        }
    };
    let mut port = [0_u8; 2];
    read_stream_bytes(stream, &mut port).await?;
    Ok(Endpoint::new(host, u16::from_be_bytes(port)))
}

async fn read_stream_bytes(stream: &Stream, mut output: &mut [u8]) -> io::Result<()> {
    while !output.is_empty() {
        let read = stream.read(output).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "anytls stream closed",
            ));
        }
        output = &mut output[read..];
    }
    Ok(())
}

fn outbound_io_error(err: io::Error) -> OutboundError {
    OutboundError::new(err.to_string())
}

fn std_io_error(err: io::Error) -> IoError {
    let kind = match err.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => IoErrorKind::Closed,
        io::ErrorKind::Interrupted => IoErrorKind::Interrupted,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => IoErrorKind::InvalidInput,
        io::ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    };
    IoError::new(kind, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anytls::proxy::session::new_server_session;
    use core::num::NonZeroU64;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustbox_host_api::TokioHost;
    use rustbox_types::{FlowId, FlowMeta, InboundId, Network};
    use rustls::ServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const PASSWORD: &str = "test-password";

    // Verifies that TCP payloads are relayed through a local AnyTLS server.
    #[tokio::test]
    async fn anytls_outbound_relays_tcp_bytes_through_local_server() {
        let server = start_anytls_server().await;
        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = AnyTlsOutbound::new(
            outbound_id,
            server,
            PASSWORD,
            AnyTlsTlsConfig {
                server_name: Some("localhost".to_string()),
                insecure: true,
                alpn: Vec::new(),
            },
            host,
        )
        .expect("create anytls outbound");
        let target = Endpoint::new(Host::domain("example.test"), 443);
        let meta = flow_meta(target.clone(), Network::Tcp);

        let mut stream = outbound
            .open_stream(OutboundContext { flow: &meta }, target)
            .await
            .expect("open anytls stream");
        rustbox_io::stream_write_all(&mut *stream, b"ping")
            .await
            .expect("write ping");
        let mut response = [0_u8; 4];
        let read = rustbox_io::stream_read(&mut *stream, &mut response)
            .await
            .expect("read pong");

        assert_eq!(read, 4);
        assert_eq!(&response, b"pong");
        rustbox_io::stream_close(&mut *stream)
            .await
            .expect("close anytls stream");
    }

    // Verifies that UDP datagrams are relayed through a local AnyTLS server.
    #[tokio::test]
    async fn anytls_outbound_relays_udp_datagrams_through_local_server() {
        let server = start_anytls_server().await;
        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        let outbound = AnyTlsOutbound::new(
            outbound_id,
            server,
            PASSWORD,
            AnyTlsTlsConfig {
                server_name: Some("localhost".to_string()),
                insecure: true,
                alpn: Vec::new(),
            },
            host,
        )
        .expect("create anytls outbound");
        let target = Endpoint::new(Host::domain("dns.example.test"), 53);
        let meta = flow_meta(target.clone(), Network::Udp);

        let mut socket = outbound
            .open_datagram(OutboundContext { flow: &meta }, target.clone())
            .await
            .expect("open anytls UOT socket");
        let sent =
            std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_send_to(cx, b"ping", &target))
                .await
                .expect("send UOT datagram");
        let mut response = [0_u8; 16];
        let (read, source) =
            std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, &mut response))
                .await
                .expect("receive UOT datagram");

        assert_eq!(sent, 4);
        assert_eq!(&response[..read], b"pong");
        assert_eq!(source, target);
    }

    // Verifies that an empty password is rejected before any connection is opened.
    #[tokio::test]
    async fn anytls_outbound_rejects_empty_password() {
        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(9).expect("non-zero outbound id"));
        // codeql[rust/hard-coded-cryptographic-value]: Test-only empty value verifies password validation; it is never used as a credential.
        let error = match AnyTlsOutbound::new(
            outbound_id,
            Endpoint::localhost_v4(443),
            "",
            AnyTlsTlsConfig::default(),
            host,
        ) {
            Ok(_) => panic!("expected empty password to fail"),
            Err(error) => error,
        };

        assert!(error.message.contains("password"));
    }

    // Verifies that the supported AnyTLS profile remains pinned to its declared dependency version.
    #[test]
    fn supported_profile_matches_the_exact_dependency_pin() {
        let manifest = include_str!("../Cargo.toml");
        assert_eq!(manifest.matches("package = \"rustbox-anytls\"").count(), 2);
        assert_eq!(
            SUPPORTED_ANYTLS_PROFILE,
            "canonical-anytls-v2/rustbox-anytls-0.2.3"
        );
    }

    async fn start_anytls_server() -> Endpoint {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind anytls server");
        let endpoint = Endpoint::localhost_v4(listener.local_addr().expect("local addr").port());
        let acceptor = tls_acceptor();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept anytls client");
            let mut tls = acceptor.accept(stream).await.expect("accept TLS");

            let mut password_hash = [0_u8; 32];
            tls.read_exact(&mut password_hash)
                .await
                .expect("read password hash");
            let expected_hash: [u8; 32] = Sha256::digest(PASSWORD.as_bytes()).into();
            assert_eq!(password_hash, expected_hash);

            let padding_length = tls.read_u16().await.expect("read padding length");
            let mut padding = vec![0_u8; usize::from(padding_length)];
            tls.read_exact(&mut padding)
                .await
                .expect("read auth padding");

            let callback = Box::new(|stream: Arc<Stream>| {
                tokio::spawn(async move {
                    handle_test_stream(stream)
                        .await
                        .expect("handle anytls stream");
                });
            });
            let session =
                new_server_session(Box::new(tls), callback, DefaultPaddingFactory::load()).await;
            let _ = session.run().await;
        });

        endpoint
    }

    async fn handle_test_stream(stream: Arc<Stream>) -> io::Result<()> {
        let target = read_socks_target(&stream).await?;
        if target == Endpoint::new(Host::domain(UOT_SENTINEL), 0) {
            let mut mode = [0_u8; 1];
            read_stream_bytes(&stream, &mut mode).await?;
            assert_eq!(mode, [0]);
            let unspecified = read_socks_target(&stream).await?;
            assert_eq!(
                unspecified,
                Endpoint::new(Host::Ip(IpAddress::V4([0, 0, 0, 0])), 0)
            );
            stream.handshake_success().await?;

            let (payload, target) = read_uot_datagram(&stream).await?;
            assert_eq!(&payload, b"ping");
            assert_eq!(target, Endpoint::new(Host::domain("dns.example.test"), 53));
            let response = encode_uot_datagram(&target, b"pong")?;
            stream.write(&response).await?;
        } else {
            assert_eq!(target, Endpoint::new(Host::domain("example.test"), 443));
            stream.handshake_success().await?;

            let mut request = [0_u8; 4];
            read_stream_bytes(&stream, &mut request).await?;
            assert_eq!(&request, b"ping");
            stream.write(b"pong").await?;
        }
        Ok(())
    }

    fn tls_acceptor() -> TlsAcceptor {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate test certificate");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
            )
            .expect("server TLS config");
        TlsAcceptor::from(Arc::new(config))
    }

    fn flow_meta(destination: Endpoint, network: Network) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero flow id")),
            network,
            source: Endpoint::localhost_v4(12000),
            destination,
            inbound: InboundId::new(NonZeroU64::new(2).expect("non-zero inbound id")),
            domain: None,
            protocol_hint: None,
        }
    }
}
