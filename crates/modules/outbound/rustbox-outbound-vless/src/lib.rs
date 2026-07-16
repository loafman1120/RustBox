//! Plain VLESS outbound adapted from `madeye/meow-rs` commit
//! `0609fed0da813496899a85d3d52e10719552aa63`.
//!
//! This intentionally excludes XTLS Vision until RustBox exposes raw-stream
//! passthrough. It has no dependency on a `meow-*` crate.

use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_transport::{StreamTransport, TransportContext};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

mod datagram;
mod vision;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VlessTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessConfigError {
    pub message: String,
}

pub struct VlessOutbound {
    id: OutboundId,
    server: Endpoint,
    uuid: [u8; 16],
    tls: Option<(ServerName<'static>, Arc<ClientConfig>)>,
    network: Arc<dyn NetworkProvider>,
    transport: Option<Arc<dyn StreamTransport>>,
    vision: bool,
}

impl VlessOutbound {
    pub fn new(
        id: OutboundId,
        server: Endpoint,
        uuid: &str,
        flow: Option<&str>,
        tls: VlessTlsConfig,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self, VlessConfigError> {
        let uuid = Uuid::parse_str(uuid).map_err(|error| VlessConfigError {
            message: format!("invalid VLESS UUID: {error}"),
        })?;
        let vision = match flow.filter(|value| !value.is_empty()) {
            None => false,
            Some("xtls-rprx-vision") => true,
            Some(value) => {
                return Err(VlessConfigError {
                    message: format!("unsupported VLESS flow `{value}`"),
                });
            }
        };
        let tls = if tls.enabled {
            Some((
                tls_server_name(tls.server_name.as_deref(), &server)?,
                tls_client_config(&tls)?,
            ))
        } else {
            None
        };
        Ok(Self {
            id,
            server,
            uuid: *uuid.as_bytes(),
            tls,
            network,
            transport: None,
            vision,
        })
    }

    pub fn with_transport(mut self, transport: Arc<dyn StreamTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    async fn connect_with_command(
        &self,
        target: &Endpoint,
        command: u8,
    ) -> Result<Box<dyn ByteStream>, OutboundError> {
        let stream = if let Some(transport) = &self.transport {
            transport
                .connect(
                    TransportContext {
                        network: &*self.network,
                    },
                    self.server.clone(),
                )
                .await
                .map_err(|error| OutboundError::new(error.message))?
        } else {
            self.network
                .connect_tcp(TcpConnect {
                    target: self.server.clone(),
                })
                .await
                .map_err(|error| OutboundError::new(error.message))?
        };
        let mut stream: Box<dyn ByteStream> = match (&self.transport, &self.tls) {
            (Some(_), _) => stream,
            (None, Some((server_name, config))) => {
                let tls = TlsConnector::from(config.clone())
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|error| {
                        OutboundError::new(format!("VLESS TLS handshake failed: {error}"))
                    })?;
                Box::new(tls)
            }
            (None, None) => stream,
        };
        let use_vision = self.vision && command == 0x01;
        let header = encode_request(&self.uuid, use_vision, command, target)?;
        stream
            .write_all(&header)
            .await
            .map_err(|error| OutboundError::new(format!("write VLESS request: {error}")))?;
        stream
            .flush()
            .await
            .map_err(|error| OutboundError::new(format!("flush VLESS request: {error}")))?;
        let stream = VlessStream::new(stream);
        if use_vision {
            Ok(Box::new(vision::VisionConn::new(stream, self.uuid)))
        } else {
            Ok(Box::new(stream))
        }
    }

    async fn connect(&self, target: &Endpoint) -> Result<Box<dyn ByteStream>, OutboundError> {
        self.connect_with_command(target, 0x01).await
    }
}

impl Outbound for VlessOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move { self.connect(&target).await })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            let stream = self.connect_with_command(&target, 0x02).await?;
            Ok(Box::new(datagram::VlessDatagram::new(stream, target)) as Box<dyn DatagramSocket>)
        })
    }
}

fn encode_request(
    uuid: &[u8; 16],
    vision: bool,
    command: u8,
    target: &Endpoint,
) -> Result<Vec<u8>, OutboundError> {
    let mut output = Vec::with_capacity(64);
    if vision {
        output.push(18);
        output.extend_from_slice(&[0x0a, 0x10]);
        output.extend_from_slice(b"xtls-rprx-vision");
    } else {
        output.push(0x00);
    }
    output.extend_from_slice(uuid);
    output.push(0x00);
    output.push(command);
    output.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddress::V4(octets)) => {
            output.push(0x01);
            output.extend_from_slice(octets);
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| OutboundError::new("VLESS target domain exceeds 255 bytes"))?;
            output.push(0x02);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddress::V6(octets)) => {
            output.push(0x03);
            output.extend_from_slice(octets);
        }
    }
    Ok(output)
}

enum ResponseState {
    Header { bytes: [u8; 2], read: usize },
    Addon { remaining: usize },
    Ready,
}

struct VlessStream {
    inner: Box<dyn ByteStream>,
    response: ResponseState,
}

impl VlessStream {
    fn new(inner: Box<dyn ByteStream>) -> Self {
        Self {
            inner,
            response: ResponseState::Header {
                bytes: [0; 2],
                read: 0,
            },
        }
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.response {
                ResponseState::Header { bytes, read } => {
                    let mut buffer = ReadBuf::new(&mut bytes[*read..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VLESS server closed before response header",
                            )));
                        }
                        Poll::Ready(Ok(())) => *read += buffer.filled().len(),
                    }
                    if *read == 2 {
                        if bytes[0] != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("VLESS response version mismatch: {}", bytes[0]),
                            )));
                        }
                        this.response = if bytes[1] == 0 {
                            ResponseState::Ready
                        } else {
                            ResponseState::Addon {
                                remaining: usize::from(bytes[1]),
                            }
                        };
                    }
                }
                ResponseState::Addon { remaining } => {
                    let mut discard = [0_u8; 256];
                    let length = (*remaining).min(discard.len());
                    let mut buffer = ReadBuf::new(&mut discard[..length]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VLESS server closed in response addon",
                            )));
                        }
                        Poll::Ready(Ok(())) => *remaining -= buffer.filled().len(),
                    }
                    if *remaining == 0 {
                        this.response = ResponseState::Ready;
                    }
                }
                ResponseState::Ready => return Pin::new(&mut this.inner).poll_read(cx, output),
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn tls_client_config(tls: &VlessTlsConfig) -> Result<Arc<ClientConfig>, VlessConfigError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| VlessConfigError {
            message: format!("failed to select VLESS TLS versions: {error}"),
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
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn tls_server_name(
    configured: Option<&str>,
    server: &Endpoint,
) -> Result<ServerName<'static>, VlessConfigError> {
    let host = configured
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| server.host.to_string());
    ServerName::try_from(host.clone()).map_err(|error| VlessConfigError {
        message: format!("invalid VLESS TLS server name `{host}`: {error}"),
    })
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_upstream_vector() {
        let uuid = *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
            .unwrap()
            .as_bytes();
        let header = encode_request(
            &uuid,
            false,
            0x01,
            &Endpoint::new(Host::domain("example.com"), 80),
        )
        .unwrap();
        assert_eq!(header[0], 0);
        assert_eq!(&header[1..17], &uuid);
        assert_eq!(&header[17..22], &[0, 1, 0, 80, 2]);
        assert_eq!(header[22], 11);
        assert_eq!(&header[23..], b"example.com");
    }

    #[tokio::test]
    async fn response_state_survives_partial_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(32);
        let mut stream = VlessStream::new(Box::new(client));
        server.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        server.write_all(&[1, 0xaa, 0x42]).await.unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [0x42]);
    }
}
