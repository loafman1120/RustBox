//! transport 契约和基础 TCP transport。
//!
//! transport 描述字节如何到达对端，和 outbound 协议语义分离。

mod h2_tunnel;
pub use h2_tunnel::{H2TunnelOptions, H2TunnelPool};
mod shadow_tls;
pub use shadow_tls::ShadowTlsTransport;
mod mux_cool;
pub use mux_cool::{MuxCoolConfig, MuxCoolPool};

use core::pin::Pin;
use core::task::{Context, Poll};
use meow_transport::Transport as MeowTransport;
use rustbox_io::ByteStream;
use rustbox_kernel::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_types::Endpoint;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;

/// 流式 transport 接口，可用于 TCP、TLS、WebSocket、QUIC 等链式组合。
pub trait StreamTransport: Send + Sync {
    fn connect<'a>(
        &'a self,
        ctx: TransportContext<'a>,
        target: Endpoint,
    ) -> BoxFuture<'a, Result<Box<dyn ByteStream>, TransportError>>;
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsLayerConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub client_certificate_pem: Option<Vec<u8>>,
    pub client_private_key_pem: Option<Vec<u8>>,
    pub certificate_authorities_der: Vec<Vec<u8>>,
    pub fingerprint: Option<String>,
    pub ech_config: Option<Vec<u8>>,
    pub reality: Option<RealityLayerConfig>,
    pub public_key_pins: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityLayerConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub support_x25519_mlkem768: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2RayTransportConfig {
    WebSocket {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
        max_early_data: usize,
        early_data_header: Option<String>,
    },
    Http2 {
        path: String,
        hosts: Vec<String>,
    },
    Grpc {
        service_name: String,
        authority: String,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
    },
}

/// A pre-built immutable transport chain. Connections only allocate their
/// stream state; TLS roots and layer configuration are shared by the outbound.
#[derive(Clone)]
pub struct LayeredTransport {
    network: Arc<dyn NetworkProvider>,
    layers: Arc<Vec<Arc<dyn MeowTransport>>>,
    pinned_tls: Option<PinnedTls>,
}

impl LayeredTransport {
    pub fn new(
        network: Arc<dyn NetworkProvider>,
        tls: Option<TlsLayerConfig>,
        transport: Option<V2RayTransportConfig>,
    ) -> Result<Self, TransportError> {
        let mut layers: Vec<Arc<dyn MeowTransport>> = Vec::new();
        let mut pinned_tls = None;
        if let Some(tls) = tls.filter(|config| config.enabled) {
            #[cfg(not(feature = "fingerprint"))]
            if tls.fingerprint.is_some() {
                return Err(TransportError::new(
                    "TLS fingerprint shaping requires the `fingerprint` build feature",
                ));
            }
            if !tls.public_key_pins.is_empty() {
                if tls.reality.is_some() || tls.fingerprint.is_some() {
                    return Err(TransportError::new(
                        "TLS public-key pinning cannot be combined with REALITY or fingerprint shaping",
                    ));
                }
                pinned_tls = Some(PinnedTls::new(&tls)?);
            } else {
                let client_cert = match (tls.client_certificate_pem, tls.client_private_key_pem) {
                    (Some(cert_pem), Some(key_pem)) => {
                        Some(meow_transport::tls::ClientCert { cert_pem, key_pem })
                    }
                    (None, None) => None,
                    _ => {
                        return Err(TransportError::new(
                            "TLS client certificate and private key must be configured together",
                        ));
                    }
                };
                let layer = meow_transport::tls::TlsLayer::new(&meow_transport::tls::TlsConfig {
                    enabled: true,
                    sni: tls.server_name,
                    alpn: tls.alpn,
                    skip_cert_verify: tls.insecure,
                    client_cert,
                    fingerprint: tls.fingerprint,
                    additional_roots: tls.certificate_authorities_der,
                    ech: tls.ech_config.map(meow_transport::tls::EchOpts::Config),
                    reality: tls
                        .reality
                        .map(|reality| meow_transport::tls::RealityConfig {
                            public_key: reality.public_key,
                            short_id: reality.short_id,
                            support_x25519_mlkem768: reality.support_x25519_mlkem768,
                        }),
                })
                .map_err(|error| TransportError::new(error.to_string()))?;
                layers.push(Arc::new(layer));
            }
        }
        if let Some(transport) = transport {
            match transport {
                V2RayTransportConfig::WebSocket {
                    path,
                    host,
                    headers,
                    max_early_data,
                    early_data_header,
                } => {
                    let layer = meow_transport::ws::WsLayer::new(meow_transport::ws::WsConfig {
                        path,
                        host_header: host,
                        extra_headers: headers,
                        max_early_data,
                        early_data_header_name: early_data_header,
                    })
                    .map_err(|error| TransportError::new(error.to_string()))?;
                    layers.push(Arc::new(layer));
                }
                V2RayTransportConfig::Http2 { path, hosts } => layers.push(Arc::new(
                    meow_transport::h2::H2Layer::new(meow_transport::h2::H2Config { path, hosts }),
                )),
                V2RayTransportConfig::Grpc {
                    service_name,
                    authority,
                } => layers.push(Arc::new(meow_transport::grpc::GrpcLayer::new(
                    meow_transport::grpc::GrpcConfig {
                        service_name,
                        authority,
                    },
                ))),
                V2RayTransportConfig::HttpUpgrade {
                    path,
                    host,
                    headers,
                } => layers.push(Arc::new(
                    meow_transport::httpupgrade::HttpUpgradeLayer::new(
                        meow_transport::httpupgrade::HttpUpgradeConfig {
                            path,
                            host_header: host,
                            extra_headers: headers,
                        },
                    ),
                )),
            }
        }
        Ok(Self {
            network,
            layers: Arc::new(layers),
            pinned_tls,
        })
    }
}

impl StreamTransport for LayeredTransport {
    fn connect(
        &self,
        _ctx: TransportContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            let stream = self
                .network
                .connect_tcp(TcpConnect { target })
                .await
                .map_err(|error| TransportError::new(error.message))?;
            let mut stream: Box<dyn meow_transport::Stream> =
                Box::new(ByteStreamAdapter(sync_wrapper::SyncWrapper::new(stream)));
            if let Some(tls) = &self.pinned_tls {
                stream = tls.connect(stream).await?;
            }
            for layer in self.layers.iter() {
                stream = layer
                    .connect(stream)
                    .await
                    .map_err(|error| TransportError::new(error.to_string()))?;
            }
            Ok(Box::new(MeowStreamAdapter(stream)) as Box<dyn ByteStream>)
        })
    }
}

#[derive(Clone)]
struct PinnedTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl PinnedTls {
    fn new(config: &TlsLayerConfig) -> Result<Self, TransportError> {
        let client = rustls_client_config(config)?;
        let server_name = config
            .server_name
            .clone()
            .ok_or_else(|| TransportError::new("TLS pinning requires server_name"))?;
        let server_name = ServerName::try_from(server_name)
            .map_err(|error| TransportError::new(format!("TLS server_name: {error}")))?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(client)),
            server_name,
        })
    }

    async fn connect(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Box<dyn meow_transport::Stream>, TransportError> {
        self.connector
            .connect(self.server_name.clone(), stream)
            .await
            .map(|stream| Box::new(stream) as Box<dyn meow_transport::Stream>)
            .map_err(|error| TransportError::new(format!("pinned TLS handshake: {error}")))
    }
}

/// Build the standard rustls client used by transports that need direct access
/// to TLS (for example QUIC). Certificate roots, mTLS, insecure mode and SPKI
/// pins therefore retain one implementation across TCP and QUIC protocols.
pub fn rustls_client_config(config: &TlsLayerConfig) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in &config.certificate_authorities_der {
        roots
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|error| TransportError::new(format!("TLS CA certificate: {error}")))?;
    }
    let web_pki =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()
            .map_err(|error| TransportError::new(format!("TLS verifier: {error}")))?;
    let verifier = Arc::new(PinnedServerVerifier {
        web_pki: (!config.insecure).then_some(web_pki),
        supported: provider.signature_verification_algorithms,
        pins: config.public_key_pins.clone(),
    });
    let wants_verifier = if let Some(ech) = &config.ech_config {
        use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
        let list = rustls::pki_types::EchConfigListBytes::from(ech.as_slice());
        let ech = rustls::client::EchConfig::new(list, ALL_SUPPORTED_SUITES)
            .map_err(|error| TransportError::new(format!("TLS ECH config: {error}")))?;
        ClientConfig::builder_with_provider(provider.clone())
            .with_ech(ech.into())
            .map_err(|error| TransportError::new(format!("TLS ECH setup: {error}")))?
    } else {
        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|error| TransportError::new(format!("TLS versions: {error}")))?
    };
    let builder = wants_verifier
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut client = match (
        &config.client_certificate_pem,
        &config.client_private_key_pem,
    ) {
        (Some(certificate), Some(private_key)) => {
            let certificates = rustls_pemfile::certs(&mut certificate.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| TransportError::new(format!("TLS client certificate: {error}")))?;
            let private_key = rustls_pemfile::private_key(&mut private_key.as_slice())
                .map_err(|error| TransportError::new(format!("TLS client key: {error}")))?
                .ok_or_else(|| TransportError::new("TLS client private key PEM is empty"))?;
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|error| TransportError::new(format!("TLS client identity: {error}")))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(TransportError::new(
                "TLS client certificate and key must be paired",
            ));
        }
    };
    client.alpn_protocols = config
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(client)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    web_pki: Option<Arc<WebPkiServerVerifier>>,
    supported: WebPkiSupportedAlgorithms,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(verifier) = &self.web_pki {
            verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let digest: [u8; 32] = Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into();
        if !self.pins.is_empty() && !self.pins.contains(&digest) {
            return Err(rustls::Error::General(
                "certificate SubjectPublicKeyInfo does not match any configured SHA-256 pin".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

struct ByteStreamAdapter(sync_wrapper::SyncWrapper<Box<dyn ByteStream>>);
struct MeowStreamAdapter(Box<dyn meow_transport::Stream>);

macro_rules! delegate_stream {
    ($name:ident) => {
        impl AsyncRead for $name {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for $name {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
    };
}

delegate_stream!(MeowStreamAdapter);

impl AsyncRead for ByteStreamAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.get_mut().0.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for ByteStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut **self.get_mut().0.get_mut()).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.get_mut().0.get_mut()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.get_mut().0.get_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustbox_kernel::TokioNetworkProvider;
    use rustls::ServerConfig;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn spki_pin_accepts_matching_key_and_rejects_wrong_key() {
        let identity = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = identity.cert.der().clone();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref()).unwrap();
        let pin: [u8; 32] = Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into();
        let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let server = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint: Endpoint = listener.local_addr().unwrap().to_string().parse().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut socket) = acceptor.accept(socket).await {
                        let mut byte = [0];
                        if socket.read_exact(&mut byte).await.is_ok() {
                            let _ = socket.write_all(&byte).await;
                        }
                    }
                });
            }
        });

        let network = Arc::new(TokioNetworkProvider::new());
        let matching = LayeredTransport::new(
            network.clone(),
            Some(TlsLayerConfig {
                enabled: true,
                server_name: Some("localhost".into()),
                insecure: true,
                public_key_pins: vec![pin],
                ..TlsLayerConfig::default()
            }),
            None,
        )
        .unwrap();
        let mut stream = matching
            .connect(TransportContext { network: &*network }, endpoint.clone())
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut echoed = [0];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, *b"x");

        let wrong = LayeredTransport::new(
            network.clone(),
            Some(TlsLayerConfig {
                enabled: true,
                server_name: Some("localhost".into()),
                insecure: true,
                public_key_pins: vec![[0x55; 32]],
                ..TlsLayerConfig::default()
            }),
            None,
        )
        .unwrap();
        let error = match wrong
            .connect(TransportContext { network: &*network }, endpoint)
            .await
        {
            Ok(_) => panic!("wrong SPKI pin was accepted"),
            Err(error) => error,
        };
        assert!(error.message.contains("SubjectPublicKeyInfo"));
        server_task.await.unwrap();
    }
}
