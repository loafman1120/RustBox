//! VMess AEAD outbound adapted from `madeye/meow-rs` commit
//! `0609fed0da813496899a85d3d52e10719552aa63`.
//!
//! The copied crypto and framing modules are kept local; this crate has no
//! `meow-*` dependency. Runtime connection setup uses RustBox host capabilities.

mod body;
mod conn;
mod header;
mod kdf;

use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, NetworkProvider, TcpConnect};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
struct Metadata {
    host: String,
    dst_ip: Option<IpAddr>,
    dst_port: u16,
}

impl Metadata {
    fn from_endpoint(endpoint: &Endpoint) -> Self {
        match &endpoint.host {
            Host::Domain(domain) => Self {
                host: domain.clone(),
                dst_ip: None,
                dst_port: endpoint.port,
            },
            Host::Ip(IpAddress::V4(octets)) => Self {
                host: String::new(),
                dst_ip: Some(IpAddr::V4(Ipv4Addr::from(*octets))),
                dst_port: endpoint.port,
            },
            Host::Ip(IpAddress::V6(octets)) => Self {
                host: String::new(),
                dst_ip: Some(IpAddr::V6(Ipv6Addr::from(*octets))),
                dst_port: endpoint.port,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VmessTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessConfigError {
    pub message: String,
}

pub struct VmessOutbound {
    id: OutboundId,
    server: Endpoint,
    command_key: [u8; 16],
    security: header::Security,
    tls: Option<(ServerName<'static>, Arc<ClientConfig>)>,
    network: Arc<dyn NetworkProvider>,
}

impl VmessOutbound {
    pub fn new(
        id: OutboundId,
        server: Endpoint,
        uuid: &str,
        security: Option<&str>,
        tls: VmessTlsConfig,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self, VmessConfigError> {
        let uuid = Uuid::parse_str(uuid).map_err(|error| VmessConfigError {
            message: format!("invalid VMess UUID: {error}"),
        })?;
        let security = match security.unwrap_or("auto").to_ascii_lowercase().as_str() {
            "auto" => header::auto_security(),
            "aes-128-gcm" | "aes128gcm" => header::Security::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => header::Security::ChaCha20Poly1305,
            "none" => header::Security::None,
            value => {
                return Err(VmessConfigError {
                    message: format!("unsupported VMess security `{value}`"),
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
            command_key: header::cmd_key(uuid.as_bytes()),
            security,
            tls,
            network,
        })
    }

    async fn connect(&self, target: &Endpoint) -> Result<Box<dyn ByteStream>, OutboundError> {
        let stream = self
            .network
            .connect_tcp(TcpConnect {
                target: self.server.clone(),
            })
            .await
            .map_err(|error| OutboundError::new(error.message))?;
        let mut stream: Box<dyn ByteStream> = match &self.tls {
            Some((name, config)) => Box::new(
                TlsConnector::from(config.clone())
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|error| {
                        OutboundError::new(format!("VMess TLS handshake failed: {error}"))
                    })?,
            ),
            None => stream,
        };
        let sealed = header::seal_request_header(
            &self.command_key,
            self.security,
            &Metadata::from_endpoint(target),
            false,
        )
        .map_err(OutboundError::new)?;
        stream
            .write_all(&sealed.bytes)
            .await
            .map_err(|error| OutboundError::new(format!("write VMess request: {error}")))?;
        let read_cipher = body::BodyCipher::new(
            self.security,
            &sealed.req_key,
            &sealed.req_iv,
            sealed.resp_v,
        );
        let write_cipher = body::BodyCipher::new(
            self.security,
            &sealed.req_key,
            &sealed.req_iv,
            sealed.resp_v,
        );
        Ok(Box::new(conn::spawn_vmess_relay(
            stream,
            read_cipher,
            write_cipher,
            sealed.resp_v,
        )))
    }
}

impl Outbound for VmessOutbound {
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
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async { Err(OutboundError::new("VMess UDP is not implemented")) })
    }
}

fn tls_client_config(tls: &VmessTlsConfig) -> Result<Arc<ClientConfig>, VmessConfigError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| VmessConfigError {
            message: format!("failed to select VMess TLS versions: {error}"),
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
) -> Result<ServerName<'static>, VmessConfigError> {
    let host = configured
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| server.host.to_string());
    ServerName::try_from(host.clone()).map_err(|error| VmessConfigError {
        message: format!("invalid VMess TLS server name `{host}`: {error}"),
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
    fn metadata_preserves_domain() {
        let metadata = Metadata::from_endpoint(&Endpoint::new(Host::domain("example.com"), 443));
        assert_eq!(metadata.host, "example.com");
        assert_eq!(metadata.dst_port, 443);
    }
}
