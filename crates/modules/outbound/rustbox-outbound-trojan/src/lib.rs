//! Trojan outbound adapted from `madeye/meow-rs` at commit
//! `0609fed0da813496899a85d3d52e10719552aa63`.
//!
//! The wire header and address encoding follow the upstream implementation.
//! Runtime integration is native RustBox and has no `meow-*` dependency.

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
use sha2::{Digest, Sha224};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrojanTlsConfig {
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanConfigError {
    pub message: String,
}

pub struct TrojanOutbound {
    id: OutboundId,
    server: Endpoint,
    password_hash: [u8; 56],
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    network: Arc<dyn NetworkProvider>,
}

impl TrojanOutbound {
    pub fn new(
        id: OutboundId,
        server: Endpoint,
        password: &str,
        tls: TrojanTlsConfig,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self, TrojanConfigError> {
        if password.is_empty() {
            return Err(TrojanConfigError {
                message: "trojan password must not be empty".to_string(),
            });
        }
        let digest = Sha224::digest(password.as_bytes());
        let mut password_hash = [0_u8; 56];
        encode_hex(&digest, &mut password_hash);
        let server_name = tls_server_name(tls.server_name.as_deref(), &server)?;
        let tls_config = tls_client_config(&tls)?;
        Ok(Self {
            id,
            server,
            password_hash,
            server_name,
            tls_config,
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
        let connector = TlsConnector::from(self.tls_config.clone());
        let mut stream = connector
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(|error| OutboundError::new(format!("trojan TLS handshake failed: {error}")))?;
        let header = build_header(&self.password_hash, CMD_CONNECT, target)?;
        stream
            .write_all(&header)
            .await
            .map_err(|error| OutboundError::new(format!("write trojan request: {error}")))?;
        stream
            .flush()
            .await
            .map_err(|error| OutboundError::new(format!("flush trojan request: {error}")))?;
        Ok(Box::new(stream))
    }
}

impl Outbound for TrojanOutbound {
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
        Box::pin(async {
            Err(OutboundError::new(
                "trojan UDP-over-TCP is not wired into RustBox yet",
            ))
        })
    }
}

fn build_header(
    password_hash: &[u8; 56],
    command: u8,
    target: &Endpoint,
) -> Result<Vec<u8>, OutboundError> {
    let mut header = Vec::with_capacity(320);
    header.extend_from_slice(password_hash);
    header.extend_from_slice(b"\r\n");
    header.push(command);
    encode_endpoint(&mut header, target)?;
    header.extend_from_slice(b"\r\n");
    Ok(header)
}

fn encode_endpoint(output: &mut Vec<u8>, endpoint: &Endpoint) -> Result<(), OutboundError> {
    match &endpoint.host {
        Host::Ip(IpAddress::V4(octets)) => {
            output.push(ATYP_IPV4);
            output.extend_from_slice(octets);
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| OutboundError::new("trojan target domain exceeds 255 bytes"))?;
            output.push(ATYP_DOMAIN);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddress::V6(octets)) => {
            output.push(ATYP_IPV6);
            output.extend_from_slice(octets);
        }
    }
    output.extend_from_slice(&endpoint.port.to_be_bytes());
    Ok(())
}

fn encode_hex(input: &[u8], output: &mut [u8; 56]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in input.iter().copied().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
}

fn tls_client_config(tls: &TrojanTlsConfig) -> Result<Arc<ClientConfig>, TrojanConfigError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| TrojanConfigError {
            message: format!("failed to select trojan TLS protocol versions: {error}"),
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
) -> Result<ServerName<'static>, TrojanConfigError> {
    let host = configured
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| server.host.to_string());
    ServerName::try_from(host.clone()).map_err(|error| TrojanConfigError {
        message: format!("invalid trojan TLS server name `{host}`: {error}"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_matches_trojan_wire_shape() {
        let digest = Sha224::digest(b"secret");
        let mut password_hash = [0_u8; 56];
        encode_hex(&digest, &mut password_hash);
        let target = Endpoint::new(Host::domain("example.com"), 443);
        let header = build_header(&password_hash, CMD_CONNECT, &target).expect("header");
        assert_eq!(
            &header[..56],
            b"95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"
        );
        assert_eq!(&header[56..59], b"\r\n\x01");
        assert_eq!(header[59], ATYP_DOMAIN);
        assert_eq!(header[60], 11);
        assert_eq!(&header[61..72], b"example.com");
        assert_eq!(&header[72..], b"\x01\xbb\r\n");
    }

    #[test]
    fn rejects_overlong_domain() {
        let target = Endpoint::new(Host::domain("a".repeat(256)), 443);
        let error = build_header(&[b'0'; 56], CMD_CONNECT, &target).expect_err("must fail");
        assert!(error.message.contains("255"));
    }
}
