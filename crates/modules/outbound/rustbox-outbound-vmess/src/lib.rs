//! VMess AEAD outbound adapted from `madeye/meow-rs` commit
//! `0609fed0da813496899a85d3d52e10719552aa63`.
//!
//! The copied crypto and framing modules are kept local; this crate has no
//! `meow-*` dependency. Runtime connection setup uses RustBox host capabilities.

mod body;
mod conn;
mod datagram;
mod header;
mod kdf;

use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{BoxFuture, NetworkProvider, TaskScope, TcpConnect};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_runtime_config::TlsClientConfig;
use rustbox_transport::{
    StreamTransport, TransportContext, rustls_client_config, rustls_server_name,
};
use rustbox_types::{Endpoint, Host, OutboundId};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
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
            Host::Ip(IpAddr::V4(octets)) => Self {
                host: String::new(),
                dst_ip: Some(IpAddr::V4(*octets)),
                dst_port: endpoint.port,
            },
            Host::Ip(IpAddr::V6(octets)) => Self {
                host: String::new(),
                dst_ip: Some(IpAddr::V6(*octets)),
                dst_port: endpoint.port,
            },
        }
    }
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
    sessions: TaskScope,
    transport: Option<Arc<dyn StreamTransport>>,
}

impl VmessOutbound {
    pub fn new(
        id: OutboundId,
        server: Endpoint,
        uuid: Uuid,
        security: Option<&str>,
        tls: TlsClientConfig,
        network: Arc<dyn NetworkProvider>,
        sessions: TaskScope,
    ) -> Result<Self, VmessConfigError> {
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
                rustls_server_name(&tls, &server).map_err(config_error)?,
                Arc::new(rustls_client_config(&tls).map_err(config_error)?),
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
            sessions,
            transport: None,
        })
    }

    pub fn with_transport(mut self, transport: Arc<dyn StreamTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    async fn connect_protocol(
        &self,
        target: &Endpoint,
        is_udp: bool,
    ) -> Result<VmessProtocolStream, OutboundError> {
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
            (None, Some((name, config))) => Box::new(
                TlsConnector::from(config.clone())
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|error| {
                        OutboundError::new(format!("VMess TLS handshake failed: {error}"))
                    })?,
            ),
            (None, None) => stream,
        };
        let sealed = header::seal_request_header(
            &self.command_key,
            self.security,
            &Metadata::from_endpoint(target),
            is_udp,
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
        Ok(VmessProtocolStream {
            stream,
            read_cipher,
            write_cipher,
            resp_v: sealed.resp_v,
        })
    }

    async fn connect(&self, target: &Endpoint) -> Result<Box<dyn ByteStream>, OutboundError> {
        let protocol = self.connect_protocol(target, false).await?;
        Ok(Box::new(conn::spawn_vmess_relay(
            &self.sessions,
            protocol.stream,
            protocol.read_cipher,
            protocol.write_cipher,
            protocol.resp_v,
        )))
    }
}

struct VmessProtocolStream {
    stream: Box<dyn ByteStream>,
    read_cipher: body::BodyCipher,
    write_cipher: body::BodyCipher,
    resp_v: u8,
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
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            let protocol = self.connect_protocol(&target, true).await?;
            Ok(Box::new(datagram::VmessDatagram::new(
                protocol.stream,
                protocol.read_cipher,
                protocol.write_cipher,
                protocol.resp_v,
                target,
            )) as Box<dyn DatagramSocket>)
        })
    }
}

fn config_error(error: rustbox_transport::TransportError) -> VmessConfigError {
    VmessConfigError {
        message: format!("VMess {}", error.message),
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
