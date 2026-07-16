use crate::{
    DnsAnswer, DnsError, DnsQuery, DnsRecordType, DnsResponse, DnsServerConfig, DnsServerProtocol,
    DnsTransport,
};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::xfer::Protocol;
use rustbox_types::{Host, IpAddress};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::sync::OnceCell;

/// One Tokio/Hickory adapter covers classic DNS and all encrypted transports.
pub struct HickoryTransport {
    server: DnsServerConfig,
    resolver: OnceCell<TokioResolver>,
}

impl HickoryTransport {
    pub fn new(server: DnsServerConfig) -> Result<Self, DnsError> {
        if server.outbound.is_some() {
            return Err(DnsError::new(format!(
                "DNS server `{}` requests an outbound; Hickory sockets currently support direct only",
                server.id
            )));
        }
        if matches!(
            server.protocol,
            DnsServerProtocol::Tls | DnsServerProtocol::Https | DnsServerProtocol::Quic
        ) && !matches!(server.endpoint.host, Host::Domain(_))
        {
            return Err(DnsError::new(format!(
                "encrypted DNS server `{}` needs a domain endpoint for TLS verification",
                server.id
            )));
        }
        Ok(Self {
            server,
            resolver: OnceCell::new(),
        })
    }

    async fn build(&self) -> Result<TokioResolver, DnsError> {
        let socket_addr = match &self.server.endpoint.host {
            Host::Ip(ip) => SocketAddr::new(to_std_ip(*ip), self.server.endpoint.port),
            Host::Domain(domain) => {
                tokio::net::lookup_host((domain.as_str(), self.server.endpoint.port))
                    .await
                    .map_err(|error| {
                        DnsError::new(format!("bootstrap lookup for `{domain}` failed: {error}"))
                    })?
                    .next()
                    .ok_or_else(|| {
                        DnsError::new(format!(
                            "bootstrap lookup for `{domain}` returned no address"
                        ))
                    })?
            }
        };
        let protocol = match self.server.protocol {
            DnsServerProtocol::Udp => Protocol::Udp,
            DnsServerProtocol::Tcp => Protocol::Tcp,
            DnsServerProtocol::Tls => Protocol::Tls,
            DnsServerProtocol::Https => Protocol::Https,
            DnsServerProtocol::Quic => Protocol::Quic,
        };
        let mut name_server = NameServerConfig::new(socket_addr, protocol);
        if let Host::Domain(domain) = &self.server.endpoint.host {
            name_server.tls_dns_name = Some(domain.clone());
        }
        if self.server.protocol == DnsServerProtocol::Https {
            name_server.http_endpoint = Some("/dns-query".to_string());
        }
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        builder.options_mut().cache_size = 0;
        builder.options_mut().attempts = 1;
        Ok(builder.build())
    }
}

impl DnsTransport for HickoryTransport {
    async fn exchange(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        let resolver = self.resolver.get_or_try_init(|| self.build()).await?;
        let record_type = match query.record_type {
            DnsRecordType::A => RecordType::A,
            DnsRecordType::Aaaa => RecordType::AAAA,
        };
        let lookup = resolver
            .lookup(format!("{}.", query.name.as_str()), record_type)
            .await
            .map_err(|error| {
                DnsError::new(format!(
                    "DNS server `{}` query failed: {error}",
                    self.server.id
                ))
            })?;
        let answers = lookup
            .record_iter()
            .filter_map(|record| match record.data() {
                RData::A(value) => Some(DnsAnswer {
                    host: Host::Ip(IpAddress::V4(value.0.octets())),
                    ttl_seconds: record.ttl(),
                }),
                RData::AAAA(value) => Some(DnsAnswer {
                    host: Host::Ip(IpAddress::V6(value.0.octets())),
                    ttl_seconds: record.ttl(),
                }),
                _ => None,
            })
            .collect();
        Ok(DnsResponse { answers })
    }
}

fn to_std_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(value) => IpAddr::V4(Ipv4Addr::from(value)),
        IpAddress::V6(value) => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{RData, Record};
    use rustbox_types::Endpoint;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn exchanges_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut packet = vec![0; 2048];
            let (len, peer) = server.recv_from(&mut packet).await.expect("receive");
            let response = response(&packet[..len]);
            server.send_to(&response, peer).await.expect("send");
        });
        assert_transport(DnsServerProtocol::Udp, port).await;
    }

    #[tokio::test]
    async fn exchanges_over_tcp() {
        let server = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.expect("accept");
            let len = stream.read_u16().await.expect("length") as usize;
            let mut packet = vec![0; len];
            stream.read_exact(&mut packet).await.expect("receive");
            let response = response(&packet);
            stream
                .write_u16(response.len() as u16)
                .await
                .expect("length");
            stream.write_all(&response).await.expect("send");
        });
        assert_transport(DnsServerProtocol::Tcp, port).await;
    }

    async fn assert_transport(protocol: DnsServerProtocol, port: u16) {
        let transport = HickoryTransport::new(DnsServerConfig {
            id: "local".to_string(),
            protocol,
            endpoint: Endpoint::localhost_v4(port),
            outbound: None,
        })
        .expect("transport");
        let result = transport
            .exchange(DnsQuery {
                name: crate::DnsName::new("transport.test").expect("name"),
                record_type: DnsRecordType::A,
            })
            .await
            .expect("exchange");
        assert_eq!(
            result.answers[0].host,
            Host::Ip(IpAddress::V4([203, 0, 113, 9]))
        );
    }

    fn response(packet: &[u8]) -> Vec<u8> {
        let request = Message::from_vec(packet).expect("query");
        let query = request.queries()[0].clone();
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .add_query(query.clone())
            .add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
            ));
        response.to_vec().expect("response")
    }
}
