use clienthello::{Extractor as QuicClientHello, PushOutcome};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use rustbox_types::ProtocolHint;
use rustls::server::Acceptor;
use std::io::Cursor;
use std::net::IpAddr;

#[derive(Default)]
pub(crate) struct SniffResult {
    pub protocol: Option<ProtocolHint>,
    pub domain: Option<String>,
    pub dns_query: Option<DnsQueryMeta>,
}

#[derive(Clone)]
pub(crate) struct DnsQueryMeta {
    pub id: u16,
    pub name: String,
}

pub(crate) fn sniff_tcp(data: &[u8]) -> SniffResult {
    if let Some(domain) = tls_sni(data) {
        return result(ProtocolHint::Tls, Some(domain), None);
    }
    if let Some(domain) = http_host(data) {
        return result(ProtocolHint::Http, Some(domain), None);
    }
    if data.len() >= 2 {
        let declared = usize::from(u16::from_be_bytes([data[0], data[1]]));
        if let Some(query) = dns_query(data.get(2..).unwrap_or_default())
            && declared <= data.len().saturating_sub(2)
        {
            return result(ProtocolHint::Dns, None, Some(query));
        }
    }
    SniffResult::default()
}

pub(crate) fn sniff_udp(data: &[u8], quic: &mut QuicClientHello) -> SniffResult {
    if let Some(query) = dns_query(data) {
        return result(ProtocolHint::Dns, None, Some(query));
    }
    match quic.push(data) {
        Ok(PushOutcome::Sni(domain)) => result(ProtocolHint::Quic, Some(domain), None),
        Ok(PushOutcome::NeedMore) | Err(_) => SniffResult::default(),
    }
}

fn result(
    protocol: ProtocolHint,
    domain: Option<String>,
    dns_query: Option<DnsQueryMeta>,
) -> SniffResult {
    SniffResult {
        protocol: Some(protocol),
        domain,
        dns_query,
    }
}

pub(crate) fn tls_sni(data: &[u8]) -> Option<String> {
    let mut acceptor = Acceptor::default();
    acceptor.read_tls(&mut Cursor::new(data)).ok()?;
    acceptor
        .accept()
        .ok()??
        .client_hello()
        .server_name()
        .map(str::to_ascii_lowercase)
}

fn http_host(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(data).ok()?.is_complete().then_some(())?;
    let value = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))?
        .value;
    normalize_authority(std::str::from_utf8(value).ok()?.trim())
}

fn normalize_authority(value: &str) -> Option<String> {
    let host = if let Some(rest) = value.strip_prefix('[') {
        rest.split_once(']')?.0
    } else {
        value.split_once(':').map_or(value, |(host, _)| host)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

pub(crate) fn dns_query(packet: &[u8]) -> Option<DnsQueryMeta> {
    let message = Message::from_vec(packet).ok()?;
    if message.message_type() != MessageType::Query {
        return None;
    }
    message.queries().first().map(|query| DnsQueryMeta {
        id: message.id(),
        name: query
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
    })
}

pub(crate) fn dns_response_addresses(packet: &[u8], query_id: u16) -> Vec<(IpAddr, u32)> {
    let Ok(message) = Message::from_vec(packet) else {
        return Vec::new();
    };
    if message.message_type() != MessageType::Response || message.id() != query_id {
        return Vec::new();
    }
    message
        .answers()
        .iter()
        .filter_map(|answer| match answer.data() {
            RData::A(value) => Some((IpAddr::V4(value.0), answer.ttl())),
            RData::AAAA(value) => Some((IpAddr::V6(value.0), answer.ttl())),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn parses_http_host() {
        let value = sniff_tcp(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n");
        assert_eq!(value.protocol, Some(ProtocolHint::Http));
        assert_eq!(value.domain.as_deref(), Some("example.com"));
    }
    #[test]
    fn parses_dns_query() {
        let p = [
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert_eq!(
            dns_query(&p).map(|q| q.name).as_deref(),
            Some("example.com")
        );
    }
    #[test]
    fn parses_tls_sni() {
        use rustls::client::ClientConnection;
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, RootCertStore};
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("tls.example")
                .expect("name")
                .to_owned(),
        )
        .expect("client");
        let mut hello = Vec::new();
        client.write_tls(&mut hello).expect("hello");
        assert_eq!(tls_sni(&hello).as_deref(), Some("tls.example"));
    }
}
