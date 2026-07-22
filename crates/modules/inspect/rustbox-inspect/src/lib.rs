//! Bounded, replay-safe protocol sniffing before routing.
//!
//! Parsing, replay and DNS response observation are isolated modules; protocol parsing
//! is delegated to rustls, httparse, clienthello and Hickory.

mod config;
mod observe;
mod protocol;

pub use config::SniffConfig;
pub use rustbox_dns_core::ReverseDns;

use clienthello::Extractor as QuicClientHello;
use core::pin::Pin;
use observe::{ObservedDatagram, ObservedStream};
use protocol::{SniffResult, sniff_tcp, sniff_udp};
use rustbox_io::{ByteStream, DatagramSocket, IoError};
use rustbox_kernel::{
    ConnectionKey, Flow, FlowDirection, FlowPayload, InspectError, MetadataEnricher,
    NetworkMetadataLookup, ProcessLookup,
};
use rustbox_types::{Endpoint, Host, ProtocolHint};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::time::{Instant, timeout_at};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticDomainEnricher {
    domain: Host,
}
impl StaticDomainEnricher {
    pub fn new(domain: Host) -> Self {
        Self { domain }
    }
}
impl MetadataEnricher for StaticDomainEnricher {
    fn name(&self) -> &'static str {
        "static-domain"
    }
    async fn enrich(&self, mut flow: Flow) -> Result<Flow, InspectError> {
        flow.meta.domain = Some(self.domain.clone());
        Ok(flow)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticProtocolHintEnricher {
    hint: ProtocolHint,
}
impl StaticProtocolHintEnricher {
    pub fn new(hint: ProtocolHint) -> Self {
        Self { hint }
    }
}
impl MetadataEnricher for StaticProtocolHintEnricher {
    fn name(&self) -> &'static str {
        "static-protocol-hint"
    }
    async fn enrich(&self, mut flow: Flow) -> Result<Flow, InspectError> {
        flow.meta.protocol_hint = Some(self.hint);
        Ok(flow)
    }
}

#[derive(Clone)]
pub struct ProtocolSniffer {
    config: SniffConfig,
    reverse_dns: Arc<ReverseDns>,
}
impl ProtocolSniffer {
    pub fn new(config: SniffConfig) -> Self {
        Self::with_reverse_dns(config, Arc::new(ReverseDns::new(4096)))
    }
    pub fn with_reverse_dns(config: SniffConfig, reverse_dns: Arc<ReverseDns>) -> Self {
        Self {
            config,
            reverse_dns,
        }
    }
    pub fn reverse_dns(&self) -> Arc<ReverseDns> {
        self.reverse_dns.clone()
    }
}
impl Default for ProtocolSniffer {
    fn default() -> Self {
        Self::new(SniffConfig::default())
    }
}

/// Single concrete enrichment pipeline used by the engine. It keeps the hot
/// routing path synchronous while performing process ownership and bounded
/// protocol sniffing asynchronously before route evaluation.
#[derive(Clone)]
pub struct FlowEnricher {
    sniffer: ProtocolSniffer,
    process_lookup: Option<Arc<dyn ProcessLookup>>,
    network_lookup: Option<Arc<dyn NetworkMetadataLookup>>,
}

impl FlowEnricher {
    pub fn new(sniffer: ProtocolSniffer, process_lookup: Option<Arc<dyn ProcessLookup>>) -> Self {
        Self {
            sniffer,
            process_lookup,
            network_lookup: None,
        }
    }

    pub fn with_network_lookup(mut self, lookup: Option<Arc<dyn NetworkMetadataLookup>>) -> Self {
        self.network_lookup = lookup;
        self
    }
}

impl MetadataEnricher for FlowEnricher {
    fn name(&self) -> &'static str {
        "flow-enricher"
    }

    async fn enrich(&self, mut flow: Flow) -> Result<Flow, InspectError> {
        let key = ConnectionKey {
            network: flow.meta.network,
            local: flow.meta.source.clone(),
            remote: flow.meta.destination.clone(),
            direction: FlowDirection::Inbound,
        };
        let process_key = key.clone();
        let process = async {
            match &self.process_lookup {
                Some(lookup) => lookup.lookup(process_key).await.ok().flatten(),
                None => None,
            }
        };
        let network = async {
            match &self.network_lookup {
                Some(lookup) => lookup.lookup_network(key).await.ok(),
                None => None,
            }
        };
        let (process, network) = tokio::join!(process, network);
        if let Some(metadata) = process {
            flow.meta.platform.process = Some(metadata);
        }
        if let Some(info) = network {
            if flow.meta.platform.interface.is_none() {
                flow.meta.platform.interface = info.interface;
            }
            flow.meta.platform.wifi_ssid = info.wifi_ssid;
            flow.meta.platform.wifi_bssid = info.wifi_bssid;
            flow.meta.platform.network_type = info.network_type;
        }
        self.sniffer.enrich(flow).await
    }
}

impl MetadataEnricher for ProtocolSniffer {
    fn name(&self) -> &'static str {
        "protocol-sniffer"
    }
    async fn enrich(&self, mut flow: Flow) -> Result<Flow, InspectError> {
        if flow.meta.domain.is_none()
            && let Host::Ip(ip) = &flow.meta.destination.host
            && let Some(domain) = self.reverse_dns.lookup(*ip)
        {
            flow.meta.domain = Some(Host::domain(domain));
        }
        match flow.payload {
            FlowPayload::Stream(stream) => {
                let (stream, prefix, result) = sniff_stream(stream, self.config).await;
                apply_result(&mut flow.meta.domain, &mut flow.meta.protocol_hint, &result);
                flow.payload = FlowPayload::Stream(Box::new(ObservedStream::new(
                    stream,
                    prefix,
                    result.dns_query,
                    self.reverse_dns.clone(),
                )));
            }
            FlowPayload::Datagram(socket) => {
                let (socket, replay, result) = sniff_datagrams(socket, self.config).await;
                apply_result(&mut flow.meta.domain, &mut flow.meta.protocol_hint, &result);
                flow.payload = FlowPayload::Datagram(Box::new(ObservedDatagram {
                    inner: socket,
                    replay,
                    query: result.dns_query,
                    reverse: self.reverse_dns.clone(),
                }));
            }
        }
        Ok(flow)
    }
}

fn apply_result(
    domain: &mut Option<Host>,
    protocol_hint: &mut Option<ProtocolHint>,
    result: &SniffResult,
) {
    if domain.is_none()
        && let Some(value) = &result.domain
    {
        *domain = Some(Host::domain(value.clone()));
    }
    if protocol_hint.is_none() {
        *protocol_hint = result.protocol;
    }
}

async fn sniff_stream(
    mut stream: Box<dyn ByteStream>,
    config: SniffConfig,
) -> (Box<dyn ByteStream>, Vec<u8>, SniffResult) {
    let deadline = Instant::now() + config.timeout;
    let mut prefix = Vec::with_capacity(config.max_bytes.min(4096));
    while prefix.len() < config.max_bytes {
        let old = prefix.len();
        prefix.resize((old + 2048).min(config.max_bytes), 0);
        match timeout_at(deadline, stream.read(&mut prefix[old..])).await {
            Err(_) | Ok(Ok(0)) | Ok(Err(_)) => {
                prefix.truncate(old);
                break;
            }
            Ok(Ok(read)) => prefix.truncate(old + read),
        }
        let found = sniff_tcp(&prefix);
        if found.protocol.is_some() {
            return (stream, prefix, found);
        }
    }
    let found = sniff_tcp(&prefix);
    (stream, prefix, found)
}

async fn sniff_datagrams(
    mut socket: Box<dyn DatagramSocket>,
    config: SniffConfig,
) -> (
    Box<dyn DatagramSocket>,
    VecDeque<(Vec<u8>, Endpoint)>,
    SniffResult,
) {
    let deadline = Instant::now() + config.timeout;
    let mut replay = VecDeque::new();
    let mut total = 0;
    let mut quic = QuicClientHello::new();
    for _ in 0..config.max_datagrams {
        let mut packet = vec![0; (config.max_bytes - total).min(65_535)];
        if packet.is_empty() {
            break;
        }
        let Ok(Ok((len, endpoint))) =
            timeout_at(deadline, recv_datagram(&mut *socket, &mut packet)).await
        else {
            break;
        };
        packet.truncate(len);
        total += len;
        let found = sniff_udp(&packet, &mut quic);
        replay.push_back((packet, endpoint));
        if found.protocol.is_some() {
            return (socket, replay, found);
        }
    }
    (socket, replay, SniffResult::default())
}

async fn recv_datagram(
    socket: &mut dyn DatagramSocket,
    buf: &mut [u8],
) -> Result<(usize, Endpoint), IoError> {
    std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, buf)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_test_host::MemoryStream;
    use rustbox_types::{FlowId, FlowMeta, InboundId, Network};
    use std::net::IpAddr;

    #[tokio::test]
    async fn replays_stream_prefix_after_http_sniff() {
        let request = b"GET / HTTP/1.1\r\nHost: replay.example\r\n\r\n".to_vec();
        let flow = Flow {
            meta: FlowMeta {
                id: FlowId::new(NonZeroU64::new(1).unwrap()),
                network: Network::Tcp,
                source: Endpoint::localhost_v4(12345),
                destination: Endpoint::new(Host::Ip(IpAddr::from([203, 0, 113, 1])), 80),
                inbound: InboundId::new(NonZeroU64::new(1).unwrap()),
                domain: None,
                protocol_hint: None,
                platform: Default::default(),
            },
            payload: FlowPayload::Stream(Box::new(MemoryStream::with_read_data(request.clone()))),
        };
        let mut flow = ProtocolSniffer::default()
            .enrich(flow)
            .await
            .expect("sniff");
        assert_eq!(flow.meta.domain, Some(Host::domain("replay.example")));
        assert_eq!(flow.meta.protocol_hint, Some(ProtocolHint::Http));
        let FlowPayload::Stream(stream) = &mut flow.payload else {
            panic!("stream")
        };
        let mut replay = Vec::new();
        stream.read_to_end(&mut replay).await.expect("replay");
        assert_eq!(replay, request);
    }
}
