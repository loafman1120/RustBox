use crate::DnsSocketProvider;
use crate::{
    CachingResolver, DnsConfig, DnsError, DnsName, DnsQuery, DnsRecordType, DnsResponse,
    DnsTransport, FakeIpAllocator, HickoryTransport, RecordingResolver, Resolver, ReverseDns,
    RuleBasedResolver,
};
use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use rustbox_types::Host;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Fully assembled concrete DNS graph. Only the cross-subsystem reverse map is shared.
pub struct DnsSubsystem {
    resolver: RecordingResolver<CachingResolver<RuleBasedResolver>>,
    transports: HashMap<String, Arc<HickoryTransport>>,
    reverse: Arc<ReverseDns>,
}

impl DnsSubsystem {
    pub fn from_config(config: DnsConfig) -> Result<Self, DnsError> {
        Self::from_config_with_sockets(config, HashMap::new())
    }

    pub fn from_config_with_sockets(
        config: DnsConfig,
        sockets: HashMap<String, Arc<dyn DnsSocketProvider>>,
    ) -> Result<Self, DnsError> {
        let final_server = config
            .final_server
            .clone()
            .or_else(|| config.servers.first().map(|server| server.id.clone()))
            .ok_or_else(|| DnsError::new("DNS needs at least one server or final_server"))?;
        let mut transports: HashMap<String, Arc<HickoryTransport>> = HashMap::new();
        for server in config.servers {
            let id = server.id.clone();
            let mut transport = HickoryTransport::new(server)?;
            if let Some(provider) = sockets.get(&id) {
                transport = transport.with_socket_provider(provider.clone());
            }
            transports.insert(id, Arc::new(transport));
        }
        if !transports.contains_key(&final_server) {
            return Err(DnsError::new(format!(
                "unknown final DNS server `{final_server}`"
            )));
        }
        let fake_ip = config
            .fake_ip
            .filter(|item| item.enabled)
            .map(FakeIpAllocator::new)
            .transpose()?;
        let rules = RuleBasedResolver::new(transports.clone(), config.rules, final_server, fake_ip);
        let cached = CachingResolver::new(rules, config.cache);
        let reverse = Arc::new(ReverseDns::new(4096));
        let resolver = RecordingResolver::new(cached, reverse.clone());
        Ok(Self {
            resolver,
            transports,
            reverse,
        })
    }
    pub fn reverse_dns(&self) -> Arc<ReverseDns> {
        self.reverse.clone()
    }
    pub async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        self.resolver.resolve(query).await
    }

    pub async fn resolve_with_server(
        &self,
        server: &str,
        query: DnsQuery,
    ) -> Result<DnsResponse, DnsError> {
        self.transports
            .get(server)
            .ok_or_else(|| DnsError::new(format!("unknown DNS server `{server}`")))?
            .exchange(query)
            .await
    }

    /// Resolve one DNS wire-format request and preserve its transaction/query
    /// metadata in the response. This is shared by UDP and TCP route hijacks.
    pub async fn exchange_wire(&self, packet: &[u8]) -> Result<Vec<u8>, DnsError> {
        let request = Message::from_vec(packet)
            .map_err(|error| DnsError::new(format!("decode DNS request: {error}")))?;
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code())
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true);
        for query in request.queries() {
            response.add_query(query.clone());
        }
        let Some(query) = request.queries().first() else {
            response.set_response_code(ResponseCode::FormErr);
            return response
                .to_vec()
                .map_err(|error| DnsError::new(format!("encode DNS response: {error}")));
        };
        if request.queries().len() != 1 {
            response.set_response_code(ResponseCode::FormErr);
        } else {
            let record_type = match query.query_type() {
                RecordType::A => Some(DnsRecordType::A),
                RecordType::AAAA => Some(DnsRecordType::Aaaa),
                RecordType::CNAME => Some(DnsRecordType::Cname),
                RecordType::MX => Some(DnsRecordType::Mx),
                RecordType::NS => Some(DnsRecordType::Ns),
                RecordType::PTR => Some(DnsRecordType::Ptr),
                RecordType::SOA => Some(DnsRecordType::Soa),
                RecordType::SRV => Some(DnsRecordType::Srv),
                RecordType::TXT => Some(DnsRecordType::Txt),
                RecordType::CAA => Some(DnsRecordType::Caa),
                RecordType::HTTPS => Some(DnsRecordType::Https),
                RecordType::SVCB => Some(DnsRecordType::Svcb),
                RecordType::NAPTR => Some(DnsRecordType::Naptr),
                RecordType::TLSA => Some(DnsRecordType::Tlsa),
                RecordType::DS => Some(DnsRecordType::Ds),
                RecordType::DNSKEY => Some(DnsRecordType::Dnskey),
                RecordType::ANY => Some(DnsRecordType::Any),
                other => Some(DnsRecordType::Other(other.into())),
            };
            if let Some(record_type) = record_type {
                let dns_query = DnsQuery {
                    name: DnsName::new(query.name().to_utf8())?,
                    record_type,
                };
                match self.resolve(dns_query).await {
                    Ok(answer) => {
                        for record in &answer.records {
                            response.add_answer(record.clone());
                        }
                        for answer in answer
                            .answers
                            .into_iter()
                            .filter(|_| answer.records.is_empty())
                        {
                            let data = match answer.host {
                                Host::Ip(IpAddr::V4(value)) => Some(RData::A(A(value))),
                                Host::Ip(IpAddr::V6(value)) => Some(RData::AAAA(AAAA(value))),
                                Host::Domain(_) => None,
                            };
                            if let Some(data) = data {
                                response.add_answer(Record::from_rdata(
                                    query.name().clone(),
                                    answer.ttl_seconds,
                                    data,
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        response.set_response_code(ResponseCode::ServFail);
                    }
                }
            } else {
                response.set_response_code(ResponseCode::NotImp);
            }
        }
        response
            .to_vec()
            .map_err(|error| DnsError::new(format!("encode DNS response: {error}")))
    }
}
