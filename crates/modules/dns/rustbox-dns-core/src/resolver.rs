use crate::{
    DnsAnswer, DnsError, DnsName, DnsQuery, DnsRecordType, DnsResponse, DnsRuleAction,
    DnsRuleConfig, DnsTransport, FakeIpAllocator, HickoryTransport, Resolver,
};
use rustbox_types::{Host, IpAddress};
use std::collections::HashMap;

pub struct RuleBasedResolver {
    transports: HashMap<String, HickoryTransport>,
    rules: Vec<DnsRuleConfig>,
    final_server: String,
    fake_ip: Option<FakeIpAllocator>,
}

impl RuleBasedResolver {
    pub fn new(
        transports: HashMap<String, HickoryTransport>,
        rules: Vec<DnsRuleConfig>,
        final_server: impl Into<String>,
        fake_ip: Option<FakeIpAllocator>,
    ) -> Self {
        Self {
            transports,
            rules,
            final_server: final_server.into(),
            fake_ip,
        }
    }
}

impl Resolver for RuleBasedResolver {
    async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        let action = self
            .rules
            .iter()
            .find(|rule| rule.matcher().matches(&query))
            .map(DnsRuleConfig::action)
            .unwrap_or_else(|| DnsRuleAction::Server(self.final_server.clone()));
        match action {
            DnsRuleAction::Server(server) => {
                self.transports
                    .get(&server)
                    .ok_or_else(|| DnsError::new(format!("unknown DNS server `{server}`")))?
                    .exchange(query)
                    .await
            }
            DnsRuleAction::FakeIp => self
                .fake_ip
                .as_ref()
                .ok_or_else(|| DnsError::new("DNS rule selected fake-ip but it is disabled"))?
                .resolve(query),
            DnsRuleAction::Reject => Ok(DnsResponse::empty()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StaticResolver {
    records: HashMap<DnsName, Vec<DnsAnswer>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert_v4(mut self, name: DnsName, address: [u8; 4], ttl_seconds: u32) -> Self {
        self.records.entry(name).or_default().push(DnsAnswer {
            host: Host::Ip(IpAddress::V4(address)),
            ttl_seconds,
        });
        self
    }
    pub fn insert_v6(mut self, name: DnsName, address: [u8; 16], ttl_seconds: u32) -> Self {
        self.records.entry(name).or_default().push(DnsAnswer {
            host: Host::Ip(IpAddress::V6(address)),
            ttl_seconds,
        });
        self
    }
}

impl Resolver for StaticResolver {
    async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        let answers = self
            .records
            .get(&query.name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|answer| {
                matches!(
                    (&answer.host, query.record_type),
                    (Host::Ip(IpAddress::V4(_)), DnsRecordType::A)
                        | (Host::Ip(IpAddress::V6(_)), DnsRecordType::Aaaa)
                )
            })
            .collect();
        Ok(DnsResponse { answers })
    }
}

impl<T: Resolver> DnsTransport for T {
    fn exchange(
        &self,
        query: DnsQuery,
    ) -> impl Future<Output = Result<DnsResponse, DnsError>> + Send {
        self.resolve(query)
    }
}
