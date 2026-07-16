use crate::{
    CachingResolver, DnsConfig, DnsError, DnsQuery, DnsResponse, FakeIpAllocator, HickoryTransport,
    RecordingResolver, Resolver, ReverseDns, RuleBasedResolver,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Fully assembled concrete DNS graph. Only the cross-subsystem reverse map is shared.
pub struct DnsSubsystem {
    resolver: RecordingResolver<CachingResolver<RuleBasedResolver>>,
    reverse: Arc<ReverseDns>,
}

impl DnsSubsystem {
    pub fn from_config(config: DnsConfig) -> Result<Self, DnsError> {
        let final_server = config
            .final_server
            .clone()
            .or_else(|| config.servers.first().map(|server| server.id.clone()))
            .ok_or_else(|| DnsError::new("DNS needs at least one server or final_server"))?;
        let mut transports: HashMap<String, HickoryTransport> = HashMap::new();
        for server in config.servers {
            transports.insert(server.id.clone(), HickoryTransport::new(server)?);
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
        let rules = RuleBasedResolver::new(transports, config.rules, final_server, fake_ip);
        let cached = CachingResolver::new(rules, config.cache);
        let reverse = Arc::new(ReverseDns::new(4096));
        let resolver = RecordingResolver::new(cached, reverse.clone());
        Ok(Self { resolver, reverse })
    }
    pub fn reverse_dns(&self) -> Arc<ReverseDns> {
        self.reverse.clone()
    }
    pub async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        self.resolver.resolve(query).await
    }
}
