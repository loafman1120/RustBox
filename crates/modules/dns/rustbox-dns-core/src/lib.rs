//! 可移植 DNS 核心契约和轻量解析链。
//!
//! DNS 是独立子系统，不隐藏在路由器内部。这里定义配置模型、transport
//! 契约、缓存、规则和 FakeIP；真实 UDP/TCP/DoH/DoT/DoQ I/O 由后续 adapter
//! 通过 `DnsTransport` 接入。

use rustbox_kernel::{BoxFuture, Clock};
use rustbox_types::{Endpoint, Host, IpAddress, IpCidr, Network};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// DNS 解析接口，输入查询，输出响应，不直接决定代理路由。
pub trait Resolver: Send + Sync {
    fn resolve(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>>;
}

/// DNS transport 契约。UDP/TCP/DoH/DoT/DoQ adapter 都应实现这个接口。
pub trait DnsTransport: Send + Sync {
    fn exchange(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>>;
}

/// 已验证的 DNS 名称。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(value: impl Into<String>) -> Result<Self, DnsError> {
        let value = normalize_dns_name(value.into())?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsQuery {
    pub name: DnsName,
    pub record_type: DnsRecordType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponse {
    pub answers: Vec<DnsAnswer>,
}

impl DnsResponse {
    pub fn empty() -> Self {
        Self {
            answers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    pub host: Host,
    pub ttl_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsError {
    pub message: String,
}

impl DnsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub servers: Vec<DnsServerConfig>,
    pub rules: Vec<DnsRuleConfig>,
    pub final_server: Option<String>,
    pub cache: DnsCacheConfig,
    pub fake_ip: Option<FakeIpConfig>,
    pub hijack: Vec<DnsHijackTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServerConfig {
    pub id: String,
    pub protocol: DnsServerProtocol,
    pub endpoint: Endpoint,
    pub outbound: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsServerProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuleConfig {
    pub matcher: DnsRuleMatcher,
    pub action: DnsRuleAction,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsRuleMatcher {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub record_types: Vec<DnsRecordType>,
    pub invert: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRuleAction {
    Server(String),
    FakeIp,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub min_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1024,
            min_ttl_seconds: 0,
            max_ttl_seconds: 3600,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub ipv4_pool: IpCidr,
    pub ttl_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHijackTarget {
    pub network: Option<Network>,
    pub endpoint: Endpoint,
}

pub struct RuleBasedResolver {
    transports: HashMap<String, Arc<dyn DnsTransport>>,
    rules: Vec<DnsRuleConfig>,
    final_server: String,
    fake_ip: Option<Arc<FakeIpAllocator>>,
}

impl RuleBasedResolver {
    pub fn new(
        transports: HashMap<String, Arc<dyn DnsTransport>>,
        rules: Vec<DnsRuleConfig>,
        final_server: impl Into<String>,
        fake_ip: Option<Arc<FakeIpAllocator>>,
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
    fn resolve(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>> {
        Box::pin(async move {
            let action = self
                .rules
                .iter()
                .find(|rule| rule.matcher.matches(&query))
                .map(|rule| rule.action.clone())
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
        })
    }
}

pub struct CachingResolver {
    upstream: Arc<dyn Resolver>,
    clock: Arc<dyn Clock>,
    enabled: bool,
    max_entries: usize,
    min_ttl_seconds: u32,
    max_ttl_seconds: u32,
    entries: Mutex<HashMap<DnsQuery, CachedResponse>>,
}

impl CachingResolver {
    pub fn new(upstream: Arc<dyn Resolver>, clock: Arc<dyn Clock>, config: DnsCacheConfig) -> Self {
        Self {
            upstream,
            clock,
            enabled: config.enabled,
            max_entries: config.max_entries,
            min_ttl_seconds: config.min_ttl_seconds,
            max_ttl_seconds: config.max_ttl_seconds,
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Resolver for CachingResolver {
    fn resolve(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>> {
        Box::pin(async move {
            if !self.enabled {
                return self.upstream.resolve(query).await;
            }

            let now = self.clock.now().as_millis();
            if let Some(response) = self.entries.lock().expect("cache lock").get(&query)
                && response.expires_at_millis > now
            {
                return Ok(response.response.clone());
            }

            let response = self.upstream.resolve(query.clone()).await?;
            let ttl = response
                .answers
                .iter()
                .map(|answer| answer.ttl_seconds)
                .min()
                .unwrap_or(0)
                .clamp(self.min_ttl_seconds, self.max_ttl_seconds);

            if ttl > 0 && self.max_entries > 0 {
                let mut entries = self.entries.lock().expect("cache lock");
                if entries.len() >= self.max_entries
                    && let Some(key) = entries.keys().next().cloned()
                {
                    entries.remove(&key);
                }
                entries.insert(
                    query,
                    CachedResponse {
                        response: response.clone(),
                        expires_at_millis: now.saturating_add(u64::from(ttl) * 1000),
                    },
                );
            }
            Ok(response)
        })
    }
}

#[derive(Clone, Debug)]
struct CachedResponse {
    response: DnsResponse,
    expires_at_millis: u64,
}

#[derive(Debug)]
pub struct FakeIpAllocator {
    pool: Ipv4Pool,
    ttl_seconds: u32,
    state: Mutex<FakeIpState>,
}

impl FakeIpAllocator {
    pub fn new(config: FakeIpConfig) -> Result<Self, DnsError> {
        Ok(Self {
            pool: Ipv4Pool::new(config.ipv4_pool)?,
            ttl_seconds: config.ttl_seconds,
            state: Mutex::new(FakeIpState::default()),
        })
    }

    pub fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        if query.record_type != DnsRecordType::A {
            return Ok(DnsResponse::empty());
        }
        let mut state = self.state.lock().expect("fake-ip lock");
        if let Some(address) = state.by_name.get(&query.name).copied() {
            return Ok(fake_ip_response(address, self.ttl_seconds));
        }

        let address = self.pool.address_at(state.next_offset)?;
        state.next_offset = self.pool.next_offset(state.next_offset);
        let name = query.name.as_str().to_string();
        state.by_name.insert(query.name, address);
        state.by_ip.insert(address, name);
        Ok(fake_ip_response(address, self.ttl_seconds))
    }

    pub fn lookup(&self, address: IpAddress) -> Option<String> {
        self.state
            .lock()
            .expect("fake-ip lock")
            .by_ip
            .get(&address)
            .cloned()
    }
}

#[derive(Default, Debug)]
struct FakeIpState {
    by_name: HashMap<DnsName, IpAddress>,
    by_ip: HashMap<IpAddress, String>,
    next_offset: u32,
}

#[derive(Clone, Copy, Debug)]
struct Ipv4Pool {
    base: u32,
    usable: u32,
}

impl Ipv4Pool {
    fn new(cidr: IpCidr) -> Result<Self, DnsError> {
        let IpAddress::V4(octets) = cidr.address else {
            return Err(DnsError::new("fake-ip currently supports only IPv4 pools"));
        };
        if cidr.prefix_len > 30 {
            return Err(DnsError::new(
                "fake-ip IPv4 pool must contain at least two usable addresses",
            ));
        }
        let address = u32::from_be_bytes(octets);
        let mask = u32::MAX << (32 - cidr.prefix_len);
        let network = address & mask;
        let total = 1u32 << (32 - cidr.prefix_len);
        Ok(Self {
            base: network.saturating_add(1),
            usable: total.saturating_sub(2),
        })
    }

    fn address_at(self, offset: u32) -> Result<IpAddress, DnsError> {
        if self.usable == 0 {
            return Err(DnsError::new("fake-ip pool is empty"));
        }
        Ok(IpAddress::V4(
            self.base.saturating_add(offset % self.usable).to_be_bytes(),
        ))
    }

    fn next_offset(self, offset: u32) -> u32 {
        (offset + 1) % self.usable
    }
}

impl DnsRuleMatcher {
    pub fn matches(&self, query: &DnsQuery) -> bool {
        let matched = self.matches_without_invert(query);
        if self.invert { !matched } else { matched }
    }

    fn matches_without_invert(&self, query: &DnsQuery) -> bool {
        if !self.record_types.is_empty() && !self.record_types.contains(&query.record_type) {
            return false;
        }
        if self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.domain_keywords.is_empty()
        {
            return true;
        }
        let name = query.name.as_str();
        self.domains.iter().any(|domain| domain == name)
            || self.domain_suffixes.iter().any(|suffix| {
                name == suffix
                    || name
                        .strip_suffix(suffix)
                        .is_some_and(|rest| rest.ends_with('.'))
            })
            || self
                .domain_keywords
                .iter()
                .any(|keyword| name.contains(keyword))
    }
}

/// 测试和默认场景使用的静态解析器。
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
    fn resolve(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>> {
        Box::pin(async move {
            let answers = self
                .records
                .get(&query.name)
                .cloned()
                .unwrap_or_else(Vec::new)
                .into_iter()
                .filter(|answer| match (&answer.host, query.record_type) {
                    (Host::Ip(IpAddress::V4(_)), DnsRecordType::A) => true,
                    (Host::Ip(IpAddress::V6(_)), DnsRecordType::Aaaa) => true,
                    (Host::Ip(_), _) => false,
                    (Host::Domain(_), _) => false,
                })
                .collect();
            Ok(DnsResponse { answers })
        })
    }
}

impl<T> DnsTransport for T
where
    T: Resolver,
{
    fn exchange(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>> {
        self.resolve(query)
    }
}

fn normalize_dns_name(value: String) -> Result<String, DnsError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return Err(DnsError::new("DNS name must not be empty"));
    }
    if value.len() > 253 {
        return Err(DnsError::new("DNS name is too long"));
    }
    if value
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(DnsError::new("DNS name contains an invalid label"));
    }
    Ok(value)
}

fn fake_ip_response(address: IpAddress, ttl_seconds: u32) -> DnsResponse {
    DnsResponse {
        answers: vec![DnsAnswer {
            host: Host::Ip(address),
            ttl_seconds,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_kernel::HostInstant;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[test]
    fn normalizes_dns_names() {
        let name = DnsName::new("Example.TEST.").expect("name");

        assert_eq!(name.as_str(), "example.test");
    }

    #[test]
    fn fake_ip_allocates_stable_answers_and_reverse_mapping() {
        let allocator = FakeIpAllocator::new(FakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddress::V4([198, 18, 0, 0]), 30).expect("cidr"),
            ttl_seconds: 60,
        })
        .expect("allocator");
        let query = DnsQuery {
            name: DnsName::new("example.test").expect("name"),
            record_type: DnsRecordType::A,
        };

        let first = allocator.resolve(query.clone()).expect("first");
        let second = allocator.resolve(query).expect("second");

        assert_eq!(first, second);
        let Host::Ip(address) = first.answers[0].host else {
            panic!("fake ip answer");
        };
        assert_eq!(allocator.lookup(address), Some("example.test".to_string()));
    }

    #[test]
    fn dns_rule_matches_suffix_and_record_type() {
        let matcher = DnsRuleMatcher {
            domain_suffixes: vec!["example.test".to_string()],
            record_types: vec![DnsRecordType::A],
            ..DnsRuleMatcher::default()
        };

        assert!(matcher.matches(&DnsQuery {
            name: DnsName::new("www.example.test").expect("name"),
            record_type: DnsRecordType::A,
        }));
        assert!(!matcher.matches(&DnsQuery {
            name: DnsName::new("www.example.test").expect("name"),
            record_type: DnsRecordType::Aaaa,
        }));
    }

    #[test]
    fn cache_resolver_reuses_positive_response() {
        let clock = Arc::new(TestClock::new());
        let upstream = Arc::new(CountingResolver::new());
        let cache = CachingResolver::new(
            upstream.clone(),
            clock,
            DnsCacheConfig {
                enabled: true,
                max_entries: 8,
                min_ttl_seconds: 0,
                max_ttl_seconds: 60,
            },
        );
        let query = DnsQuery {
            name: DnsName::new("cache.example").expect("name"),
            record_type: DnsRecordType::A,
        };

        futures::executor::block_on(cache.resolve(query.clone())).expect("first");
        futures::executor::block_on(cache.resolve(query)).expect("second");

        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    }

    struct TestClock {
        now: AtomicU64,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now: AtomicU64::new(1000),
            }
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> HostInstant {
            HostInstant::from_millis(self.now.load(Ordering::SeqCst))
        }

        fn sleep_until(&self, _deadline: HostInstant) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    struct CountingResolver {
        calls: AtomicUsize,
    }

    impl CountingResolver {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Resolver for CountingResolver {
        fn resolve(&self, _query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(DnsResponse {
                    answers: vec![DnsAnswer {
                        host: Host::Ip(IpAddress::V4([203, 0, 113, 1])),
                        ttl_seconds: 30,
                    }],
                })
            })
        }
    }
}
