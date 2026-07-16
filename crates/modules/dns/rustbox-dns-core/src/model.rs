use garde::Validate;
use rustbox_types::{Endpoint, Host, IpCidr, Network};
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};

pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        query: DnsQuery,
    ) -> impl Future<Output = Result<DnsResponse, DnsError>> + Send;
}

pub trait DnsTransport: Send + Sync {
    fn exchange(
        &self,
        query: DnsQuery,
    ) -> impl Future<Output = Result<DnsResponse, DnsError>> + Send;
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(value: impl Into<String>) -> Result<Self, DnsError> {
        let value = value.into();
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if value.is_empty() || value.len() > 253 {
            return Err(DnsError::new("DNS name is empty or too long"));
        }
        if value
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(DnsError::new("DNS name contains an invalid label"));
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
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

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DnsError {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,
    pub final_server: Option<String>,
    #[serde(default)]
    #[garde(dive)]
    pub cache: DnsCacheConfig,
    #[garde(dive)]
    pub fake_ip: Option<FakeIpConfig>,
    #[serde(default)]
    pub hijack: Vec<DnsHijackTarget>,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    pub id: String,
    pub protocol: DnsServerProtocol,
    #[serde_as(as = "DisplayFromStr")]
    pub endpoint: Endpoint,
    pub outbound: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsServerProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DnsRuleConfig {
    Server {
        server: String,
        #[serde(flatten)]
        matcher: DnsRuleMatcher,
    },
    FakeIp {
        #[serde(flatten)]
        matcher: DnsRuleMatcher,
    },
    Reject {
        #[serde(flatten)]
        matcher: DnsRuleMatcher,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRuleMatcher {
    #[serde(rename = "domain")]
    pub domains: Vec<String>,
    #[serde(rename = "domain_suffix")]
    pub domain_suffixes: Vec<String>,
    #[serde(rename = "domain_keyword")]
    pub domain_keywords: Vec<String>,
    #[serde(rename = "record_type")]
    pub record_types: Vec<DnsRecordType>,
    pub invert: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRuleAction {
    Server(String),
    FakeIp,
    Reject,
}

impl DnsRuleConfig {
    pub fn matcher(&self) -> &DnsRuleMatcher {
        match self {
            Self::Server { matcher, .. } | Self::FakeIp { matcher } | Self::Reject { matcher } => {
                matcher
            }
        }
    }
    pub fn action(&self) -> DnsRuleAction {
        match self {
            Self::Server { server, .. } => DnsRuleAction::Server(server.clone()),
            Self::FakeIp { .. } => DnsRuleAction::FakeIp,
            Self::Reject { .. } => DnsRuleAction::Reject,
        }
    }
}

impl DnsRuleMatcher {
    pub fn matches(&self, query: &DnsQuery) -> bool {
        let matched = self.matches_inner(query);
        if self.invert { !matched } else { matched }
    }
    fn matches_inner(&self, query: &DnsQuery) -> bool {
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    #[garde(range(min = 1))]
    pub max_entries: usize,
    pub min_ttl_seconds: u32,
    #[garde(range(min = 1))]
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

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct FakeIpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde_as(as = "DisplayFromStr")]
    pub ipv4_pool: IpCidr,
    #[serde(default = "default_fake_ip_ttl_seconds")]
    #[garde(range(min = 1))]
    pub ttl_seconds: u32,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsHijackTarget {
    pub network: Option<Network>,
    #[serde_as(as = "DisplayFromStr")]
    pub endpoint: Endpoint,
}

fn default_true() -> bool {
    true
}
fn default_fake_ip_ttl_seconds() -> u32 {
    60
}
