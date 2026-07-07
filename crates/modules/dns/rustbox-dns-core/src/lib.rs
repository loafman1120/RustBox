//! 可移植 DNS 核心契约。
//!
//! DNS 是独立子系统，不隐藏在路由器内部；解析器通过能力或未来 DNS transport 获取效果。

use rustbox_host_api::BoxFuture;
use rustbox_types::{Host, IpAddress};
use std::collections::HashMap;

/// DNS 解析接口，输入查询，输出响应，不直接决定代理路由。
pub trait Resolver: Send + Sync {
    fn resolve(&self, query: DnsQuery) -> BoxFuture<'_, Result<DnsResponse, DnsError>>;
}

/// 已验证的 DNS 名称。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(value: impl Into<String>) -> Result<Self, DnsError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DnsError::new("DNS name must not be empty"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    pub name: DnsName,
    pub record_type: DnsRecordType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
                    (Host::Domain(_), _) => false,
                    _ => false,
                })
                .collect();
            Ok(DnsResponse { answers })
        })
    }
}
