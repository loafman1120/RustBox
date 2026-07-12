//! RustBox 配置文件格式适配器。
//!
//! 本 crate 负责把用户编写的 TOML 等文件形态转换为格式无关的
//! `rustbox-config` 模型。运行时模块和内核不依赖文件解析。

mod observability;

use garde::Validate;
use rustbox_config::{
    AnyTlsInboundTlsConfig, DnsCacheConfig, DnsConfig, DnsHijackTarget, DnsRecordType,
    DnsRuleAction, DnsRuleConfig, DnsRuleMatcher, DnsServerConfig, DnsServerProtocol, FakeIpConfig,
    InboundConfig, InboundConfigKind, LogicalModeConfig, OutboundConfig, OutboundConfigKind,
    OutboundTlsConfig, RouteActionConfig, RouteMatchConfig, RouteMatcherConfig, RouteMode,
    RouteRuleConfig, RouteRuleSetConfig, SourceConfig, TransparentInboundConfig,
    TransparentNetwork, TransparentRedirectMode, TunDnsMode, TunInboundConfig,
};
use rustbox_types::{Endpoint, IpCidr, Network, PortRange, RejectReason};
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{ConfigFileError, loader, migration};
pub use observability::FileObservabilityConfig;
use observability::TomlObservabilityConfig;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// 文件解析结果：核心 SourceConfig 加上文件侧可选的应用级配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConfig {
    pub source: SourceConfig,
    pub observability: Option<FileObservabilityConfig>,
}

/// Typed configuration loader with optional environment overrides.
///
/// Environment loading is opt-in so existing file-only callers remain fully
/// deterministic. Nested keys use `__`, for example
/// `RUSTBOX_OBSERVABILITY__LEVEL=debug` with the `RUSTBOX_` prefix.
#[derive(Clone, Debug, Default)]
pub struct ConfigLoader {
    env_prefix: Option<String>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = Some(prefix.into());
        self
    }

    pub fn load(&self, path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
        let path = path.as_ref();
        let document = match self.env_prefix.as_deref() {
            Some(prefix) => loader::load_toml_with_env::<TomlConfigDocument>(path, prefix)?,
            None => loader::load_toml::<TomlConfigDocument>(path)?,
        };
        document.into_file_config(path.parent())
    }

    pub fn parse(&self, input: &str) -> Result<FileConfig, ConfigFileError> {
        let document = match self.env_prefix.as_deref() {
            Some(prefix) => loader::parse_toml_with_env::<TomlConfigDocument>(input, prefix)?,
            None => loader::parse_toml::<TomlConfigDocument>(input)?,
        };
        document.into_file_config(None)
    }
}

/// 从磁盘读取 TOML 文件并解析为统一配置模型。
pub fn load_toml_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    ConfigLoader::new().load(path)
}

/// 从 TOML 文本解析配置，供 CLI、测试和 FFI 文本入口复用。
pub fn parse_toml_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    ConfigLoader::new().parse(input)
}

#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
struct TomlConfigDocument {
    schema_version: u32,
    #[garde(dive)]
    observability: Option<TomlObservabilityConfig>,
    #[serde(default)]
    inbounds: Vec<TomlInboundConfig>,
    #[serde(default)]
    #[garde(dive)]
    outbounds: Vec<TomlOutboundConfig>,
    #[garde(dive)]
    dns: Option<TomlDnsConfig>,
    #[serde(default)]
    rule_sets: Vec<TomlRouteRuleSetConfig>,
    #[serde(default)]
    routes: Vec<TomlRouteRuleConfig>,
}

impl TomlConfigDocument {
    fn into_file_config(self, base_dir: Option<&Path>) -> Result<FileConfig, ConfigFileError> {
        // Reject unknown document shapes before applying current-schema rules.
        migration::accept_schema_version(self.schema_version)?;
        self.validate().map_err(|error| {
            ConfigFileError::new(format!("configuration validation failed: {error}"))
        })?;

        let inbounds = self
            .inbounds
            .into_iter()
            .map(TomlInboundConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let outbounds = self
            .outbounds
            .into_iter()
            .map(TomlOutboundConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let routes = self
            .routes
            .into_iter()
            .map(TomlRouteRuleConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let route_rule_sets = self
            .rule_sets
            .into_iter()
            .map(|rule_set| rule_set.into_source(base_dir))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FileConfig {
            source: SourceConfig {
                inbounds,
                outbounds,
                dns: self.dns.map(TomlDnsConfig::into_source).transpose()?,
                route_rule_sets,
                routes,
            },
            observability: self
                .observability
                .map(TomlObservabilityConfig::into_file)
                .transpose()?,
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlInboundConfig {
    Mixed {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    HttpConnect {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    AnyTls {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        password: String,
        tls: TomlAnyTlsInboundTlsConfig,
    },
    Tun {
        id: String,
        interface_name: Option<String>,
        #[serde(default)]
        #[serde_as(as = "Vec<DisplayFromStr>")]
        addresses: Vec<IpCidr>,
        mtu: Option<u16>,
        #[serde(default)]
        auto_route: bool,
        #[serde(default)]
        strict_route: bool,
        #[serde(default)]
        #[serde_as(as = "Vec<DisplayFromStr>")]
        route_includes: Vec<IpCidr>,
        #[serde(default)]
        #[serde_as(as = "Vec<DisplayFromStr>")]
        route_excludes: Vec<IpCidr>,
        #[serde(default)]
        dns_hijack: Vec<TomlDnsHijackConfig>,
        #[serde(default)]
        platform_http_proxy: bool,
        #[serde(default)]
        auto_redirect: bool,
    },
    Transparent {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        #[serde(default = "default_transparent_network")]
        network: TomlTransparentNetwork,
        #[serde(default = "default_transparent_mode")]
        mode: TomlTransparentMode,
        #[serde(default)]
        auto_rules: bool,
        mark: Option<u32>,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlAnyTlsInboundTlsConfig {
    certificate_path: String,
    private_key_path: String,
    #[serde(default)]
    alpn: Vec<String>,
}

impl TomlInboundConfig {
    fn into_source(self) -> Result<InboundConfig, ConfigFileError> {
        match self {
            Self::Mixed {
                id,
                listen,
                username,
                password,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::Mixed {
                    listen,
                    username,
                    password,
                },
            }),
            Self::HttpConnect {
                id,
                listen,
                username,
                password,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::HttpConnect {
                    listen,
                    username,
                    password,
                },
            }),
            Self::Socks5 {
                id,
                listen,
                username,
                password,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::Socks5 {
                    listen,
                    username,
                    password,
                },
            }),
            Self::AnyTls {
                id,
                listen,
                password,
                tls,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::AnyTls {
                    listen,
                    password,
                    tls: AnyTlsInboundTlsConfig {
                        certificate_path: tls.certificate_path,
                        private_key_path: tls.private_key_path,
                        alpn: tls.alpn,
                    },
                },
            }),
            Self::Tun {
                id,
                interface_name,
                addresses,
                mtu,
                auto_route,
                strict_route,
                route_includes,
                route_excludes,
                dns_hijack,
                platform_http_proxy,
                auto_redirect,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::Tun(TunInboundConfig {
                    interface_name,
                    addresses,
                    mtu,
                    route_mode: route_mode(auto_route, strict_route),
                    dns_mode: if dns_hijack.is_empty() {
                        TunDnsMode::None
                    } else {
                        TunDnsMode::Hijack
                    },
                    auto_route,
                    strict_route,
                    route_includes,
                    route_excludes,
                    dns_hijack: dns_hijack
                        .into_iter()
                        .map(TomlDnsHijackConfig::into_source)
                        .collect::<Result<Vec<_>, _>>()?,
                    platform_http_proxy,
                    auto_redirect,
                }),
            }),
            Self::Transparent {
                id,
                listen,
                network,
                mode,
                auto_rules,
                mark,
            } => Ok(InboundConfig {
                id,
                kind: InboundConfigKind::Transparent(TransparentInboundConfig {
                    listen,
                    network: network.into(),
                    mode: mode.into(),
                    auto_rules,
                    mark,
                }),
            }),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlOutboundConfig {
    Direct {
        id: String,
    },
    Block {
        id: String,
    },
    Socks5 {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Shadowsocks {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        method: String,
        password: String,
    },
    Selector {
        id: String,
        outbounds: Vec<String>,
        default: Option<String>,
    },
    Urltest {
        id: String,
        #[garde(length(min = 1))]
        outbounds: Vec<String>,
        #[serde(default = "default_urltest_url")]
        url: String,
        #[serde(default = "default_urltest_interval_seconds")]
        #[garde(range(min = 1))]
        interval_seconds: u64,
        #[serde(default)]
        tolerance_ms: u16,
    },
    Vmess {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<TomlOutboundTlsConfig>,
        transport: Option<String>,
    },
    Vless {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<TomlOutboundTlsConfig>,
        transport: Option<String>,
    },
    Trojan {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        tls: Option<TomlOutboundTlsConfig>,
        transport: Option<String>,
    },
    Anytls {
        id: String,
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        tls: Option<TomlOutboundTlsConfig>,
    },
}

impl TomlOutboundConfig {
    fn into_source(self) -> Result<OutboundConfig, ConfigFileError> {
        match self {
            Self::Direct { id } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Direct,
            }),
            Self::Block { id } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Block,
            }),
            Self::Socks5 {
                id,
                server,
                username,
                password,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Socks5 {
                    server,
                    username,
                    password,
                },
            }),
            Self::Http {
                id,
                server,
                username,
                password,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Http {
                    server,
                    username,
                    password,
                },
            }),
            Self::Shadowsocks {
                id,
                server,
                method,
                password,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Shadowsocks {
                    server,
                    method,
                    password,
                },
            }),
            Self::Selector {
                id,
                outbounds,
                default,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Selector { outbounds, default },
            }),
            Self::Urltest {
                id,
                outbounds,
                url,
                interval_seconds,
                tolerance_ms,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::UrlTest {
                    outbounds,
                    url,
                    interval_seconds,
                    tolerance_ms,
                },
            }),
            Self::Vmess {
                id,
                server,
                uuid,
                security,
                alter_id,
                tls,
                transport,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Vmess {
                    server,
                    uuid,
                    security,
                    alter_id,
                    tls: tls.map(Into::into),
                    transport,
                },
            }),
            Self::Vless {
                id,
                server,
                uuid,
                flow,
                tls,
                transport,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Vless {
                    server,
                    uuid,
                    flow,
                    tls: tls.map(Into::into),
                    transport,
                },
            }),
            Self::Trojan {
                id,
                server,
                password,
                tls,
                transport,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::Trojan {
                    server,
                    password,
                    tls: tls.map(Into::into),
                    transport,
                },
            }),
            Self::Anytls {
                id,
                server,
                password,
                tls,
            } => Ok(OutboundConfig {
                id,
                kind: OutboundConfigKind::AnyTls {
                    server,
                    password,
                    tls: tls.map(Into::into),
                },
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlOutboundTlsConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    server_name: Option<String>,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    alpn: Vec<String>,
}

impl From<TomlOutboundTlsConfig> for OutboundTlsConfig {
    fn from(value: TomlOutboundTlsConfig) -> Self {
        Self {
            enabled: value.enabled,
            server_name: value.server_name,
            insecure: value.insecure,
            alpn: value.alpn,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
struct TomlDnsConfig {
    #[serde(default)]
    servers: Vec<TomlDnsServerConfig>,
    #[serde(default)]
    rules: Vec<TomlDnsRuleConfig>,
    final_server: Option<String>,
    #[garde(dive)]
    cache: Option<TomlDnsCacheConfig>,
    #[garde(dive)]
    fake_ip: Option<TomlFakeIpConfig>,
    #[serde(default)]
    hijack: Vec<TomlDnsHijackConfig>,
}

impl TomlDnsConfig {
    fn into_source(self) -> Result<DnsConfig, ConfigFileError> {
        Ok(DnsConfig {
            servers: self
                .servers
                .into_iter()
                .map(TomlDnsServerConfig::into_source)
                .collect::<Result<Vec<_>, _>>()?,
            rules: self
                .rules
                .into_iter()
                .map(TomlDnsRuleConfig::into_source)
                .collect::<Result<Vec<_>, _>>()?,
            final_server: self.final_server,
            cache: self.cache.map(Into::into).unwrap_or_default(),
            fake_ip: self
                .fake_ip
                .map(TomlFakeIpConfig::into_source)
                .transpose()?,
            hijack: self
                .hijack
                .into_iter()
                .map(TomlDnsHijackConfig::into_source)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsServerConfig {
    id: String,
    protocol: TomlDnsServerProtocol,
    #[serde_as(as = "DisplayFromStr")]
    endpoint: Endpoint,
    outbound: Option<String>,
}

impl TomlDnsServerConfig {
    fn into_source(self) -> Result<DnsServerConfig, ConfigFileError> {
        Ok(DnsServerConfig {
            id: self.id,
            protocol: self.protocol.into(),
            endpoint: self.endpoint,
            outbound: self.outbound,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlDnsServerProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

impl From<TomlDnsServerProtocol> for DnsServerProtocol {
    fn from(value: TomlDnsServerProtocol) -> Self {
        match value {
            TomlDnsServerProtocol::Udp => Self::Udp,
            TomlDnsServerProtocol::Tcp => Self::Tcp,
            TomlDnsServerProtocol::Tls => Self::Tls,
            TomlDnsServerProtocol::Https => Self::Https,
            TomlDnsServerProtocol::Quic => Self::Quic,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsRuleConfig {
    action: TomlDnsRuleAction,
    server: Option<String>,
    #[serde(flatten)]
    matcher: TomlDnsRuleMatcher,
}

impl TomlDnsRuleConfig {
    fn into_source(self) -> Result<DnsRuleConfig, ConfigFileError> {
        let action = match self.action {
            TomlDnsRuleAction::Server => DnsRuleAction::Server(self.server.ok_or_else(|| {
                ConfigFileError::new("dns rule with action = \"server\" must set server")
            })?),
            TomlDnsRuleAction::FakeIp => {
                if self.server.is_some() {
                    return Err(ConfigFileError::new("dns fake-ip rule must not set server"));
                }
                DnsRuleAction::FakeIp
            }
            TomlDnsRuleAction::Reject => {
                if self.server.is_some() {
                    return Err(ConfigFileError::new("dns reject rule must not set server"));
                }
                DnsRuleAction::Reject
            }
        };
        Ok(DnsRuleConfig {
            matcher: self.matcher.into_source(),
            action,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlDnsRuleAction {
    Server,
    FakeIp,
    Reject,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsRuleMatcher {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(default)]
    record_type: Vec<TomlDnsRecordType>,
    #[serde(default)]
    invert: bool,
}

impl TomlDnsRuleMatcher {
    fn into_source(self) -> DnsRuleMatcher {
        DnsRuleMatcher {
            domains: self.domain,
            domain_suffixes: self.domain_suffix,
            domain_keywords: self.domain_keyword,
            record_types: self.record_type.into_iter().map(Into::into).collect(),
            invert: self.invert,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlDnsRecordType {
    A,
    Aaaa,
}

impl From<TomlDnsRecordType> for DnsRecordType {
    fn from(value: TomlDnsRecordType) -> Self {
        match value {
            TomlDnsRecordType::A => Self::A,
            TomlDnsRecordType::Aaaa => Self::Aaaa,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
struct TomlDnsCacheConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_dns_cache_max_entries")]
    #[garde(range(min = 1))]
    max_entries: usize,
    #[serde(default)]
    min_ttl_seconds: u32,
    #[serde(default = "default_dns_cache_max_ttl_seconds")]
    #[garde(range(min = 1))]
    max_ttl_seconds: u32,
}

impl From<TomlDnsCacheConfig> for DnsCacheConfig {
    fn from(value: TomlDnsCacheConfig) -> Self {
        Self {
            enabled: value.enabled,
            max_entries: value.max_entries,
            min_ttl_seconds: value.min_ttl_seconds,
            max_ttl_seconds: value.max_ttl_seconds,
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
struct TomlFakeIpConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde_as(as = "DisplayFromStr")]
    ipv4_pool: IpCidr,
    #[serde(default = "default_fake_ip_ttl_seconds")]
    #[garde(range(min = 1))]
    ttl_seconds: u32,
}

impl TomlFakeIpConfig {
    fn into_source(self) -> Result<FakeIpConfig, ConfigFileError> {
        Ok(FakeIpConfig {
            enabled: self.enabled,
            ipv4_pool: self.ipv4_pool,
            ttl_seconds: self.ttl_seconds,
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsHijackConfig {
    #[serde_as(as = "DisplayFromStr")]
    endpoint: Endpoint,
    network: Option<TomlNetwork>,
}

impl TomlDnsHijackConfig {
    fn into_source(self) -> Result<DnsHijackTarget, ConfigFileError> {
        Ok(DnsHijackTarget {
            network: self.network.map(Into::into),
            endpoint: self.endpoint,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteRuleConfig {
    Default {
        outbound: String,
    },
    RejectDefault {
        reason: TomlRejectReason,
    },
    Rule {
        outbound: Option<String>,
        reject: Option<TomlRejectReason>,
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    Logical {
        mode: TomlLogicalMode,
        rules: Vec<TomlRouteMatcherConfig>,
        outbound: Option<String>,
        reject: Option<TomlRejectReason>,
        #[serde(default)]
        invert: bool,
    },
}

impl TomlRouteRuleConfig {
    fn into_source(self) -> Result<RouteRuleConfig, ConfigFileError> {
        match self {
            Self::Default { outbound } => Ok(RouteRuleConfig::Default { outbound }),
            Self::RejectDefault { reason } => Ok(RouteRuleConfig::RejectDefault {
                reason: reason.into(),
            }),
            Self::Rule {
                outbound,
                reject,
                matcher,
            } => Ok(RouteRuleConfig::Rule {
                matcher: RouteMatcherConfig::Conditions(Box::new((*matcher).into_source()?)),
                action: route_action(outbound, reject)?,
            }),
            Self::Logical {
                mode,
                rules,
                outbound,
                reject,
                invert,
            } => Ok(RouteRuleConfig::Logical {
                mode: mode.into(),
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
                invert,
                action: route_action(outbound, reject)?,
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteMatcherConfig {
    Rule {
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    Logical {
        mode: TomlLogicalMode,
        rules: Vec<TomlRouteMatcherConfig>,
        #[serde(default)]
        invert: bool,
    },
}

impl TomlRouteMatcherConfig {
    fn into_source(self) -> Result<RouteMatcherConfig, ConfigFileError> {
        match self {
            Self::Rule { matcher } => Ok(RouteMatcherConfig::Conditions(Box::new(
                (*matcher).into_source()?,
            ))),
            Self::Logical {
                mode,
                rules,
                invert,
            } => Ok(RouteMatcherConfig::Logical {
                mode: mode.into(),
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
                invert,
            }),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRouteMatchFields {
    #[serde(default)]
    inbound: Vec<String>,
    #[serde(default)]
    network: Vec<TomlNetwork>,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(default)]
    domain_regex: Vec<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    ip_cidr: Vec<IpCidr>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    source_ip_cidr: Vec<IpCidr>,
    #[serde(default)]
    port: Vec<u16>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    port_range: Vec<PortRange>,
    #[serde(default)]
    source_port: Vec<u16>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    source_port_range: Vec<PortRange>,
    #[serde(default)]
    rule_set: Vec<String>,
    #[serde(default)]
    invert: bool,
}

impl TomlRouteMatchFields {
    fn into_source(self) -> Result<RouteMatchConfig, ConfigFileError> {
        Ok(RouteMatchConfig {
            inbound: self.inbound,
            network: self.network.into_iter().map(Into::into).collect(),
            domain: self.domain,
            domain_suffix: self.domain_suffix,
            domain_keyword: self.domain_keyword,
            domain_regex: self.domain_regex,
            ip_cidr: self.ip_cidr,
            source_ip_cidr: self.source_ip_cidr,
            port: parse_port_ranges(self.port, self.port_range)?,
            source_port: parse_port_ranges(self.source_port, self.source_port_range)?,
            rule_set: self.rule_set,
            invert: self.invert,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlNetwork {
    Tcp,
    Udp,
}

impl From<TomlNetwork> for Network {
    fn from(value: TomlNetwork) -> Self {
        match value {
            TomlNetwork::Tcp => Self::Tcp,
            TomlNetwork::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlTransparentNetwork {
    Tcp,
    Udp,
    TcpUdp,
}

impl From<TomlTransparentNetwork> for TransparentNetwork {
    fn from(value: TomlTransparentNetwork) -> Self {
        match value {
            TomlTransparentNetwork::Tcp => Self::Tcp,
            TomlTransparentNetwork::Udp => Self::Udp,
            TomlTransparentNetwork::TcpUdp => Self::TcpUdp,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlTransparentMode {
    Redirect,
    Tproxy,
    WfpRedirect,
}

impl From<TomlTransparentMode> for TransparentRedirectMode {
    fn from(value: TomlTransparentMode) -> Self {
        match value {
            TomlTransparentMode::Redirect => Self::Redirect,
            TomlTransparentMode::Tproxy => Self::Tproxy,
            TomlTransparentMode::WfpRedirect => Self::WfpRedirect,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlLogicalMode {
    And,
    Or,
}

impl From<TomlLogicalMode> for LogicalModeConfig {
    fn from(value: TomlLogicalMode) -> Self {
        match value {
            TomlLogicalMode::And => Self::And,
            TomlLogicalMode::Or => Self::Or,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteRuleSetConfig {
    Local {
        id: String,
        path: String,
    },
    Inline {
        id: String,
        rules: Vec<TomlRouteMatcherConfig>,
    },
}

impl TomlRouteRuleSetConfig {
    fn into_source(self, base_dir: Option<&Path>) -> Result<RouteRuleSetConfig, ConfigFileError> {
        match self {
            Self::Local { id, path } => {
                let path = resolve_config_path(base_dir, &path);
                let text = fs::read_to_string(&path).map_err(|err| {
                    ConfigFileError::new(format!(
                        "failed to read route rule-set `{}`: {err}",
                        path.display()
                    ))
                })?;
                let document =
                    loader::parse_toml::<TomlRouteRuleSetDocument>(&text).map_err(|error| {
                        ConfigFileError::new(format!(
                            "failed to parse route rule-set `{}`: {error}",
                            path.display()
                        ))
                    })?;
                Ok(RouteRuleSetConfig {
                    id,
                    rules: document.into_rules()?,
                })
            }
            Self::Inline { id, rules } => Ok(RouteRuleSetConfig {
                id,
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRouteRuleSetDocument {
    rules: Vec<TomlRouteMatcherConfig>,
}

impl TomlRouteRuleSetDocument {
    fn into_rules(self) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
        self.rules
            .into_iter()
            .map(TomlRouteMatcherConfig::into_source)
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlRejectReason {
    Policy,
    NoRoute,
    UnsupportedNetwork,
}

impl From<TomlRejectReason> for RejectReason {
    fn from(value: TomlRejectReason) -> Self {
        match value {
            TomlRejectReason::Policy => Self::Policy,
            TomlRejectReason::NoRoute => Self::NoRoute,
            TomlRejectReason::UnsupportedNetwork => Self::UnsupportedNetwork,
        }
    }
}

fn route_action(
    outbound: Option<String>,
    reject: Option<TomlRejectReason>,
) -> Result<RouteActionConfig, ConfigFileError> {
    match (outbound, reject) {
        (Some(outbound), None) => Ok(RouteActionConfig::Outbound(outbound)),
        (None, Some(reason)) => Ok(RouteActionConfig::Reject(reason.into())),
        (None, None) => Err(ConfigFileError::new(
            "route rule must set either outbound or reject",
        )),
        (Some(_), Some(_)) => Err(ConfigFileError::new(
            "route rule must not set outbound and reject together",
        )),
    }
}

fn parse_port_ranges(
    ports: Vec<u16>,
    ranges: Vec<PortRange>,
) -> Result<Vec<PortRange>, ConfigFileError> {
    let mut parsed = ports.into_iter().map(PortRange::single).collect::<Vec<_>>();
    parsed.extend(ranges);
    Ok(parsed)
}

fn resolve_config_path(base_dir: Option<&Path>, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        base_dir.unwrap_or_else(|| Path::new(".")).join(path)
    }
}

fn default_true() -> bool {
    true
}

fn default_dns_cache_max_entries() -> usize {
    DnsCacheConfig::default().max_entries
}

fn default_dns_cache_max_ttl_seconds() -> u32 {
    DnsCacheConfig::default().max_ttl_seconds
}

fn default_fake_ip_ttl_seconds() -> u32 {
    60
}

fn default_urltest_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}

fn default_urltest_interval_seconds() -> u64 {
    300
}

fn default_transparent_network() -> TomlTransparentNetwork {
    TomlTransparentNetwork::Tcp
}

fn default_transparent_mode() -> TomlTransparentMode {
    TomlTransparentMode::Redirect
}

fn route_mode(auto_route: bool, strict_route: bool) -> RouteMode {
    if strict_route {
        RouteMode::Strict
    } else if auto_route {
        RouteMode::Auto
    } else {
        RouteMode::Manual
    }
}
