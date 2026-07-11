//! RustBox 配置文件格式适配器。
//!
//! 本 crate 负责把用户编写的 TOML 等文件形态转换为格式无关的
//! `rustbox-config` 模型。运行时模块和内核不依赖文件解析。

use rustbox_config::{
    AnyTlsInboundTlsConfig, DnsCacheConfig, DnsConfig, DnsHijackTarget, DnsRecordType,
    DnsRuleAction, DnsRuleConfig, DnsRuleMatcher, DnsServerConfig, DnsServerProtocol, FakeIpConfig,
    InboundConfig, InboundConfigKind, LogicalModeConfig, OutboundConfig, OutboundConfigKind,
    OutboundTlsConfig, RouteActionConfig, RouteMatchConfig, RouteMatcherConfig, RouteMode,
    RouteRuleConfig, RouteRuleSetConfig, SourceConfig, TransparentInboundConfig,
    TransparentNetwork, TransparentRedirectMode, TunDnsMode, TunInboundConfig,
};
use rustbox_observability::{LevelFilter, ObservabilityOutput};
use rustbox_types::{Endpoint, IpCidr, Network, PortRange, RejectReason};
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use std::fs;
use std::path::{Path, PathBuf};

mod error;
mod migration;

pub use error::ConfigFileError;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// 文件解析结果：核心 SourceConfig 加上文件侧可选的应用级配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConfig {
    pub source: SourceConfig,
    pub observability: Option<FileObservabilityConfig>,
}

/// 当前文件格式支持的观测配置，组合根会把它转成具体 sink。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservabilityConfig {
    pub level: Option<LevelFilter>,
    pub output: ObservabilityOutput,
    pub platform: Option<bool>,
    pub remote_endpoint: Option<String>,
}

/// 从磁盘读取 TOML 文件并解析为统一配置模型。
pub fn load_toml_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .map_err(|err| ConfigFileError::new(format!("failed to read config file: {err}")))?;
    parse_toml_str_with_base_dir(&text, path.parent())
}

/// 从 TOML 文本解析配置，供 CLI、测试和 FFI 文本入口复用。
pub fn parse_toml_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    parse_toml_str_with_base_dir(input, None)
}

fn parse_toml_str_with_base_dir(
    input: &str,
    base_dir: Option<&Path>,
) -> Result<FileConfig, ConfigFileError> {
    let document = toml::from_str::<TomlConfigDocument>(input)
        .map_err(|err| ConfigFileError::new(format!("failed to parse TOML config: {err}")))?;
    document.into_file_config(base_dir)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfigDocument {
    schema_version: u32,
    observability: Option<TomlObservabilityConfig>,
    #[serde(default)]
    inbounds: Vec<TomlInboundConfig>,
    #[serde(default)]
    outbounds: Vec<TomlOutboundConfig>,
    dns: Option<TomlDnsConfig>,
    #[serde(default)]
    rule_sets: Vec<TomlRouteRuleSetConfig>,
    #[serde(default)]
    routes: Vec<TomlRouteRuleConfig>,
}

impl TomlConfigDocument {
    fn into_file_config(self, base_dir: Option<&Path>) -> Result<FileConfig, ConfigFileError> {
        // 文件格式版本在进入 SourceConfig 前校验，避免运行时理解历史格式。
        migration::accept_schema_version(self.schema_version)?;

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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlObservabilityConfig {
    level: Option<String>,
    output: Option<TomlObservabilityOutput>,
    file: Option<String>,
    platform: Option<bool>,
    remote_endpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlObservabilityOutput {
    Console,
    File,
    ConsoleAndFile,
}

impl TomlObservabilityConfig {
    fn into_file(self) -> Result<FileObservabilityConfig, ConfigFileError> {
        let level = match self.level.as_deref() {
            Some(value) => Some(LevelFilter::parse(value).ok_or_else(|| {
                ConfigFileError::new(
                    "invalid observability level; expected trace, debug, info, warn, error, or off",
                )
            })?),
            None => None,
        };
        let output = match (
            self.output.unwrap_or(TomlObservabilityOutput::Console),
            self.file,
        ) {
            (TomlObservabilityOutput::Console, None) => ObservabilityOutput::Console,
            (TomlObservabilityOutput::Console, Some(_)) => {
                return Err(ConfigFileError::new(
                    "observability.file requires output = \"file\" or \"console-and-file\"",
                ));
            }
            (TomlObservabilityOutput::File, Some(path)) => ObservabilityOutput::File(path.into()),
            (TomlObservabilityOutput::ConsoleAndFile, Some(path)) => {
                ObservabilityOutput::ConsoleAndFile(path.into())
            }
            (TomlObservabilityOutput::File | TomlObservabilityOutput::ConsoleAndFile, None) => {
                return Err(ConfigFileError::new(
                    "observability output requires a file path",
                ));
            }
        };
        Ok(FileObservabilityConfig {
            level,
            output,
            platform: self.platform,
            remote_endpoint: self.remote_endpoint,
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
#[derive(Clone, Debug, Deserialize)]
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
        outbounds: Vec<String>,
        #[serde(default = "default_urltest_url")]
        url: String,
        #[serde(default = "default_urltest_interval_seconds")]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsConfig {
    #[serde(default)]
    servers: Vec<TomlDnsServerConfig>,
    #[serde(default)]
    rules: Vec<TomlDnsRuleConfig>,
    final_server: Option<String>,
    cache: Option<TomlDnsCacheConfig>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDnsCacheConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_dns_cache_max_entries")]
    max_entries: usize,
    #[serde(default)]
    min_ttl_seconds: u32,
    #[serde(default = "default_dns_cache_max_ttl_seconds")]
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
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlFakeIpConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde_as(as = "DisplayFromStr")]
    ipv4_pool: IpCidr,
    #[serde(default = "default_fake_ip_ttl_seconds")]
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
                    toml::from_str::<TomlRouteRuleSetDocument>(&text).map_err(|err| {
                        ConfigFileError::new(format!(
                            "failed to parse route rule-set `{}`: {err}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::{Host, IpAddress};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn parses_http_and_socks5_proxy_config() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[observability]
level = "debug"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"
username = "alice"
password = "secret"

[[outbounds]]
id = "direct"
type = "direct"

[[outbounds]]
id = "socks-out"
type = "socks5"
server = "127.0.0.1:1081"

[[outbounds]]
id = "block"
type = "block"

[[outbounds]]
id = "http-out"
type = "http"
server = "proxy.example.test:8080"
username = "alice"
password = "secret"

[[outbounds]]
id = "ss-out"
type = "shadowsocks"
server = "ss.example.test:8388"
method = "aes-128-gcm"
password = "test-password"

[[outbounds]]
id = "select"
type = "selector"
outbounds = ["direct", "block"]
default = "direct"

[[outbounds]]
id = "auto"
type = "urltest"
outbounds = ["direct", "block"]
url = "https://www.gstatic.com/generate_204"
interval_seconds = 300
tolerance_ms = 50

[[outbounds]]
id = "vmess-out"
type = "vmess"
server = "vmess.example.test:443"
uuid = "00000000-0000-0000-0000-000000000001"
security = "auto"
alter_id = 0
transport = "tcp"
tls = { enabled = true, server_name = "vmess.example.test", alpn = ["h2"] }

[[outbounds]]
id = "vless-out"
type = "vless"
server = "vless.example.test:443"
uuid = "00000000-0000-0000-0000-000000000002"
transport = "tcp"
tls = { enabled = true, server_name = "vless.example.test" }

[[outbounds]]
id = "trojan-out"
type = "trojan"
server = "trojan.example.test:443"
password = "test-password"
transport = "tcp"
tls = { enabled = true, server_name = "trojan.example.test" }

[[outbounds]]
id = "anytls-out"
type = "anytls"
server = "anytls.example.test:443"
password = "test-password"
tls = { enabled = true, server_name = "anytls.example.test" }

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse config");

        assert_eq!(config.source.inbounds.len(), 3);
        assert_eq!(config.source.outbounds.len(), 11);
        assert_eq!(config.source.routes.len(), 1);
        assert!(matches!(
            &config.source.inbounds[2].kind,
            InboundConfigKind::Mixed {
                username: Some(username),
                password: Some(password),
                ..
            } if username == "alice" && password == "secret"
        ));
        assert!(matches!(
            &config.source.outbounds[2].kind,
            OutboundConfigKind::Block
        ));
        assert!(matches!(
            &config.source.outbounds[3].kind,
            OutboundConfigKind::Http { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[4].kind,
            OutboundConfigKind::Shadowsocks { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[5].kind,
            OutboundConfigKind::Selector { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[6].kind,
            OutboundConfigKind::UrlTest { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[7].kind,
            OutboundConfigKind::Vmess { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[8].kind,
            OutboundConfigKind::Vless { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[9].kind,
            OutboundConfigKind::Trojan { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[10].kind,
            OutboundConfigKind::AnyTls { .. }
        ));
        assert_eq!(
            config.observability.map(|value| (
                value.level,
                value.output,
                value.platform,
                value.remote_endpoint
            )),
            Some((
                Some(LevelFilter::Debug),
                ObservabilityOutput::Console,
                None,
                None
            ))
        );
    }

    #[test]
    fn parses_observability_outputs() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[observability]
level = "info"
output = "console-and-file"
file = "target/rustbox.log"
platform = true
remote_endpoint = "https://telemetry.example.test/rustbox"
"#,
        )
        .expect("parse config");

        let observability = config.observability.expect("observability config");
        assert_eq!(
            observability.output,
            ObservabilityOutput::ConsoleAndFile(PathBuf::from("target/rustbox.log"))
        );
        assert_eq!(observability.platform, Some(true));
        assert_eq!(
            observability.remote_endpoint,
            Some("https://telemetry.example.test/rustbox".to_string())
        );
    }

    #[test]
    fn rejects_invalid_observability_level() {
        let error = parse_toml_str(
            r#"
schema_version = 1
[observability]
level = "loud"
"#,
        )
        .expect_err("invalid level");
        assert!(error.message.contains("invalid observability level"));
    }

    #[test]
    fn validates_observability_output_and_file_as_one_choice() {
        for input in [
            r#"schema_version = 1
[observability]
output = "file"
"#,
            r#"schema_version = 1
[observability]
output = "console"
file = "rustbox.log"
"#,
        ] {
            assert!(parse_toml_str(input).is_err());
        }
    }

    #[test]
    fn parses_route_rules_and_inline_rule_sets() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[outbounds]]
id = "direct"
type = "direct"

[[outbounds]]
id = "block"
type = "block"

[[rule_sets]]
id = "ads"
type = "inline"
rules = [
  { type = "rule", domain_keyword = ["ads"] },
]

[[routes]]
type = "rule"
inbound = ["http"]
network = ["tcp"]
domain_suffix = ["example.test"]
ip_cidr = ["10.0.0.0/8"]
port = [443]
port_range = ["10000-10010"]
rule_set = ["ads"]
outbound = "block"

[[routes]]
type = "logical"
mode = "or"
outbound = "direct"
rules = [
  { type = "rule", domain = ["example.org"] },
  { type = "rule", source_ip_cidr = ["127.0.0.0/8"] },
]
"#,
        )
        .expect("parse route config");

        assert_eq!(config.source.route_rule_sets.len(), 1);
        assert_eq!(config.source.routes.len(), 2);
        assert!(matches!(
            &config.source.routes[0],
            RouteRuleConfig::Rule {
                action: RouteActionConfig::Outbound(outbound),
                ..
            } if outbound == "block"
        ));
        assert!(matches!(
            &config.source.routes[1],
            RouteRuleConfig::Logical {
                mode: LogicalModeConfig::Or,
                ..
            }
        ));
    }

    #[test]
    fn parses_tun_and_transparent_inbounds() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "tun"
type = "tun"
interface_name = "rustbox0"
addresses = ["172.18.0.1/30"]
mtu = 1500
auto_route = true
route_includes = ["0.0.0.0/0"]
route_excludes = ["127.0.0.0/8"]

[[inbounds]]
id = "transparent"
type = "transparent"
listen = "127.0.0.1:12345"
network = "tcp"
mode = "redirect"
auto_rules = false

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse tun transparent config");

        assert_eq!(config.source.inbounds.len(), 2);
        assert!(matches!(
            &config.source.inbounds[0].kind,
            InboundConfigKind::Tun(value)
                if value.interface_name.as_deref() == Some("rustbox0")
                    && value.auto_route
        ));
        assert!(matches!(
            &config.source.inbounds[1].kind,
            InboundConfigKind::Transparent(value)
                if value.listen == Endpoint::localhost_v4(12345)
                    && value.network == TransparentNetwork::Tcp
        ));
    }

    #[test]
    fn parses_dns_config() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"

[[outbounds]]
id = "direct"
type = "direct"

[dns.cache]
enabled = true
max_entries = 256
min_ttl_seconds = 5
max_ttl_seconds = 300

[dns.fake_ip]
enabled = true
ipv4_pool = "198.18.0.0/15"
ttl_seconds = 60

[[dns.servers]]
id = "cf"
protocol = "https"
endpoint = "cloudflare-dns.com:443"
outbound = "direct"

[[dns.rules]]
action = "fake-ip"
domain_suffix = ["example.test"]
record_type = ["a"]

[[dns.hijack]]
network = "udp"
endpoint = "127.0.0.1:53"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse dns config");

        let dns = config.source.dns.expect("dns config");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].protocol, DnsServerProtocol::Https);
        assert_eq!(dns.rules.len(), 1);
        assert!(matches!(dns.rules[0].action, DnsRuleAction::FakeIp));
        assert_eq!(dns.cache.max_entries, 256);
        assert_eq!(dns.hijack.len(), 1);
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint() {
        let endpoint = Endpoint::from_str("[::1]:1080").expect("parse endpoint");

        assert_eq!(endpoint.port, 1080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V6(Ipv6Addr::LOCALHOST.octets()))
        );
    }

    #[test]
    fn parses_anytls_server_inbound() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "anytls-server"
type = "any-tls"
listen = "0.0.0.0:8443"
password = "secret"
tls = { certificate_path = "server.crt", private_key_path = "server.key", alpn = ["h2"] }

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse AnyTLS inbound");

        assert!(matches!(
            &config.source.inbounds[0].kind,
            InboundConfigKind::AnyTls { password, tls, .. }
                if password == "secret"
                    && tls.certificate_path == "server.crt"
                    && tls.private_key_path == "server.key"
                    && tls.alpn == ["h2"]
        ));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let error = parse_toml_str(
            r#"
schema_version = 2
"#,
        )
        .expect_err("unsupported schema");

        assert!(error.message.contains("unsupported config schema_version"));
    }

    #[test]
    fn parses_ipv4_endpoint() {
        let endpoint = Endpoint::from_str("127.0.0.1:18080").expect("parse endpoint");

        assert_eq!(endpoint.port, 18080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V4(Ipv4Addr::LOCALHOST.octets()))
        );
    }
}
