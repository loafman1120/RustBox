//! 配置流水线类型。
//!
//! 文件、GUI、远程 API、FFI 等输入格式都应先转换为 `SourceConfig`，
//! 再进入解析、验证和编译阶段。运行时模块只接收编译后的类型化配置。

use core::num::NonZeroU64;
use regex::Regex;
pub use rustbox_dns_core::{
    DnsCacheConfig, DnsConfig, DnsHijackTarget, DnsRecordType, DnsRuleAction, DnsRuleConfig,
    DnsRuleMatcher, DnsServerConfig, DnsServerProtocol, FakeIpConfig,
};
pub use rustbox_host_api::{RouteMode, TransparentRedirectMode, TunDnsMode};
use rustbox_types::{
    Endpoint, InboundId, IpCidr, Network, OutboundId, PortRange, RejectReason, RouteDecision,
};
use std::collections::{HashMap, HashSet};

mod stages;

pub use stages::{ConfigCompiler, ConfigError, NormalizedConfig, ParsedConfig, ValidatedConfig};

/// 格式无关的语义配置，是所有输入前端汇合后的统一模型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub dns: Option<DnsConfig>,
    pub route_rule_sets: Vec<RouteRuleSetConfig>,
    pub routes: Vec<RouteRuleConfig>,
}

impl SourceConfig {
    pub fn default_http_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig {
                id: "http".to_string(),
                kind: InboundConfigKind::HttpConnect {
                    listen,
                    username: None,
                    password: None,
                },
            }],
            outbounds: vec![OutboundConfig {
                id: "direct".to_string(),
                kind: OutboundConfigKind::Direct,
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        }
    }

    pub fn default_socks5_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig {
                id: "socks5".to_string(),
                kind: InboundConfigKind::Socks5 {
                    listen,
                    username: None,
                    password: None,
                },
            }],
            outbounds: vec![OutboundConfig {
                id: "direct".to_string(),
                kind: OutboundConfigKind::Direct,
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        }
    }
}

/// 运行图构造使用的类型化计划，逻辑 ID 已解析为稳定内部 ID。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    pub inbounds: Vec<CompiledInbound>,
    pub outbounds: Vec<CompiledOutbound>,
    pub dns: Option<CompiledDnsConfig>,
    pub route_rule_sets: Vec<CompiledRouteRuleSet>,
    pub route_rules: Vec<CompiledRouteRule>,
}

/// inbound 的源配置，描述用户想暴露的入口类型和监听地址。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundConfig {
    pub id: String,
    pub kind: InboundConfigKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfigKind {
    /// mixed 入口，在同一 TCP 监听地址上接受 HTTP 代理和 SOCKS5。
    Mixed {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// HTTP 代理入口，监听本地 TCP 地址并支持 CONNECT 和普通 absolute-form 请求。
    HttpConnect {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// SOCKS5 入口，监听本地 TCP 地址并支持 CONNECT/UDP ASSOCIATE。
    Socks5 {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// TUN packet-device inbound. The packet-to-flow stack is composed by the
    /// runtime/platform layer, not by the config model.
    Tun(TunInboundConfig),
    /// Transparent TCP redirect/TPROXY/WFP inbound using platform original-dst.
    Transparent(TransparentInboundConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunInboundConfig {
    pub interface_name: Option<String>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    pub route_mode: RouteMode,
    pub dns_mode: TunDnsMode,
    pub auto_route: bool,
    pub strict_route: bool,
    pub route_includes: Vec<IpCidr>,
    pub route_excludes: Vec<IpCidr>,
    pub dns_hijack: Vec<DnsHijackTarget>,
    pub platform_http_proxy: bool,
    pub auto_redirect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentInboundConfig {
    pub listen: Endpoint,
    pub network: TransparentNetwork,
    pub mode: TransparentRedirectMode,
    pub auto_rules: bool,
    pub mark: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentNetwork {
    Tcp,
    Udp,
    TcpUdp,
}

/// outbound 的源配置，描述可被路由引用的出站能力。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundConfig {
    pub id: String,
    pub kind: OutboundConfigKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfigKind {
    /// 直连出站，对应 sing-box `direct` outbound。
    Direct,
    /// 阻断出站，对应 sing-box `block` outbound。
    ///
    /// 当前路由编译器会把指向该 ID 的默认路由转成 `Reject(Policy)`，
    /// 避免数据面为“阻断”创建无意义的上游连接。
    Block,
    /// SOCKS5 上游代理，对应 sing-box `socks` outbound 的基础字段。
    Socks5 {
        /// SOCKS5 代理服务器地址和端口。
        server: Endpoint,
        /// SOCKS5 用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// SOCKS5 密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// HTTP CONNECT 上游代理，对应 sing-box `http` outbound 的基础字段。
    Http {
        /// HTTP 代理服务器地址和端口。
        server: Endpoint,
        /// HTTP 代理认证用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// HTTP 代理认证密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// Shadowsocks 上游代理，对应 sing-box `shadowsocks` outbound 的基础字段。
    Shadowsocks {
        /// Shadowsocks 服务器地址和端口。
        server: Endpoint,
        /// Shadowsocks 加密方法名称，例如 `aes-128-gcm`。
        method: String,
        /// Shadowsocks 密码；部分 2022 方法要求这里是 base64 密钥材料。
        password: String,
    },
    /// 手动出站组，对应 sing-box `selector` outbound 的基础字段。
    Selector {
        /// 可被选择的子出站逻辑 ID。
        outbounds: Vec<String>,
        /// 初始选择；未设置时使用 `outbounds` 第一项。
        default: Option<String>,
    },
    /// 延迟测试出站组，对应 sing-box `urltest` outbound 的基础字段。
    UrlTest {
        /// 可参与测试的子出站逻辑 ID。
        outbounds: Vec<String>,
        /// 测试 URL。
        url: String,
        /// 测试间隔秒数。
        interval_seconds: u64,
        /// 延迟容差毫秒数。
        tolerance_ms: u16,
    },
    /// VMess AEAD 上游代理。
    Vmess {
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    /// VLESS 上游代理；当前数据面支持普通 TCP 模式。
    Vless {
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    /// Trojan TLS 上游代理。
    Trojan {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    /// AnyTLS 上游代理；组合根通过 `rustbox-outbound-anytls` 实例化数据面。
    AnyTls {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

/// 路由源规则，使用逻辑 ID，尚不直接持有内部 `OutboundId`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteRuleConfig {
    Default {
        outbound: String,
    },
    RejectDefault {
        reason: RejectReason,
    },
    Rule {
        matcher: RouteMatcherConfig,
        action: RouteActionConfig,
    },
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<RouteMatcherConfig>,
        invert: bool,
        action: RouteActionConfig,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRuleSetConfig {
    pub id: String,
    pub rules: Vec<RouteMatcherConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteActionConfig {
    Outbound(String),
    Reject(RejectReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalModeConfig {
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMatcherConfig {
    Conditions(Box<RouteMatchConfig>),
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<RouteMatcherConfig>,
        invert: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteMatchConfig {
    pub inbound: Vec<String>,
    pub network: Vec<Network>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Vec<IpCidr>,
    pub source_ip_cidr: Vec<IpCidr>,
    pub port: Vec<PortRange>,
    pub source_port: Vec<PortRange>,
    pub rule_set: Vec<String>,
    pub invert: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledInbound {
    pub id: InboundId,
    pub logical_id: String,
    pub kind: CompiledInboundKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledInboundKind {
    Mixed {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    HttpConnect {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Tun(TunInboundConfig),
    Transparent(TransparentInboundConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledOutbound {
    pub id: OutboundId,
    pub logical_id: String,
    pub kind: CompiledOutboundKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledOutboundKind {
    /// 已分配内部 ID 的直连出站，组合根会实例化 direct 数据面模块。
    Direct,
    /// 已分配内部 ID 的阻断出站，路由引用它时会编译成策略拒绝。
    Block,
    /// 已分配内部 ID 的 SOCKS5 上游代理，当前组合根已有运行时模块。
    Socks5 {
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 HTTP CONNECT 上游代理，组合根会实例化 HTTP outbound 模块。
    Http {
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 Shadowsocks 上游代理，组合根会实例化 Shadowsocks 模块。
    Shadowsocks {
        server: Endpoint,
        method: String,
        password: String,
    },
    /// 已分配内部 ID 的手动出站组。当前编译为静态初始选择。
    Selector {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
    },
    /// 已分配内部 ID 的延迟测试出站组。当前编译为静态首选项。
    UrlTest {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
        url: String,
        interval_seconds: u64,
        tolerance_ms: u16,
    },
    Vmess {
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    Vless {
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    Trojan {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    AnyTls {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledDnsConfig {
    pub servers: Vec<CompiledDnsServerConfig>,
    pub rules: Vec<DnsRuleConfig>,
    pub final_server: String,
    pub cache: DnsCacheConfig,
    pub fake_ip: Option<FakeIpConfig>,
    pub hijack: Vec<DnsHijackTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledDnsServerConfig {
    pub id: String,
    pub protocol: DnsServerProtocol,
    pub endpoint: Endpoint,
    pub outbound: Option<OutboundId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledRouteRule {
    Default(RouteDecision),
    Rule {
        matcher: CompiledRouteMatcher,
        decision: RouteDecision,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRouteRuleSet {
    pub id: String,
    pub rules: Vec<CompiledRouteMatcher>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledRouteMatcher {
    Conditions(Box<CompiledRouteConditions>),
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<CompiledRouteMatcher>,
        invert: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledRouteConditions {
    pub inbounds: Vec<InboundId>,
    pub networks: Vec<Network>,
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ip_cidrs: Vec<IpCidr>,
    pub source_ip_cidrs: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub rule_sets: Vec<String>,
    pub invert: bool,
}

impl ConfigCompiler {
    pub fn parse(source: SourceConfig) -> Result<ParsedConfig, ConfigError> {
        Ok(ParsedConfig { source })
    }

    pub fn normalize(parsed: ParsedConfig) -> Result<NormalizedConfig, ConfigError> {
        Ok(NormalizedConfig {
            source: parsed.source,
        })
    }

    pub fn validate(normalized: NormalizedConfig) -> Result<ValidatedConfig, ConfigError> {
        // 验证阶段只检查语义正确性，不创建 socket、任务或运行时对象。
        if normalized.source.inbounds.is_empty() {
            return Err(ConfigError::new("at least one inbound is required"));
        }
        if normalized.source.outbounds.is_empty() {
            return Err(ConfigError::new("at least one outbound is required"));
        }

        let mut outbound_ids = HashSet::new();
        let mut outbound_kinds = HashMap::new();
        for outbound in &normalized.source.outbounds {
            let logical_id = outbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("outbound id must not be empty"));
            }
            if !outbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate outbound id `{logical_id}`"
                )));
            }
            outbound_kinds.insert(logical_id.to_string(), outbound.kind());
        }

        for outbound in &normalized.source.outbounds {
            let logical_id = outbound.logical_id();
            match &outbound.kind {
                OutboundConfigKind::Socks5 {
                    username, password, ..
                } => validate_optional_credentials("socks5", logical_id, username, password)?,
                OutboundConfigKind::Http {
                    username, password, ..
                } => validate_optional_credentials("http", logical_id, username, password)?,
                OutboundConfigKind::Shadowsocks {
                    method, password, ..
                } => {
                    if method.is_empty() {
                        return Err(ConfigError::new(format!(
                            "shadowsocks outbound `{logical_id}` method must not be empty"
                        )));
                    }
                    if password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "shadowsocks outbound `{logical_id}` password must not be empty"
                        )));
                    }
                }
                OutboundConfigKind::Selector {
                    outbounds, default, ..
                } => validate_outbound_group(
                    "selector",
                    logical_id,
                    outbounds,
                    default.as_deref(),
                    &outbound_ids,
                    &outbound_kinds,
                )?,
                OutboundConfigKind::UrlTest {
                    outbounds,
                    url,
                    interval_seconds,
                    ..
                } => {
                    validate_outbound_group(
                        "urltest",
                        logical_id,
                        outbounds,
                        None,
                        &outbound_ids,
                        &outbound_kinds,
                    )?;
                    if url.is_empty() {
                        return Err(ConfigError::new(format!(
                            "urltest outbound `{logical_id}` url must not be empty"
                        )));
                    }
                    if *interval_seconds == 0 {
                        return Err(ConfigError::new(format!(
                            "urltest outbound `{logical_id}` interval_seconds must be greater than zero"
                        )));
                    }
                }
                OutboundConfigKind::Vmess {
                    uuid,
                    security,
                    tls,
                    transport,
                    ..
                } => validate_proxy_protocol_config(
                    "vmess", logical_id, uuid, security, tls, transport,
                )?,
                OutboundConfigKind::Vless {
                    uuid,
                    flow,
                    tls,
                    transport,
                    ..
                } => {
                    validate_proxy_protocol_config("vless", logical_id, uuid, flow, tls, transport)?
                }
                OutboundConfigKind::Trojan {
                    password,
                    tls,
                    transport,
                    ..
                } => validate_secret_protocol_config(
                    "trojan",
                    logical_id,
                    password,
                    tls,
                    transport.as_deref(),
                )?,
                OutboundConfigKind::AnyTls { password, tls, .. } => {
                    validate_secret_protocol_config("anytls", logical_id, password, tls, None)?;
                    if tls.as_ref().is_some_and(|tls| !tls.enabled) {
                        return Err(ConfigError::new(format!(
                            "anytls outbound `{logical_id}` requires TLS"
                        )));
                    }
                }
                OutboundConfigKind::Direct | OutboundConfigKind::Block => {}
            }
        }

        let mut inbound_ids = HashSet::new();
        for inbound in &normalized.source.inbounds {
            let logical_id = inbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("inbound id must not be empty"));
            }
            if !inbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate inbound id `{logical_id}`"
                )));
            }
            match &inbound.kind {
                InboundConfigKind::Mixed {
                    username, password, ..
                } => {
                    validate_optional_credentials("mixed inbound", logical_id, username, password)?
                }
                InboundConfigKind::HttpConnect {
                    username, password, ..
                } => validate_optional_credentials("http inbound", logical_id, username, password)?,
                InboundConfigKind::Socks5 {
                    username, password, ..
                } => {
                    validate_optional_credentials("socks5 inbound", logical_id, username, password)?
                }
                InboundConfigKind::Tun(config) => validate_tun_inbound(logical_id, config)?,
                InboundConfigKind::Transparent(config) => {
                    validate_transparent_inbound(logical_id, config)?
                }
            }
        }

        if let Some(dns) = &normalized.source.dns {
            validate_dns_config(dns, &outbound_ids)?;
        }

        let mut rule_set_ids = HashSet::new();
        for rule_set in &normalized.source.route_rule_sets {
            if rule_set.id.is_empty() {
                return Err(ConfigError::new("route rule-set id must not be empty"));
            }
            if !rule_set_ids.insert(rule_set.id.clone()) {
                return Err(ConfigError::new(format!(
                    "duplicate route rule-set id `{}`",
                    rule_set.id
                )));
            }
            if rule_set.rules.is_empty() {
                return Err(ConfigError::new(format!(
                    "route rule-set `{}` must contain at least one rule",
                    rule_set.id
                )));
            }
        }

        for rule_set in &normalized.source.route_rule_sets {
            for matcher in &rule_set.rules {
                validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
            }
        }

        for rule in &normalized.source.routes {
            match rule {
                RouteRuleConfig::Default { outbound } => {
                    if !outbound_ids.contains(outbound.as_str()) {
                        return Err(ConfigError::new(format!(
                            "route references unknown outbound `{outbound}`"
                        )));
                    }
                }
                RouteRuleConfig::RejectDefault { .. } => {}
                RouteRuleConfig::Rule { matcher, action } => {
                    validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
                    validate_route_action(action, &outbound_ids)?;
                }
                RouteRuleConfig::Logical { rules, action, .. } => {
                    if rules.is_empty() {
                        return Err(ConfigError::new("logical route must include rules"));
                    }
                    for matcher in rules {
                        validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
                    }
                    validate_route_action(action, &outbound_ids)?;
                }
            }
        }

        Ok(ValidatedConfig {
            source: normalized.source,
        })
    }

    pub fn compile(validated: ValidatedConfig) -> Result<CompiledConfig, ConfigError> {
        // 编译阶段把用户可读的逻辑 ID 映射为内核使用的稳定非零 ID。
        let inbounds = validated
            .source
            .inbounds
            .iter()
            .enumerate()
            .map(|(index, inbound)| {
                let kind = match &inbound.kind {
                    InboundConfigKind::Mixed {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::Mixed {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::HttpConnect {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::HttpConnect {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::Socks5 {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::Socks5 {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::Tun(config) => CompiledInboundKind::Tun(config.clone()),
                    InboundConfigKind::Transparent(config) => {
                        CompiledInboundKind::Transparent(config.clone())
                    }
                };
                Ok(CompiledInbound {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: inbound.id.clone(),
                    kind,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let source_outbound_ids = validated
            .source
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| {
                (
                    outbound.logical_id().to_string(),
                    OutboundId::new(non_zero_id(index)),
                )
            })
            .collect::<HashMap<_, _>>();

        let source_outbounds = validated
            .source
            .outbounds
            .iter()
            .map(|outbound| (outbound.logical_id().to_string(), outbound))
            .collect::<HashMap<_, _>>();

        let outbounds = validated
            .source
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| {
                let kind = match &outbound.kind {
                    OutboundConfigKind::Direct => CompiledOutboundKind::Direct,
                    OutboundConfigKind::Block => CompiledOutboundKind::Block,
                    OutboundConfigKind::Socks5 {
                        server,
                        username,
                        password,
                    } => CompiledOutboundKind::Socks5 {
                        server: server.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Http {
                        server,
                        username,
                        password,
                    } => CompiledOutboundKind::Http {
                        server: server.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Shadowsocks {
                        server,
                        method,
                        password,
                    } => CompiledOutboundKind::Shadowsocks {
                        server: server.clone(),
                        method: method.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Selector { outbounds, default } => {
                        let selected = default.as_deref().unwrap_or_else(|| outbounds[0].as_str());
                        CompiledOutboundKind::Selector {
                            outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                            selected: source_outbound_route_decision(
                                selected,
                                &source_outbound_ids,
                                &source_outbounds,
                            )?,
                        }
                    }
                    OutboundConfigKind::UrlTest {
                        outbounds,
                        url,
                        interval_seconds,
                        tolerance_ms,
                    } => CompiledOutboundKind::UrlTest {
                        outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                        selected: source_outbound_route_decision(
                            &outbounds[0],
                            &source_outbound_ids,
                            &source_outbounds,
                        )?,
                        url: url.clone(),
                        interval_seconds: *interval_seconds,
                        tolerance_ms: *tolerance_ms,
                    },
                    OutboundConfigKind::Vmess {
                        server,
                        uuid,
                        security,
                        alter_id,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Vmess {
                        server: server.clone(),
                        uuid: uuid.clone(),
                        security: security.clone(),
                        alter_id: *alter_id,
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::Vless {
                        server,
                        uuid,
                        flow,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Vless {
                        server: server.clone(),
                        uuid: uuid.clone(),
                        flow: flow.clone(),
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::Trojan {
                        server,
                        password,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Trojan {
                        server: server.clone(),
                        password: password.clone(),
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::AnyTls {
                        server,
                        password,
                        tls,
                    } => CompiledOutboundKind::AnyTls {
                        server: server.clone(),
                        password: password.clone(),
                        tls: tls.clone(),
                    },
                };
                Ok(CompiledOutbound {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: outbound.id.clone(),
                    kind,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let inbound_by_logical_id = inbounds
            .iter()
            .map(|inbound| (inbound.logical_id().to_string(), inbound.internal_id()))
            .collect::<HashMap<_, _>>();
        let outbound_by_logical_id = outbounds
            .iter()
            .map(|outbound| (outbound.logical_id().to_string(), outbound.internal_id()))
            .collect::<HashMap<_, _>>();
        let dns = validated
            .source
            .dns
            .as_ref()
            .map(|dns| compile_dns_config(dns, &outbound_by_logical_id))
            .transpose()?;

        let route_rule_sets = validated
            .source
            .route_rule_sets
            .iter()
            .map(|rule_set| {
                let rules = rule_set
                    .rules
                    .iter()
                    .map(|matcher| compile_route_matcher(matcher, &inbound_by_logical_id))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CompiledRouteRuleSet {
                    id: rule_set.id.clone(),
                    rules,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let route_rules = validated
            .source
            .routes
            .iter()
            .map(|rule| match rule {
                RouteRuleConfig::Default { outbound } => {
                    let outbound_id = outbounds
                        .iter()
                        .find(|compiled| compiled.logical_id() == outbound)
                        .ok_or_else(|| {
                            ConfigError::new(format!("unknown outbound `{outbound}`"))
                        })?;
                    Ok(CompiledRouteRule::Default(outbound_id.route_decision()))
                }
                RouteRuleConfig::RejectDefault { reason } => Ok(CompiledRouteRule::Default(
                    RouteDecision::Reject(reason.clone()),
                )),
                RouteRuleConfig::Rule { matcher, action } => Ok(CompiledRouteRule::Rule {
                    matcher: compile_route_matcher(matcher, &inbound_by_logical_id)?,
                    decision: route_action_decision(action, &outbounds)?,
                }),
                RouteRuleConfig::Logical {
                    mode,
                    rules,
                    invert,
                    action,
                } => Ok(CompiledRouteRule::Rule {
                    matcher: CompiledRouteMatcher::Logical {
                        mode: mode.clone(),
                        rules: rules
                            .iter()
                            .map(|matcher| compile_route_matcher(matcher, &inbound_by_logical_id))
                            .collect::<Result<Vec<_>, _>>()?,
                        invert: *invert,
                    },
                    decision: route_action_decision(action, &outbounds)?,
                }),
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        Ok(CompiledConfig {
            inbounds,
            outbounds,
            dns,
            route_rule_sets,
            route_rules,
        })
    }
}

impl InboundConfig {
    pub fn logical_id(&self) -> &str {
        &self.id
    }
}

impl CompiledInbound {
    fn logical_id(&self) -> &str {
        &self.logical_id
    }

    fn internal_id(&self) -> InboundId {
        self.id
    }
}

impl OutboundConfig {
    pub fn logical_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> OutboundKind {
        match &self.kind {
            OutboundConfigKind::Selector { .. } => OutboundKind::Selector,
            OutboundConfigKind::UrlTest { .. } => OutboundKind::UrlTest,
            _ => OutboundKind::Concrete,
        }
    }
}

impl CompiledOutbound {
    fn logical_id(&self) -> &str {
        &self.logical_id
    }

    fn internal_id(&self) -> OutboundId {
        self.id
    }

    fn route_decision(&self) -> RouteDecision {
        match &self.kind {
            CompiledOutboundKind::Direct
            | CompiledOutboundKind::Socks5 { .. }
            | CompiledOutboundKind::Http { .. }
            | CompiledOutboundKind::Shadowsocks { .. }
            | CompiledOutboundKind::Vmess { .. }
            | CompiledOutboundKind::Vless { .. }
            | CompiledOutboundKind::Trojan { .. }
            | CompiledOutboundKind::AnyTls { .. } => RouteDecision::Forward(self.id),
            CompiledOutboundKind::Block => RouteDecision::Reject(RejectReason::Policy),
            CompiledOutboundKind::Selector { selected, .. }
            | CompiledOutboundKind::UrlTest { selected, .. } => selected.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundKind {
    Concrete,
    Selector,
    UrlTest,
}

fn validate_optional_credentials(
    protocol: &str,
    logical_id: &str,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<(), ConfigError> {
    // 代理认证字段成对出现，避免运行时猜测“空用户名”或“空密码”的含义。
    if username.is_some() != password.is_some() {
        return Err(ConfigError::new(format!(
            "{protocol} `{logical_id}` must set username and password together"
        )));
    }
    if username.as_deref() == Some("") || password.as_deref() == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} `{logical_id}` credentials must not be empty"
        )));
    }
    Ok(())
}

fn validate_tun_inbound(logical_id: &str, config: &TunInboundConfig) -> Result<(), ConfigError> {
    if config.addresses.is_empty() {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` must include at least one address"
        )));
    }
    if let Some(mtu) = config.mtu
        && mtu < 1280
    {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` mtu must be at least 1280"
        )));
    }
    if config.strict_route && !config.auto_route {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` strict_route requires auto_route"
        )));
    }
    if config.auto_redirect && !config.auto_route {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` auto_redirect requires auto_route"
        )));
    }
    Ok(())
}

fn validate_transparent_inbound(
    logical_id: &str,
    config: &TransparentInboundConfig,
) -> Result<(), ConfigError> {
    if config.network != TransparentNetwork::Tcp {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` currently supports tcp only"
        )));
    }
    if config.mode != TransparentRedirectMode::Redirect {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` currently supports redirect mode only"
        )));
    }
    if config.auto_rules {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` auto_rules are not implemented; set auto_rules = false and install platform redirect rules externally"
        )));
    }
    Ok(())
}

fn validate_outbound_group(
    protocol: &str,
    logical_id: &str,
    outbounds: &[String],
    default: Option<&str>,
    outbound_ids: &HashSet<String>,
    outbound_kinds: &HashMap<String, OutboundKind>,
) -> Result<(), ConfigError> {
    if outbounds.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` must include at least one outbound"
        )));
    }
    let mut seen = HashSet::new();
    for child in outbounds {
        if child.is_empty() {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` child outbound id must not be empty"
            )));
        }
        if child == logical_id {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` must not reference itself"
            )));
        }
        if !seen.insert(child) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` references duplicate child `{child}`"
            )));
        }
        if !outbound_ids.contains(child.as_str()) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` references unknown outbound `{child}`"
            )));
        }
        if outbound_kinds
            .get(child)
            .is_some_and(|kind| *kind != OutboundKind::Concrete)
        {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` must not reference group outbound `{child}`"
            )));
        }
    }
    if let Some(default) = default
        && !outbounds.iter().any(|child| child == default)
    {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` default `{default}` is not in outbounds"
        )));
    }
    Ok(())
}

fn validate_proxy_protocol_config(
    protocol: &str,
    logical_id: &str,
    uuid: &str,
    option: &Option<String>,
    tls: &Option<OutboundTlsConfig>,
    transport: &Option<String>,
) -> Result<(), ConfigError> {
    if uuid.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` uuid must not be empty"
        )));
    }
    if option.as_deref() == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` optional protocol field must not be empty"
        )));
    }
    validate_tls_and_transport(protocol, logical_id, tls, transport.as_deref())
}

fn validate_secret_protocol_config(
    protocol: &str,
    logical_id: &str,
    password: &str,
    tls: &Option<OutboundTlsConfig>,
    transport: Option<&str>,
) -> Result<(), ConfigError> {
    if password.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` password must not be empty"
        )));
    }
    validate_tls_and_transport(protocol, logical_id, tls, transport)
}

fn validate_tls_and_transport(
    protocol: &str,
    logical_id: &str,
    tls: &Option<OutboundTlsConfig>,
    transport: Option<&str>,
) -> Result<(), ConfigError> {
    if transport == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` transport must not be empty"
        )));
    }
    if let Some(tls) = tls {
        if tls.server_name.as_deref() == Some("") {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` tls.server_name must not be empty"
            )));
        }
        if tls.alpn.iter().any(|value| value.is_empty()) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` tls.alpn must not contain empty values"
            )));
        }
    }
    Ok(())
}

fn validate_route_action(
    action: &RouteActionConfig,
    outbound_ids: &HashSet<String>,
) -> Result<(), ConfigError> {
    match action {
        RouteActionConfig::Outbound(outbound) => {
            if outbound_ids.contains(outbound.as_str()) {
                Ok(())
            } else {
                Err(ConfigError::new(format!(
                    "route references unknown outbound `{outbound}`"
                )))
            }
        }
        RouteActionConfig::Reject(_) => Ok(()),
    }
}

fn validate_route_matcher(
    matcher: &RouteMatcherConfig,
    inbound_ids: &HashSet<String>,
    rule_set_ids: &HashSet<String>,
) -> Result<(), ConfigError> {
    match matcher {
        RouteMatcherConfig::Conditions(conditions) => {
            for inbound in &conditions.inbound {
                if !inbound_ids.contains(inbound.as_str()) {
                    return Err(ConfigError::new(format!(
                        "route references unknown inbound `{inbound}`"
                    )));
                }
            }
            for rule_set in &conditions.rule_set {
                if !rule_set_ids.contains(rule_set.as_str()) {
                    return Err(ConfigError::new(format!(
                        "route references unknown rule-set `{rule_set}`"
                    )));
                }
            }
            for pattern in &conditions.domain_regex {
                Regex::new(pattern).map_err(|err| {
                    ConfigError::new(format!("route domain_regex `{pattern}` is invalid: {err}"))
                })?;
            }
            Ok(())
        }
        RouteMatcherConfig::Logical { rules, .. } => {
            if rules.is_empty() {
                return Err(ConfigError::new("logical route matcher must include rules"));
            }
            for rule in rules {
                validate_route_matcher(rule, inbound_ids, rule_set_ids)?;
            }
            Ok(())
        }
    }
}

fn validate_dns_config(dns: &DnsConfig, outbound_ids: &HashSet<String>) -> Result<(), ConfigError> {
    if dns.servers.is_empty() {
        return Err(ConfigError::new(
            "dns.servers must contain at least one server",
        ));
    }
    let mut server_ids = HashSet::new();
    for server in &dns.servers {
        if server.id.is_empty() {
            return Err(ConfigError::new("dns server id must not be empty"));
        }
        if !server_ids.insert(server.id.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate dns server id `{}`",
                server.id
            )));
        }
        if let Some(outbound) = &server.outbound
            && !outbound_ids.contains(outbound.as_str())
        {
            return Err(ConfigError::new(format!(
                "dns server `{}` references unknown outbound `{outbound}`",
                server.id
            )));
        }
    }

    if let Some(final_server) = &dns.final_server
        && !server_ids.contains(final_server)
    {
        return Err(ConfigError::new(format!(
            "dns final_server references unknown server `{final_server}`"
        )));
    }

    for rule in &dns.rules {
        match &rule.action {
            DnsRuleAction::Server(server) if !server_ids.contains(server) => {
                return Err(ConfigError::new(format!(
                    "dns rule references unknown server `{server}`"
                )));
            }
            DnsRuleAction::Server(_) | DnsRuleAction::Reject | DnsRuleAction::FakeIp => {}
        }
        if matches!(rule.action, DnsRuleAction::FakeIp)
            && !dns.fake_ip.as_ref().is_some_and(|fake_ip| fake_ip.enabled)
        {
            return Err(ConfigError::new(
                "dns rule selects fake-ip but dns.fake_ip is disabled",
            ));
        }
    }

    if dns.cache.min_ttl_seconds > dns.cache.max_ttl_seconds {
        return Err(ConfigError::new(
            "dns cache min_ttl_seconds must be <= max_ttl_seconds",
        ));
    }
    if let Some(fake_ip) = &dns.fake_ip
        && fake_ip.enabled
    {
        rustbox_dns_core::FakeIpAllocator::new(fake_ip.clone())
            .map_err(|err| ConfigError::new(err.message))?;
    }
    Ok(())
}

fn compile_dns_config(
    dns: &DnsConfig,
    outbound_by_logical_id: &HashMap<String, OutboundId>,
) -> Result<CompiledDnsConfig, ConfigError> {
    let final_server = dns
        .final_server
        .clone()
        .unwrap_or_else(|| dns.servers[0].id.clone());
    let servers = dns
        .servers
        .iter()
        .map(|server| {
            let outbound = server
                .outbound
                .as_ref()
                .map(|logical_id| {
                    outbound_by_logical_id
                        .get(logical_id)
                        .copied()
                        .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
                })
                .transpose()?;
            Ok(CompiledDnsServerConfig {
                id: server.id.clone(),
                protocol: server.protocol,
                endpoint: server.endpoint.clone(),
                outbound,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;

    Ok(CompiledDnsConfig {
        servers,
        rules: dns.rules.clone(),
        final_server,
        cache: dns.cache.clone(),
        fake_ip: dns.fake_ip.clone(),
        hijack: dns.hijack.clone(),
    })
}

fn compile_route_matcher(
    matcher: &RouteMatcherConfig,
    inbound_by_logical_id: &HashMap<String, InboundId>,
) -> Result<CompiledRouteMatcher, ConfigError> {
    match matcher {
        RouteMatcherConfig::Conditions(conditions) => {
            let inbounds = conditions
                .inbound
                .iter()
                .map(|logical_id| {
                    inbound_by_logical_id
                        .get(logical_id)
                        .copied()
                        .ok_or_else(|| ConfigError::new(format!("unknown inbound `{logical_id}`")))
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(CompiledRouteMatcher::Conditions(Box::new(
                CompiledRouteConditions {
                    inbounds,
                    networks: conditions.network.clone(),
                    domains: conditions.domain.clone(),
                    domain_suffixes: conditions.domain_suffix.clone(),
                    domain_keywords: conditions.domain_keyword.clone(),
                    domain_regexes: conditions.domain_regex.clone(),
                    ip_cidrs: conditions.ip_cidr.clone(),
                    source_ip_cidrs: conditions.source_ip_cidr.clone(),
                    ports: conditions.port.clone(),
                    source_ports: conditions.source_port.clone(),
                    rule_sets: conditions.rule_set.clone(),
                    invert: conditions.invert,
                },
            )))
        }
        RouteMatcherConfig::Logical {
            mode,
            rules,
            invert,
        } => Ok(CompiledRouteMatcher::Logical {
            mode: mode.clone(),
            rules: rules
                .iter()
                .map(|rule| compile_route_matcher(rule, inbound_by_logical_id))
                .collect::<Result<Vec<_>, _>>()?,
            invert: *invert,
        }),
    }
}

fn route_action_decision(
    action: &RouteActionConfig,
    outbounds: &[CompiledOutbound],
) -> Result<RouteDecision, ConfigError> {
    match action {
        RouteActionConfig::Outbound(outbound) => outbounds
            .iter()
            .find(|compiled| compiled.logical_id() == outbound)
            .ok_or_else(|| ConfigError::new(format!("unknown outbound `{outbound}`")))
            .map(CompiledOutbound::route_decision),
        RouteActionConfig::Reject(reason) => Ok(RouteDecision::Reject(reason.clone())),
    }
}

fn compile_child_outbounds(
    outbounds: &[String],
    outbound_by_logical_id: &HashMap<String, OutboundId>,
) -> Result<Vec<OutboundId>, ConfigError> {
    outbounds
        .iter()
        .map(|logical_id| {
            outbound_by_logical_id
                .get(logical_id)
                .copied()
                .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
        })
        .collect()
}

fn source_outbound_route_decision(
    logical_id: &str,
    outbound_by_logical_id: &HashMap<String, OutboundId>,
    source_outbounds: &HashMap<String, &OutboundConfig>,
) -> Result<RouteDecision, ConfigError> {
    let outbound = source_outbounds
        .get(logical_id)
        .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))?;
    if matches!(&outbound.kind, OutboundConfigKind::Block) {
        Ok(RouteDecision::Reject(RejectReason::Policy))
    } else {
        outbound_by_logical_id
            .get(logical_id)
            .copied()
            .map(RouteDecision::Forward)
            .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
    }
}

fn non_zero_id(index: usize) -> NonZeroU64 {
    NonZeroU64::new(index as u64 + 1).expect("index plus one is non-zero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::Endpoint;

    fn validate_error(source: SourceConfig) -> ConfigError {
        let parsed = ConfigCompiler::parse(source).expect("parse");
        let normalized = ConfigCompiler::normalize(parsed).expect("normalize");
        ConfigCompiler::validate(normalized).expect_err("reject config")
    }

    fn inbound_http(id: &str) -> InboundConfig {
        InboundConfig {
            id: id.to_string(),
            kind: InboundConfigKind::HttpConnect {
                listen: Endpoint::localhost_v4(18080),
                username: None,
                password: None,
            },
        }
    }

    fn outbound_direct(id: &str) -> OutboundConfig {
        OutboundConfig {
            id: id.to_string(),
            kind: OutboundConfigKind::Direct,
        }
    }

    #[test]
    fn rejects_incomplete_inbound_credentials() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig {
                id: "socks".to_string(),
                kind: InboundConfigKind::Socks5 {
                    listen: Endpoint::localhost_v4(1080),
                    username: Some("alice".to_string()),
                    password: None,
                },
            }],
            outbounds: vec![outbound_direct("direct")],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("username and password together"));
    }

    #[test]
    fn rejects_incomplete_http_outbound_credentials() {
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![OutboundConfig {
                id: "http-out".to_string(),
                kind: OutboundConfigKind::Http {
                    server: Endpoint::localhost_v4(8080),
                    username: Some("user".to_string()),
                    password: None,
                },
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "http-out".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("username and password together"));
    }

    #[test]
    fn rejects_empty_shadowsocks_method() {
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![OutboundConfig {
                id: "ss".to_string(),
                kind: OutboundConfigKind::Shadowsocks {
                    server: Endpoint::localhost_v4(8388),
                    method: String::new(),
                    password: "secret".to_string(),
                },
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "ss".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("method must not be empty"));
    }

    #[test]
    fn rejects_anytls_with_tls_disabled() {
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![OutboundConfig {
                id: "anytls".to_string(),
                kind: OutboundConfigKind::AnyTls {
                    server: Endpoint::localhost_v4(443),
                    password: "secret".to_string(),
                    tls: Some(OutboundTlsConfig {
                        enabled: false,
                        server_name: None,
                        insecure: false,
                        alpn: Vec::new(),
                    }),
                },
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "anytls".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("requires TLS"));
    }

    #[test]
    fn rejects_selector_referencing_group_outbound() {
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![
                outbound_direct("direct"),
                OutboundConfig {
                    id: "auto".to_string(),
                    kind: OutboundConfigKind::UrlTest {
                        outbounds: vec!["direct".to_string()],
                        url: "https://www.gstatic.com/generate_204".to_string(),
                        interval_seconds: 300,
                        tolerance_ms: 50,
                    },
                },
                OutboundConfig {
                    id: "select".to_string(),
                    kind: OutboundConfigKind::Selector {
                        outbounds: vec!["auto".to_string()],
                        default: None,
                    },
                },
            ],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "select".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("must not reference group outbound"));
    }

    #[test]
    fn rejects_transparent_auto_rules_until_platform_rule_install_is_implemented() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig {
                id: "transparent".to_string(),
                kind: InboundConfigKind::Transparent(TransparentInboundConfig {
                    listen: Endpoint::localhost_v4(12345),
                    network: TransparentNetwork::Tcp,
                    mode: TransparentRedirectMode::Redirect,
                    auto_rules: true,
                    mark: None,
                }),
            }],
            outbounds: vec![outbound_direct("direct")],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        };

        let error = validate_error(source);

        assert!(error.message.contains("auto_rules are not implemented"));
    }
}
