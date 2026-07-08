//! 配置流水线类型。
//!
//! 文件、GUI、远程 API、FFI 等输入格式都应先转换为 `SourceConfig`，
//! 再进入解析、验证和编译阶段。运行时模块只接收编译后的类型化配置。

use core::num::NonZeroU64;
use regex::Regex;
use rustbox_types::{
    Endpoint, InboundId, IpCidr, Network, OutboundId, PortRange, RejectReason, RouteDecision,
};
use std::collections::{HashMap, HashSet};

/// 格式无关的语义配置，是所有输入前端汇合后的统一模型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route_rule_sets: Vec<RouteRuleSetConfig>,
    pub routes: Vec<RouteRuleConfig>,
}

impl SourceConfig {
    pub fn default_http_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen,
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        }
    }

    pub fn default_socks5_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig::Socks5 {
                id: "socks5".to_string(),
                listen,
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        }
    }
}

/// 已完成输入层解析的配置，目前保留阶段边界以便后续加入 normalization。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedConfig {
    pub source: SourceConfig,
}

/// 已通过语义校验的配置，保证 ID 唯一、引用存在、基础拓扑可构造。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    pub source: SourceConfig,
}

/// 运行图构造使用的类型化计划，逻辑 ID 已解析为稳定内部 ID。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    pub inbounds: Vec<CompiledInbound>,
    pub outbounds: Vec<CompiledOutbound>,
    pub route_rule_sets: Vec<CompiledRouteRuleSet>,
    pub route_rules: Vec<CompiledRouteRule>,
}

/// inbound 的源配置，描述用户想暴露的入口类型和监听地址。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfig {
    /// mixed 入口，在同一 TCP 监听地址上接受 HTTP 代理和 SOCKS5。
    Mixed {
        id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// HTTP 代理入口，监听本地 TCP 地址并支持 CONNECT 和普通 absolute-form 请求。
    HttpConnect {
        id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// SOCKS5 入口，监听本地 TCP 地址并支持 CONNECT/UDP ASSOCIATE。
    Socks5 {
        id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
}

/// outbound 的源配置，描述可被路由引用的出站能力。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfig {
    /// 直连出站，对应 sing-box `direct` outbound。
    Direct {
        /// 用户配置里的逻辑 ID，路由规则通过它引用该 outbound。
        id: String,
    },
    /// 阻断出站，对应 sing-box `block` outbound。
    ///
    /// 当前路由编译器会把指向该 ID 的默认路由转成 `Reject(Policy)`，
    /// 避免数据面为“阻断”创建无意义的上游连接。
    Block {
        /// 用户配置里的逻辑 ID，路由规则通过它引用该 outbound。
        id: String,
    },
    /// SOCKS5 上游代理，对应 sing-box `socks` outbound 的基础字段。
    Socks5 {
        /// 用户配置里的逻辑 ID，路由规则通过它引用该 outbound。
        id: String,
        /// SOCKS5 代理服务器地址和端口。
        server: Endpoint,
        /// SOCKS5 用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// SOCKS5 密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// HTTP CONNECT 上游代理，对应 sing-box `http` outbound 的基础字段。
    Http {
        /// 用户配置里的逻辑 ID，路由规则通过它引用该 outbound。
        id: String,
        /// HTTP 代理服务器地址和端口。
        server: Endpoint,
        /// HTTP 代理认证用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// HTTP 代理认证密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// Shadowsocks 上游代理，对应 sing-box `shadowsocks` outbound 的基础字段。
    Shadowsocks {
        /// 用户配置里的逻辑 ID，路由规则通过它引用该 outbound。
        id: String,
        /// Shadowsocks 服务器地址和端口。
        server: Endpoint,
        /// Shadowsocks 加密方法名称，例如 `aes-128-gcm`。
        method: String,
        /// Shadowsocks 密码；部分 2022 方法要求这里是 base64 密钥材料。
        password: String,
    },
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
pub enum CompiledInbound {
    Mixed {
        id: InboundId,
        logical_id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    HttpConnect {
        id: InboundId,
        logical_id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        id: InboundId,
        logical_id: String,
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledOutbound {
    /// 已分配内部 ID 的直连出站，组合根会实例化 direct 数据面模块。
    Direct { id: OutboundId, logical_id: String },
    /// 已分配内部 ID 的阻断出站，路由引用它时会编译成策略拒绝。
    Block { id: OutboundId, logical_id: String },
    /// 已分配内部 ID 的 SOCKS5 上游代理，当前组合根已有运行时模块。
    Socks5 {
        id: OutboundId,
        logical_id: String,
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 HTTP CONNECT 上游代理，组合根会实例化 HTTP outbound 模块。
    Http {
        id: OutboundId,
        logical_id: String,
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 Shadowsocks 上游代理，组合根会实例化 Shadowsocks 模块。
    Shadowsocks {
        id: OutboundId,
        logical_id: String,
        server: Endpoint,
        method: String,
        password: String,
    },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub message: String,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 配置编译器维持 Source -> Parsed -> Validated -> Compiled 的阶段边界。
pub struct ConfigCompiler;

impl ConfigCompiler {
    pub fn parse(source: SourceConfig) -> Result<ParsedConfig, ConfigError> {
        Ok(ParsedConfig { source })
    }

    pub fn validate(parsed: ParsedConfig) -> Result<ValidatedConfig, ConfigError> {
        // 验证阶段只检查语义正确性，不创建 socket、任务或运行时对象。
        if parsed.source.inbounds.is_empty() {
            return Err(ConfigError::new("at least one inbound is required"));
        }
        if parsed.source.outbounds.is_empty() {
            return Err(ConfigError::new("at least one outbound is required"));
        }

        let mut outbound_ids = HashSet::new();
        for outbound in &parsed.source.outbounds {
            let logical_id = outbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("outbound id must not be empty"));
            }
            if !outbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate outbound id `{logical_id}`"
                )));
            }
            match outbound {
                OutboundConfig::Socks5 {
                    username, password, ..
                } => validate_optional_credentials("socks5", logical_id, username, password)?,
                OutboundConfig::Http {
                    username, password, ..
                } => validate_optional_credentials("http", logical_id, username, password)?,
                OutboundConfig::Shadowsocks {
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
                OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => {}
            }
        }

        let mut inbound_ids = HashSet::new();
        for inbound in &parsed.source.inbounds {
            let logical_id = inbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("inbound id must not be empty"));
            }
            if !inbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate inbound id `{logical_id}`"
                )));
            }
            match inbound {
                InboundConfig::Mixed {
                    username, password, ..
                } => {
                    validate_optional_credentials("mixed inbound", logical_id, username, password)?
                }
                InboundConfig::HttpConnect {
                    username, password, ..
                } => validate_optional_credentials("http inbound", logical_id, username, password)?,
                InboundConfig::Socks5 {
                    username, password, ..
                } => {
                    validate_optional_credentials("socks5 inbound", logical_id, username, password)?
                }
            }
        }

        let mut rule_set_ids = HashSet::new();
        for rule_set in &parsed.source.route_rule_sets {
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

        for rule_set in &parsed.source.route_rule_sets {
            for matcher in &rule_set.rules {
                validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
            }
        }

        for rule in &parsed.source.routes {
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
            source: parsed.source,
        })
    }

    pub fn compile(validated: ValidatedConfig) -> Result<CompiledConfig, ConfigError> {
        // 编译阶段把用户可读的逻辑 ID 映射为内核使用的稳定非零 ID。
        let inbounds = validated
            .source
            .inbounds
            .iter()
            .enumerate()
            .map(|(index, inbound)| match inbound {
                InboundConfig::Mixed {
                    id,
                    listen,
                    username,
                    password,
                } => Ok(CompiledInbound::Mixed {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    listen: listen.clone(),
                    username: username.clone(),
                    password: password.clone(),
                }),
                InboundConfig::HttpConnect {
                    id,
                    listen,
                    username,
                    password,
                } => Ok(CompiledInbound::HttpConnect {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    listen: listen.clone(),
                    username: username.clone(),
                    password: password.clone(),
                }),
                InboundConfig::Socks5 {
                    id,
                    listen,
                    username,
                    password,
                } => Ok(CompiledInbound::Socks5 {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    listen: listen.clone(),
                    username: username.clone(),
                    password: password.clone(),
                }),
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let outbounds = validated
            .source
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| match outbound {
                OutboundConfig::Direct { id } => Ok(CompiledOutbound::Direct {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                }),
                OutboundConfig::Block { id } => Ok(CompiledOutbound::Block {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                }),
                OutboundConfig::Socks5 {
                    id,
                    server,
                    username,
                    password,
                } => Ok(CompiledOutbound::Socks5 {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    server: server.clone(),
                    username: username.clone(),
                    password: password.clone(),
                }),
                OutboundConfig::Http {
                    id,
                    server,
                    username,
                    password,
                } => Ok(CompiledOutbound::Http {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    server: server.clone(),
                    username: username.clone(),
                    password: password.clone(),
                }),
                OutboundConfig::Shadowsocks {
                    id,
                    server,
                    method,
                    password,
                } => Ok(CompiledOutbound::Shadowsocks {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    server: server.clone(),
                    method: method.clone(),
                    password: password.clone(),
                }),
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let inbound_by_logical_id = inbounds
            .iter()
            .map(|inbound| (inbound.logical_id().to_string(), inbound.internal_id()))
            .collect::<HashMap<_, _>>();

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
            route_rule_sets,
            route_rules,
        })
    }
}

impl InboundConfig {
    pub fn logical_id(&self) -> &str {
        match self {
            Self::Mixed { id, .. } => id,
            Self::HttpConnect { id, .. } => id,
            Self::Socks5 { id, .. } => id,
        }
    }
}

impl CompiledInbound {
    fn logical_id(&self) -> &str {
        match self {
            Self::Mixed { logical_id, .. } => logical_id,
            Self::HttpConnect { logical_id, .. } => logical_id,
            Self::Socks5 { logical_id, .. } => logical_id,
        }
    }

    fn internal_id(&self) -> InboundId {
        match self {
            Self::Mixed { id, .. } => *id,
            Self::HttpConnect { id, .. } => *id,
            Self::Socks5 { id, .. } => *id,
        }
    }
}

impl OutboundConfig {
    pub fn logical_id(&self) -> &str {
        match self {
            Self::Direct { id } => id,
            Self::Block { id } => id,
            Self::Socks5 { id, .. } => id,
            Self::Http { id, .. } => id,
            Self::Shadowsocks { id, .. } => id,
        }
    }
}

impl CompiledOutbound {
    fn logical_id(&self) -> &str {
        match self {
            Self::Direct { logical_id, .. } => logical_id,
            Self::Block { logical_id, .. } => logical_id,
            Self::Socks5 { logical_id, .. } => logical_id,
            Self::Http { logical_id, .. } => logical_id,
            Self::Shadowsocks { logical_id, .. } => logical_id,
        }
    }

    fn route_decision(&self) -> RouteDecision {
        match self {
            Self::Direct { id, .. }
            | Self::Socks5 { id, .. }
            | Self::Http { id, .. }
            | Self::Shadowsocks { id, .. } => RouteDecision::Forward(*id),
            Self::Block { .. } => RouteDecision::Reject(RejectReason::Policy),
        }
    }
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

fn non_zero_id(index: usize) -> NonZeroU64 {
    NonZeroU64::new(index as u64 + 1).expect("index plus one is non-zero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::Endpoint;

    #[test]
    fn compiles_default_http_proxy_to_typed_runtime_plan() {
        let source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(18080));
        let parsed = ConfigCompiler::parse(source).expect("parse");
        let validated = ConfigCompiler::validate(parsed).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");

        assert_eq!(compiled.inbounds.len(), 1);
        assert_eq!(compiled.outbounds.len(), 1);
        assert_eq!(compiled.route_rules.len(), 1);
    }

    #[test]
    fn compiles_default_socks5_proxy_to_typed_runtime_plan() {
        let source = SourceConfig::default_socks5_proxy(Endpoint::localhost_v4(1080));
        let parsed = ConfigCompiler::parse(source).expect("parse");
        let validated = ConfigCompiler::validate(parsed).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");

        assert_eq!(compiled.inbounds.len(), 1);
        assert!(matches!(
            compiled.inbounds[0],
            CompiledInbound::Socks5 { .. }
        ));
        assert_eq!(compiled.outbounds.len(), 1);
        assert_eq!(compiled.route_rules.len(), 1);
    }

    #[test]
    fn compiles_first_batch_sing_box_style_outbounds() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen: Endpoint::localhost_v4(18080),
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    id: "direct".to_string(),
                },
                OutboundConfig::Block {
                    id: "block".to_string(),
                },
                OutboundConfig::Socks5 {
                    id: "socks".to_string(),
                    server: Endpoint::localhost_v4(1080),
                    username: Some("user".to_string()),
                    password: Some("pass".to_string()),
                },
                OutboundConfig::Http {
                    id: "http-out".to_string(),
                    server: Endpoint::localhost_v4(8080),
                    username: None,
                    password: None,
                },
                OutboundConfig::Shadowsocks {
                    id: "ss".to_string(),
                    server: Endpoint::localhost_v4(8388),
                    method: "aes-128-gcm".to_string(),
                    password: "test-password".to_string(),
                },
            ],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "block".to_string(),
            }],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let validated = ConfigCompiler::validate(parsed).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");

        assert_eq!(compiled.outbounds.len(), 5);
        assert!(matches!(
            compiled.route_rules[0],
            CompiledRouteRule::Default(RouteDecision::Reject(RejectReason::Policy))
        ));
    }

    #[test]
    fn compiles_mixed_inbound_with_credentials() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::Mixed {
                id: "mixed".to_string(),
                listen: Endpoint::localhost_v4(2080),
                username: Some("alice".to_string()),
                password: Some("secret".to_string()),
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let validated = ConfigCompiler::validate(parsed).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");

        assert!(matches!(
            &compiled.inbounds[0],
            CompiledInbound::Mixed {
                username: Some(username),
                password: Some(password),
                ..
            } if username == "alice" && password == "secret"
        ));
    }

    #[test]
    fn compiles_ordered_route_rules_and_rule_sets() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen: Endpoint::localhost_v4(18080),
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    id: "direct".to_string(),
                },
                OutboundConfig::Block {
                    id: "block".to_string(),
                },
            ],
            route_rule_sets: vec![RouteRuleSetConfig {
                id: "ads".to_string(),
                rules: vec![RouteMatcherConfig::Conditions(Box::new(RouteMatchConfig {
                    domain_keyword: vec!["ads".to_string()],
                    ..RouteMatchConfig::default()
                }))],
            }],
            routes: vec![
                RouteRuleConfig::Rule {
                    matcher: RouteMatcherConfig::Conditions(Box::new(RouteMatchConfig {
                        inbound: vec!["http".to_string()],
                        network: vec![Network::Tcp],
                        domain_suffix: vec!["example.test".to_string()],
                        port: vec![PortRange::single(443)],
                        rule_set: vec!["ads".to_string()],
                        ..RouteMatchConfig::default()
                    })),
                    action: RouteActionConfig::Outbound("block".to_string()),
                },
                RouteRuleConfig::Default {
                    outbound: "direct".to_string(),
                },
            ],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let validated = ConfigCompiler::validate(parsed).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");

        assert_eq!(compiled.route_rule_sets.len(), 1);
        assert!(matches!(
            compiled.route_rules[0],
            CompiledRouteRule::Rule {
                decision: RouteDecision::Reject(RejectReason::Policy),
                ..
            }
        ));
    }

    #[test]
    fn rejects_incomplete_inbound_credentials() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::Socks5 {
                id: "socks".to_string(),
                listen: Endpoint::localhost_v4(1080),
                username: Some("alice".to_string()),
                password: None,
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let error = ConfigCompiler::validate(parsed).expect_err("reject credentials");

        assert!(error.message.contains("username and password together"));
    }

    #[test]
    fn rejects_incomplete_http_outbound_credentials() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen: Endpoint::localhost_v4(18080),
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Http {
                id: "http-out".to_string(),
                server: Endpoint::localhost_v4(8080),
                username: Some("user".to_string()),
                password: None,
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "http-out".to_string(),
            }],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let error = ConfigCompiler::validate(parsed).expect_err("reject credentials");

        assert!(error.message.contains("username and password together"));
    }

    #[test]
    fn rejects_empty_shadowsocks_method() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen: Endpoint::localhost_v4(18080),
                username: None,
                password: None,
            }],
            outbounds: vec![OutboundConfig::Shadowsocks {
                id: "ss".to_string(),
                server: Endpoint::localhost_v4(8388),
                method: String::new(),
                password: "secret".to_string(),
            }],
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "ss".to_string(),
            }],
        };

        let parsed = ConfigCompiler::parse(source).expect("parse");
        let error = ConfigCompiler::validate(parsed).expect_err("reject method");

        assert!(error.message.contains("method must not be empty"));
    }
}
