//! 配置流水线类型。
//!
//! 文件、GUI、远程 API、FFI 等输入格式都应先转换为 `SourceConfig`，
//! 再进入解析、验证和编译阶段。运行时模块只接收编译后的类型化配置。

use core::num::NonZeroU64;
use rustbox_types::{Endpoint, InboundId, OutboundId, RejectReason, RouteDecision};
use std::collections::HashSet;

/// 格式无关的语义配置，是所有输入前端汇合后的统一模型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routes: Vec<RouteRuleConfig>,
}

impl SourceConfig {
    pub fn default_http_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig::HttpConnect {
                id: "http".to_string(),
                listen,
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
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
            }],
            outbounds: vec![OutboundConfig::Direct {
                id: "direct".to_string(),
            }],
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
    pub route_rules: Vec<CompiledRouteRule>,
}

/// inbound 的源配置，描述用户想暴露的入口类型和监听地址。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfig {
    HttpConnect { id: String, listen: Endpoint },
    Socks5 { id: String, listen: Endpoint },
}

/// outbound 的源配置，描述可被路由引用的出站能力。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfig {
    Direct { id: String },
}

/// 路由源规则，使用逻辑 ID，尚不直接持有内部 `OutboundId`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteRuleConfig {
    Default { outbound: String },
    RejectDefault { reason: RejectReason },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledInbound {
    HttpConnect {
        id: InboundId,
        logical_id: String,
        listen: Endpoint,
    },
    Socks5 {
        id: InboundId,
        logical_id: String,
        listen: Endpoint,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledOutbound {
    Direct { id: OutboundId, logical_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledRouteRule {
    Default(RouteDecision),
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
        }

        for rule in &parsed.source.routes {
            if let RouteRuleConfig::Default { outbound } = rule
                && !outbound_ids.contains(outbound.as_str())
            {
                return Err(ConfigError::new(format!(
                    "route references unknown outbound `{outbound}`"
                )));
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
                InboundConfig::HttpConnect { id, listen } => Ok(CompiledInbound::HttpConnect {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    listen: listen.clone(),
                }),
                InboundConfig::Socks5 { id, listen } => Ok(CompiledInbound::Socks5 {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: id.clone(),
                    listen: listen.clone(),
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
                        .find_map(|compiled| match compiled {
                            CompiledOutbound::Direct { id, logical_id }
                                if logical_id == outbound =>
                            {
                                Some(*id)
                            }
                            CompiledOutbound::Direct { .. } => None,
                        })
                        .ok_or_else(|| {
                            ConfigError::new(format!("unknown outbound `{outbound}`"))
                        })?;
                    Ok(CompiledRouteRule::Default(RouteDecision::Forward(
                        outbound_id,
                    )))
                }
                RouteRuleConfig::RejectDefault { reason } => Ok(CompiledRouteRule::Default(
                    RouteDecision::Reject(reason.clone()),
                )),
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        Ok(CompiledConfig {
            inbounds,
            outbounds,
            route_rules,
        })
    }
}

impl InboundConfig {
    pub fn logical_id(&self) -> &str {
        match self {
            Self::HttpConnect { id, .. } => id,
            Self::Socks5 { id, .. } => id,
        }
    }
}

impl OutboundConfig {
    pub fn logical_id(&self) -> &str {
        match self {
            Self::Direct { id } => id,
        }
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
}
