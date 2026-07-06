//! Configuration pipeline types.
//!
//! Input formats such as JSON, YAML, TOML, GUI state, or remote APIs should be
//! translated into `SourceConfig` before validation and compilation.

use core::num::NonZeroU64;
use rustbox_types::{Endpoint, InboundId, OutboundId, RejectReason, RouteDecision};
use std::collections::HashSet;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedConfig {
    pub source: SourceConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    pub source: SourceConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    pub inbounds: Vec<CompiledInbound>,
    pub outbounds: Vec<CompiledOutbound>,
    pub route_rules: Vec<CompiledRouteRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfig {
    HttpConnect { id: String, listen: Endpoint },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfig {
    Direct { id: String },
}

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

pub struct ConfigCompiler;

impl ConfigCompiler {
    pub fn parse(source: SourceConfig) -> Result<ParsedConfig, ConfigError> {
        Ok(ParsedConfig { source })
    }

    pub fn validate(parsed: ParsedConfig) -> Result<ValidatedConfig, ConfigError> {
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
}
