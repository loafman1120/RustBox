//! 配置流水线类型。
//!
//! 文件、Flutter、远程 API 等输入格式都应先转换为 `SourceConfig`，
//! 再进入解析、验证和编译阶段。运行时模块只接收编译后的类型化配置。

use core::num::NonZeroU64;
use regex::Regex;
pub use rustbox_dns_core::{
    DnsCacheConfig, DnsConfig, DnsHijackTarget, DnsRecordType, DnsRuleAction, DnsRuleConfig,
    DnsRuleMatcher, DnsServerConfig, DnsServerProtocol, FakeIpConfig,
};
pub use rustbox_kernel::{RouteMode, TransparentRedirectMode, TunDnsMode};
use rustbox_route::{ResolveStrategy, RouteAction, RouteOptions, RouteResolve};
use rustbox_types::{
    Endpoint, Host, InboundId, IpAddress, IpCidr, Network, OutboundId, PortRange, ProtocolHint,
    RejectReason, RouteDecision,
};
use std::collections::{HashMap, HashSet};

mod stages;

pub use stages::{ConfigCompiler, ConfigError, NormalizedConfig, ParsedConfig, ValidatedConfig};

mod compiler;
pub use compiler::compile_headless_route_matcher;
mod model;

pub use model::*;

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
            dial: DialConfig::default(),
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
                dial: DialConfig::default(),
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
                dial: DialConfig::default(),
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
                dial: DialConfig::default(),
                kind: OutboundConfigKind::AnyTls {
                    server: Endpoint::localhost_v4(443),
                    password: "secret".to_string(),
                    tls: Some(OutboundTlsConfig {
                        enabled: false,
                        server_name: None,
                        insecure: false,
                        alpn: Vec::new(),
                        client_certificate_pem: None,
                        client_private_key_pem: None,
                        certificate_authorities_pem: Vec::new(),
                        certificate_public_key_sha256: Vec::new(),
                        fingerprint: None,
                        ech_config: None,
                        reality: None,
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
                    dial: DialConfig::default(),
                    kind: OutboundConfigKind::UrlTest {
                        outbounds: vec!["direct".to_string()],
                        url: "https://www.gstatic.com/generate_204".to_string(),
                        interval_seconds: 300,
                        tolerance_ms: 50,
                        timeout_seconds: 10,
                        concurrency: 4,
                        failure_threshold: 2,
                        cache_path: None,
                        interrupt_exist_connections: false,
                    },
                },
                OutboundConfig {
                    id: "select".to_string(),
                    dial: DialConfig::default(),
                    kind: OutboundConfigKind::Selector {
                        outbounds: vec!["auto".to_string()],
                        default: None,
                        cache_path: None,
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
    fn rejects_detour_cycles() {
        let mut first = outbound_direct("first");
        first.dial.detour = Some("second".to_string());
        let mut second = outbound_direct("second");
        second.dial.detour = Some("first".to_string());
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![first, second],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "first".to_string(),
            }],
        };

        let error = validate_error(source);
        assert!(error.message.contains("detour cycle"));
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
