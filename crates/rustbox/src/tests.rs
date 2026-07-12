use super::*;
use rustbox_config::{
    ConfigError, InboundConfig, InboundConfigKind, OutboundConfig, OutboundConfigKind,
    RouteRuleConfig, SourceConfig,
};
use rustbox_control::EngineState;
use rustbox_control_api::ControlApiConfig;
use rustbox_observability::ObservabilityStore;
use rustbox_types::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;

fn inbound_http(id: &str) -> InboundConfig {
    InboundConfig {
        id: id.to_string(),
        kind: InboundConfigKind::HttpConnect {
            listen: Endpoint::localhost_v4(0),
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
fn composes_default_http_proxy_runtime_graph() {
    let runtime =
        RuntimeGraphBuilder::default_http_proxy(Endpoint::localhost_v4(0)).expect("compose");

    assert_eq!(runtime.engine().outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn composes_default_socks5_proxy_runtime_graph() {
    let runtime =
        RuntimeGraphBuilder::default_socks5_proxy(Endpoint::localhost_v4(0)).expect("compose");

    assert_eq!(runtime.engine().outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn validates_control_grpc_options_during_construction() {
    let options = RustBoxOptions::default().with_control_grpc(
        ControlApiConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            ..ControlApiConfig::default()
        },
        Arc::new(ObservabilityStore::default()),
    );

    let error = match RustBox::with_options(
        SourceConfig::default_http_proxy(Endpoint::localhost_v4(0)),
        options,
    ) {
        Ok(_) => panic!("expected public unauthenticated control API to be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ComposeError::Control(message) if message.contains("bearer token")
    ));
}

#[tokio::test]
async fn owns_control_grpc_lifecycle() {
    let config = ControlApiConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..ControlApiConfig::default()
    };
    let expected_listen = config.listen;
    let options = RustBoxOptions::default()
        .with_control_grpc(config, Arc::new(ObservabilityStore::default()));
    let mut runtime = RustBox::with_options(
        SourceConfig::default_http_proxy(Endpoint::localhost_v4(0)),
        options,
    )
    .expect("compose with control gRPC");

    assert_eq!(runtime.control_grpc_addr(), Some(expected_listen));
    runtime
        .start()
        .await
        .expect("start runtime and control gRPC");
    runtime.stop().await.expect("stop runtime and control gRPC");
    assert_eq!(runtime.snapshot().state, EngineState::Stopped);
}

#[test]
fn composes_first_batch_proxy_outbounds() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![
            outbound_direct("direct"),
            OutboundConfig {
                id: "block".to_string(),
                kind: OutboundConfigKind::Block,
            },
            OutboundConfig {
                id: "socks".to_string(),
                kind: OutboundConfigKind::Socks5 {
                    server: Endpoint::localhost_v4(1080),
                    username: None,
                    password: None,
                },
            },
            OutboundConfig {
                id: "http-out".to_string(),
                kind: OutboundConfigKind::Http {
                    server: Endpoint::localhost_v4(8080),
                    username: None,
                    password: None,
                },
            },
            OutboundConfig {
                id: "ss".to_string(),
                kind: OutboundConfigKind::Shadowsocks {
                    server: Endpoint::localhost_v4(8388),
                    method: "aes-128-gcm".to_string(),
                    password: "test-password".to_string(),
                },
            },
        ],
        dns: None,
        route_rule_sets: Vec::new(),
        routes: vec![RouteRuleConfig::Default {
            outbound: "direct".to_string(),
        }],
    };

    let runtime = RuntimeGraphBuilder::new()
        .compose_source(source)
        .expect("compose proxy outbounds");

    assert_eq!(runtime.engine().outbound_count(), 4);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn composes_mixed_inbound_runtime_graph() {
    let source = SourceConfig {
        inbounds: vec![InboundConfig {
            id: "mixed".to_string(),
            kind: InboundConfigKind::Mixed {
                listen: Endpoint::localhost_v4(0),
                username: Some("alice".to_string()),
                password: Some("secret".to_string()),
            },
        }],
        outbounds: vec![outbound_direct("direct")],
        dns: None,
        route_rule_sets: Vec::new(),
        routes: vec![RouteRuleConfig::Default {
            outbound: "direct".to_string(),
        }],
    };

    let runtime = RuntimeGraphBuilder::new()
        .compose_source(source)
        .expect("compose mixed inbound");

    assert_eq!(runtime.engine().outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn composes_selector_as_static_child_route() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![
            outbound_direct("direct"),
            OutboundConfig {
                id: "select".to_string(),
                kind: OutboundConfigKind::Selector {
                    outbounds: vec!["direct".to_string()],
                    default: Some("direct".to_string()),
                },
            },
        ],
        dns: None,
        route_rule_sets: Vec::new(),
        routes: vec![RouteRuleConfig::Default {
            outbound: "select".to_string(),
        }],
    };

    let runtime = RuntimeGraphBuilder::new()
        .compose_source(source)
        .expect("compose selector");

    assert_eq!(runtime.engine().outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

fn implemented_protocol_outbounds() -> Vec<(&'static str, OutboundConfigKind)> {
    vec![
        (
            "vmess",
            OutboundConfigKind::Vmess {
                server: Endpoint::localhost_v4(443),
                uuid: "00000000-0000-0000-0000-000000000001".to_string(),
                security: Some("auto".to_string()),
                alter_id: Some(0),
                tls: None,
                transport: Some("tcp".to_string()),
            },
        ),
        (
            "vless",
            OutboundConfigKind::Vless {
                server: Endpoint::localhost_v4(443),
                uuid: "00000000-0000-0000-0000-000000000002".to_string(),
                flow: None,
                tls: None,
                transport: Some("tcp".to_string()),
            },
        ),
        (
            "trojan",
            OutboundConfigKind::Trojan {
                server: Endpoint::localhost_v4(443),
                password: "secret".to_string(),
                tls: None,
                transport: Some("tcp".to_string()),
            },
        ),
    ]
}

#[test]
fn composes_vmess_vless_and_trojan_runtime_graphs() {
    for (protocol, kind) in implemented_protocol_outbounds() {
        let source = SourceConfig {
            inbounds: vec![inbound_http("http")],
            outbounds: vec![OutboundConfig {
                id: protocol.to_string(),
                kind,
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: protocol.to_string(),
            }],
        };

        let runtime = RuntimeGraphBuilder::new()
            .compose_source(source)
            .unwrap_or_else(|error| panic!("compose {protocol}: {error:?}"));
        assert_eq!(runtime.engine().outbound_count(), 1, "{protocol}");
        assert_eq!(runtime.service_count(), 1, "{protocol}");
    }
}

#[test]
fn composes_anytls_outbound_runtime_graph() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![OutboundConfig {
            id: "anytls".to_string(),
            kind: OutboundConfigKind::AnyTls {
                server: Endpoint::localhost_v4(443),
                password: "secret".to_string(),
                tls: None,
            },
        }],
        dns: None,
        route_rule_sets: Vec::new(),
        routes: vec![RouteRuleConfig::Default {
            outbound: "anytls".to_string(),
        }],
    };

    let runtime = RuntimeGraphBuilder::new()
        .compose_source(source)
        .expect("compose anytls outbound");

    assert_eq!(runtime.engine().outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn composes_tun_inbound_runtime_graph_on_supported_platforms() {
    let source = SourceConfig {
        inbounds: vec![InboundConfig {
            id: "tun".to_string(),
            kind: InboundConfigKind::Tun(rustbox_config::TunInboundConfig {
                interface_name: Some("rustbox0".to_string()),
                addresses: vec![
                    rustbox_types::IpCidr::new(rustbox_types::IpAddress::V4([172, 18, 0, 1]), 30)
                        .expect("cidr"),
                ],
                mtu: Some(1500),
                route_mode: rustbox_config::RouteMode::Manual,
                dns_mode: rustbox_config::TunDnsMode::None,
                auto_route: false,
                strict_route: false,
                route_includes: Vec::new(),
                route_excludes: Vec::new(),
                dns_hijack: Vec::new(),
                platform_http_proxy: false,
                auto_redirect: false,
            }),
        }],
        outbounds: vec![outbound_direct("direct")],
        dns: None,
        route_rule_sets: Vec::new(),
        routes: vec![RouteRuleConfig::Default {
            outbound: "direct".to_string(),
        }],
    };

    let result = RuntimeGraphBuilder::new().compose_source(source);

    if rustbox_platform::SUPPORTS_TUN {
        let runtime = result.expect("compose tun inbound");
        assert_eq!(runtime.engine().outbound_count(), 1);
        assert_eq!(runtime.service_count(), 1);
    } else {
        let error = match result {
            Ok(_) => panic!("expected unsupported tun platform"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ComposeError::Config(ConfigError { message }) if message.contains("tun inbound")
        ));
    }
}
