use super::*;
use rustbox_clash_api::ClashApiConfig;
use rustbox_config::{
    ConfigError, DnsCacheConfig, DnsConfig, DnsRuleConfig, DnsRuleMatcher, DnsServerConfig,
    DnsServerProtocol, FakeIpConfig, InboundConfig, InboundConfigKind, OutboundConfig,
    OutboundConfigKind, RouteRuleConfig, SourceConfig,
};
use rustbox_control::EngineState;
use rustbox_control_api::ControlApiConfig;
use rustbox_control_api::daemon::{
    SelectOutboundRequest, started_service_client::StartedServiceClient,
};
use rustbox_observability::ObservabilityStore;
use rustbox_types::{Endpoint, Host, IpAddress, IpCidr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Default)]
struct RecordingNetworkFactory {
    created: Mutex<
        Vec<(
            rustbox_kernel::NetworkProviderPurpose,
            rustbox_kernel::DialOptions,
        )>,
    >,
}

impl rustbox_kernel::NetworkProviderFactory for RecordingNetworkFactory {
    fn create(
        &self,
        purpose: rustbox_kernel::NetworkProviderPurpose,
        options: rustbox_kernel::DialOptions,
        resolver: Option<Arc<dyn rustbox_kernel::DomainResolver>>,
    ) -> Arc<dyn rustbox_kernel::NetworkProvider> {
        self.created
            .lock()
            .expect("factory lock")
            .push((purpose, options.clone()));
        let mut provider = rustbox_kernel::TokioNetworkProvider::with_options(options);
        if let Some(resolver) = resolver {
            provider = provider.with_resolver(resolver);
        }
        Arc::new(provider)
    }
}

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
        dial: Default::default(),
        kind: OutboundConfigKind::Direct,
    }
}

#[test]
fn composes_default_http_proxy_runtime_graph() {
    let runtime =
        RuntimeGraphBuilder::default_http_proxy(Endpoint::localhost_v4(0)).expect("compose");

    assert_eq!(runtime.outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[tokio::test]
async fn injected_network_factory_is_reused_for_outbound_reload_and_restart() {
    let factory = Arc::new(RecordingNetworkFactory::default());
    let mut source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(0));
    source.outbounds[0].dial.routing_mark = Some(42);
    let options = RustBoxOptions::default()
        .with_capabilities(RuntimeCapabilities::default().with_network(factory.clone()));
    let mut runtime = RustBox::with_options(source.clone(), options).expect("compose");

    let created = factory.created.lock().expect("factory lock").clone();
    assert_eq!(
        created.len(),
        2,
        "one inbound host and one physical outbound"
    );
    assert_eq!(
        created[0].0,
        rustbox_kernel::NetworkProviderPurpose::Inbound
    );
    assert_eq!(created[0].1, rustbox_kernel::DialOptions::default());
    assert_eq!(
        created[1].0,
        rustbox_kernel::NetworkProviderPurpose::Outbound
    );
    assert_eq!(created[1].1.routing_mark, Some(42));

    runtime.reload(source).await.expect("reload");
    runtime.start().await.expect("start");
    runtime.stop().await.expect("stop");
    runtime.start().await.expect("restart");
    runtime.stop().await.expect("final stop");

    let created = factory.created.lock().expect("factory lock");
    assert_eq!(
        created.len(),
        6,
        "capabilities must survive reload and restart"
    );
    assert!(created.iter().all(|(purpose, options)| {
        (*purpose == rustbox_kernel::NetworkProviderPurpose::Inbound
            && options == &rustbox_kernel::DialOptions::default())
            || (*purpose == rustbox_kernel::NetworkProviderPurpose::Outbound
                && options.routing_mark == Some(42))
    }));
}

#[tokio::test]
async fn composes_dns_rules_cache_fake_ip_and_resolver_api() {
    let mut source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(0));
    source.dns = Some(DnsConfig {
        servers: vec![DnsServerConfig {
            id: "local".to_string(),
            protocol: DnsServerProtocol::Udp,
            endpoint: Endpoint::localhost_v4(53),
            outbound: Some("direct".to_string()),
        }],
        rules: vec![DnsRuleConfig::FakeIp {
            matcher: DnsRuleMatcher {
                domain_suffixes: vec!["example.test".to_string()],
                ..DnsRuleMatcher::default()
            },
        }],
        final_server: Some("local".to_string()),
        cache: DnsCacheConfig::default(),
        fake_ip: Some(FakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddress::V4([198, 18, 0, 0]), 24).expect("pool"),
            ipv6_pool: None,
            state_file: None,
            ttl_seconds: 60,
        }),
        hijack: Vec::new(),
    });
    let runtime = RustBox::new(source).expect("compose DNS");
    let response = runtime
        .resolve_dns(DnsQuery {
            name: DnsName::new("www.example.test").expect("name"),
            record_type: DnsRecordType::A,
        })
        .await
        .expect("resolve");
    assert!(matches!(
        response.answers[0].host,
        Host::Ip(IpAddress::V4(_))
    ));
}

#[test]
fn composes_dns_socket_through_proxy_outbound() {
    let mut source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(0));
    source.outbounds.push(OutboundConfig {
        id: "dns-proxy".into(),
        dial: Default::default(),
        kind: OutboundConfigKind::Socks5 {
            server: Endpoint::localhost_v4(1080),
            username: None,
            password: None,
        },
    });
    source.dns = Some(DnsConfig {
        servers: vec![DnsServerConfig {
            id: "proxied".into(),
            protocol: DnsServerProtocol::Tcp,
            endpoint: Endpoint::new(Host::domain("dns.example"), 53),
            outbound: Some("dns-proxy".into()),
        }],
        rules: Vec::new(),
        final_server: Some("proxied".into()),
        cache: DnsCacheConfig::default(),
        fake_ip: None,
        hijack: Vec::new(),
    });
    RustBox::new(source).expect("late-bind proxied DNS socket");
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
    assert_ne!(
        runtime.control_grpc_addr().expect("control address").port(),
        0,
        "Tokio listener should expose the OS-assigned port"
    );
    runtime.stop().await.expect("stop runtime and control gRPC");
    assert_eq!(runtime.snapshot().state, EngineState::Stopped);
}

#[tokio::test]
async fn owns_clash_api_lifecycle_and_serves_version() {
    let config = ClashApiConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..ClashApiConfig::default()
    };
    let expected_listen = config.listen;
    let options =
        RustBoxOptions::default().with_clash_api(config, Arc::new(ObservabilityStore::default()));
    let mut runtime = RustBox::with_options(
        SourceConfig::default_http_proxy(Endpoint::localhost_v4(0)),
        options,
    )
    .expect("compose with Clash API");

    assert_eq!(runtime.clash_api_addr(), Some(expected_listen));
    runtime.start().await.expect("start runtime and Clash API");
    let address = runtime.clash_api_addr().expect("Clash API address");
    assert_ne!(address.port(), 0);
    let response = reqwest::get(format!("http://{address}/version"))
        .await
        .expect("request Clash version")
        .text()
        .await
        .expect("read Clash version");
    assert!(response.contains("\"meta\":true"));
    assert!(response.contains("\"version\":\"RustBox "));

    runtime.stop().await.expect("stop runtime and Clash API");
    assert_eq!(runtime.snapshot().state, EngineState::Stopped);
}

#[tokio::test]
async fn rolls_back_runtime_when_control_grpc_cannot_bind() {
    let occupied = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("reserve address");
    let listen = occupied.local_addr().expect("reserved address");
    let options = RustBoxOptions::default().with_control_grpc(
        ControlApiConfig {
            listen,
            ..ControlApiConfig::default()
        },
        Arc::new(ObservabilityStore::default()),
    );
    let mut runtime = RustBox::with_options(
        SourceConfig::default_http_proxy(Endpoint::localhost_v4(0)),
        options,
    )
    .expect("compose with control gRPC");

    let error = runtime.start().await.expect_err("occupied port must fail");

    assert!(matches!(
        error,
        ComposeError::Control(message) if message.contains("failed to bind")
    ));
    assert_eq!(runtime.snapshot().state, EngineState::Failed);
}

#[tokio::test]
async fn control_grpc_lists_and_switches_selector_outbound() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![
            outbound_direct("direct-a"),
            outbound_direct("direct-b"),
            OutboundConfig {
                id: "select".to_string(),
                dial: Default::default(),
                kind: OutboundConfigKind::Selector {
                    outbounds: vec!["direct-a".to_string(), "direct-b".to_string()],
                    default: Some("direct-a".to_string()),
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
    let options = RustBoxOptions::default().with_control_grpc(
        ControlApiConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..ControlApiConfig::default()
        },
        Arc::new(ObservabilityStore::default()),
    );
    let mut runtime = RustBox::with_options(source, options).expect("compose selector runtime");
    runtime.start().await.expect("start selector runtime");
    let address = runtime.control_grpc_addr().expect("control address");
    let mut client = StartedServiceClient::connect(format!("http://{address}"))
        .await
        .expect("connect control client");

    let mut groups = client
        .subscribe_groups(())
        .await
        .expect("subscribe outbound groups")
        .into_inner();
    let initial = groups
        .message()
        .await
        .expect("read initial outbound groups")
        .expect("initial outbound groups");
    assert_eq!(initial.group.len(), 1);
    assert_eq!(initial.group[0].selected, "direct-a");

    client
        .select_outbound(SelectOutboundRequest {
            group_tag: "select".to_string(),
            outbound_tag: "direct-b".to_string(),
        })
        .await
        .expect("switch selector");
    let updated = groups
        .message()
        .await
        .expect("read updated outbound groups")
        .expect("updated outbound groups");
    assert_eq!(updated.group[0].selected, "direct-b");
    drop(groups);
    drop(client);

    runtime.stop().await.expect("stop selector runtime");
}

#[tokio::test]
async fn failed_reload_keeps_the_committed_source_and_generation() {
    let previous = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("reserve previous address");
    let previous_port = previous.local_addr().expect("previous address").port();
    drop(previous);

    let mut runtime = RustBox::default_http_proxy(Endpoint::localhost_v4(previous_port))
        .expect("compose previous generation");
    runtime.start().await.expect("start previous generation");

    let occupied = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("reserve failed reload address");
    let occupied_port = occupied.local_addr().expect("occupied address").port();
    runtime
        .reload(SourceConfig::default_http_proxy(Endpoint::localhost_v4(
            occupied_port,
        )))
        .await
        .expect_err("occupied reload address must fail");

    assert_eq!(runtime.snapshot().state, EngineState::Failed);
    assert_eq!(runtime.snapshot().generation, 0);
    drop(occupied);

    runtime
        .start()
        .await
        .expect("restart the last committed source");
    assert_eq!(runtime.snapshot().generation, 0);
    runtime.stop().await.expect("stop recovered runtime");
}

#[test]
fn composes_first_batch_proxy_outbounds() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![
            outbound_direct("direct"),
            OutboundConfig {
                id: "block".to_string(),
                dial: Default::default(),
                kind: OutboundConfigKind::Block,
            },
            OutboundConfig {
                id: "socks".to_string(),
                dial: Default::default(),
                kind: OutboundConfigKind::Socks5 {
                    server: Endpoint::localhost_v4(1080),
                    username: None,
                    password: None,
                },
            },
            OutboundConfig {
                id: "http-out".to_string(),
                dial: Default::default(),
                kind: OutboundConfigKind::Http {
                    server: Endpoint::localhost_v4(8080),
                    username: None,
                    password: None,
                },
            },
            OutboundConfig {
                id: "ss".to_string(),
                dial: Default::default(),
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

    assert_eq!(runtime.outbound_count(), 4);
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

    assert_eq!(runtime.outbound_count(), 1);
    assert_eq!(runtime.service_count(), 1);
}

#[test]
fn composes_selector_runtime_route() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![
            outbound_direct("direct"),
            OutboundConfig {
                id: "select".to_string(),
                dial: Default::default(),
                kind: OutboundConfigKind::Selector {
                    outbounds: vec!["direct".to_string()],
                    default: Some("direct".to_string()),
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

    let runtime = RuntimeGraphBuilder::new()
        .compose_source(source)
        .expect("compose selector");

    assert_eq!(runtime.outbound_count(), 1);
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
                transport: Some(rustbox_config::V2RayTransportConfig::Tcp),
            },
        ),
        (
            "vless",
            OutboundConfigKind::Vless {
                server: Endpoint::localhost_v4(443),
                uuid: "00000000-0000-0000-0000-000000000002".to_string(),
                flow: None,
                tls: None,
                transport: Some(rustbox_config::V2RayTransportConfig::Tcp),
            },
        ),
        (
            "trojan",
            OutboundConfigKind::Trojan {
                server: Endpoint::localhost_v4(443),
                password: "secret".to_string(),
                tls: None,
                transport: Some(rustbox_config::V2RayTransportConfig::Tcp),
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
                dial: Default::default(),
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
        assert_eq!(runtime.outbound_count(), 1, "{protocol}");
        assert_eq!(runtime.service_count(), 1, "{protocol}");
    }
}

#[test]
fn composes_anytls_outbound_runtime_graph() {
    let source = SourceConfig {
        inbounds: vec![inbound_http("http")],
        outbounds: vec![OutboundConfig {
            id: "anytls".to_string(),
            dial: Default::default(),
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

    assert_eq!(runtime.outbound_count(), 1);
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
        assert_eq!(runtime.outbound_count(), 1);
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
