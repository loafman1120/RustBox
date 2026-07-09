//! 具体组合根。
//!
//! 本 crate 位于 L4 Composition，把 `CompiledConfig` 变成真实运行图。
//! 只有组合根知道 TokioHost、inbound、outbound、内核和观测 sink 的装配关系。

use rustbox_config::{
    CompiledConfig, CompiledInboundKind, CompiledOutboundKind, CompiledRouteConditions,
    CompiledRouteMatcher, CompiledRouteRule, ConfigCompiler, ConfigError, LogicalModeConfig,
    SourceConfig,
};
use rustbox_host_api::{NoopObservabilitySink, ObservabilitySink, TransparentProxyProvider};
use rustbox_inbound_http::{HttpInboundCredentials, HttpProxyInbound};
use rustbox_inbound_socks5::{
    MixedInbound, MixedInboundCredentials, Socks5Inbound, Socks5InboundCredentials,
};
use rustbox_inbound_transparent::{
    TransparentInboundConfig as RuntimeTransparentInboundConfig, TransparentProxyInbound,
};
use rustbox_inbound_tun::{TunInbound, TunInboundConfig as RuntimeTunInboundConfig};
use rustbox_kernel::{Engine, EngineError, FlowSink, Service, ServiceContext, ServiceError};
use rustbox_outbound_direct::DirectOutbound;
use rustbox_outbound_http::{HttpProxyCredentials, HttpProxyOutbound};
use rustbox_outbound_shadowsocks::ShadowsocksOutbound;
use rustbox_outbound_socks5::{Socks5Credentials, Socks5Outbound};
use rustbox_route::{
    LogicalMode, RouteConditions, RouteMatcher, RouteRule, RouteRuleSet, RouteTable,
};
use rustbox_runtime_tokio::TokioHost;
use rustbox_types::{Endpoint, RouteDecision};
use std::sync::Arc;

/// 当前默认的 Tokio 组合根，负责把配置计划实例化为可运行代理图。
pub struct TokioComposition {
    host: Arc<TokioHost>,
    observability: Arc<dyn ObservabilitySink>,
}

impl TokioComposition {
    pub fn new() -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub fn with_observability(observability: Arc<dyn ObservabilitySink>) -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability,
        }
    }

    pub fn default_http_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_default_http_proxy(listen)
    }

    pub fn default_http_proxy_with_observability(
        listen: Endpoint,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Result<ComposedRuntime, ComposeError> {
        Self::with_observability(observability).compose_default_http_proxy(listen)
    }

    pub fn default_socks5_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_default_socks5_proxy(listen)
    }

    pub fn default_socks5_proxy_with_observability(
        listen: Endpoint,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Result<ComposedRuntime, ComposeError> {
        Self::with_observability(observability).compose_default_socks5_proxy(listen)
    }

    pub fn compose_default_http_proxy(
        self,
        listen: Endpoint,
    ) -> Result<ComposedRuntime, ComposeError> {
        let source = SourceConfig::default_http_proxy(listen);
        self.compose_source(source)
    }

    pub fn compose_default_socks5_proxy(
        self,
        listen: Endpoint,
    ) -> Result<ComposedRuntime, ComposeError> {
        let source = SourceConfig::default_socks5_proxy(listen);
        self.compose_source(source)
    }

    pub fn compose_source(self, source: SourceConfig) -> Result<ComposedRuntime, ComposeError> {
        // 组合根接受 SourceConfig，但仍然先走完整配置流水线。
        let parsed = ConfigCompiler::parse(source).map_err(ComposeError::Config)?;
        let normalized = ConfigCompiler::normalize(parsed).map_err(ComposeError::Config)?;
        let validated = ConfigCompiler::validate(normalized).map_err(ComposeError::Config)?;
        let compiled = ConfigCompiler::compile(validated).map_err(ComposeError::Config)?;
        self.compose(compiled)
    }

    pub fn compose(self, compiled: CompiledConfig) -> Result<ComposedRuntime, ComposeError> {
        // 关键装配点：路由表、内核、出站、inbound 服务都在这里显式连线。
        let router = route_table(&compiled);
        let mut builder =
            Engine::builder(Box::new(router)).observability(self.observability.clone());

        for outbound in &compiled.outbounds {
            match &outbound.kind {
                CompiledOutboundKind::Direct => {
                    builder = builder
                        .register_outbound(Box::new(
                            DirectOutbound::new(outbound.id, self.host.clone())
                                .with_observability(self.observability.clone()),
                        ))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Socks5 {
                    server,
                    username,
                    password,
                } => {
                    let mut runtime_outbound =
                        Socks5Outbound::new(outbound.id, server.clone(), self.host.clone())
                            .with_observability(self.observability.clone());
                    if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                        runtime_outbound = runtime_outbound
                            .with_credentials(Socks5Credentials { username, password });
                    }
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Block => {
                    // `block` outbound 在配置编译阶段会被路由规则转成 Reject 决策，
                    // 组合根不需要为它注册会发起 I/O 的数据面组件。
                }
                CompiledOutboundKind::Http {
                    server,
                    username,
                    password,
                } => {
                    let mut runtime_outbound =
                        HttpProxyOutbound::new(outbound.id, server.clone(), self.host.clone())
                            .with_observability(self.observability.clone());
                    if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                        runtime_outbound = runtime_outbound
                            .with_credentials(HttpProxyCredentials { username, password });
                    }
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Shadowsocks {
                    server,
                    method,
                    password,
                } => {
                    let outbound = ShadowsocksOutbound::new(
                        outbound.id,
                        server.clone(),
                        method,
                        password,
                        self.host.clone(),
                    )
                    .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                    .with_observability(self.observability.clone());
                    builder = builder
                        .register_outbound(Box::new(outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Selector { .. } | CompiledOutboundKind::UrlTest { .. } => {
                    // Group outbounds are compiled to their current child route decision.
                }
                CompiledOutboundKind::Vmess { .. } => {
                    return Err(ComposeError::Config(ConfigError::new(format!(
                        "vmess outbound `{}` is parsed but its data plane is not implemented yet",
                        outbound.logical_id
                    ))));
                }
                CompiledOutboundKind::Vless { .. } => {
                    return Err(ComposeError::Config(ConfigError::new(format!(
                        "vless outbound `{}` is parsed but its data plane is not implemented yet",
                        outbound.logical_id
                    ))));
                }
                CompiledOutboundKind::Trojan { .. } => {
                    return Err(ComposeError::Config(ConfigError::new(format!(
                        "trojan outbound `{}` is parsed but its data plane is not implemented yet",
                        outbound.logical_id
                    ))));
                }
                CompiledOutboundKind::AnyTls { .. } => {
                    return Err(ComposeError::Config(ConfigError::new(format!(
                        "anytls outbound `{}` is parsed but its data plane is not implemented yet",
                        outbound.logical_id
                    ))));
                }
            }
        }

        let engine = Arc::new(builder.build().map_err(ComposeError::Engine)?);
        let sink: Arc<dyn FlowSink> = engine.clone();
        let mut services: Vec<Box<dyn Service>> = Vec::new();

        for inbound in compiled.inbounds {
            match inbound.kind {
                CompiledInboundKind::Mixed {
                    listen,
                    username,
                    password,
                } => {
                    let mut inbound = MixedInbound::new(
                        inbound.id,
                        listen,
                        self.host.clone(),
                        self.host.clone(),
                        sink.clone(),
                    )
                    .with_observability(self.observability.clone());
                    if let (Some(username), Some(password)) = (username, password) {
                        inbound = inbound
                            .with_credentials(MixedInboundCredentials { username, password });
                    }
                    services.push(Box::new(inbound));
                }
                CompiledInboundKind::HttpConnect {
                    listen,
                    username,
                    password,
                } => {
                    let mut inbound = HttpProxyInbound::new(
                        inbound.id,
                        listen,
                        self.host.clone(),
                        self.host.clone(),
                        sink.clone(),
                    )
                    .with_observability(self.observability.clone());
                    if let (Some(username), Some(password)) = (username, password) {
                        inbound =
                            inbound.with_credentials(HttpInboundCredentials { username, password });
                    }
                    services.push(Box::new(inbound));
                }
                CompiledInboundKind::Socks5 {
                    listen,
                    username,
                    password,
                } => {
                    let mut inbound = Socks5Inbound::new(
                        inbound.id,
                        listen,
                        self.host.clone(),
                        self.host.clone(),
                        sink.clone(),
                    )
                    .with_observability(self.observability.clone());
                    if let (Some(username), Some(password)) = (username, password) {
                        inbound = inbound
                            .with_credentials(Socks5InboundCredentials { username, password });
                    }
                    services.push(Box::new(inbound));
                }
                CompiledInboundKind::Transparent(config) => {
                    let provider = transparent_proxy_provider()?;
                    let inbound = TransparentProxyInbound::new(
                        inbound.id,
                        config.listen,
                        provider,
                        self.host.clone(),
                        sink.clone(),
                        RuntimeTransparentInboundConfig {
                            mode: config.mode,
                            mark: config.mark,
                        },
                    )
                    .with_observability(self.observability.clone());
                    services.push(Box::new(inbound));
                }
                CompiledInboundKind::Tun(config) => {
                    let (packet_devices, network_control) = tun_platform_capabilities()?;
                    let mtu = config.mtu.unwrap_or(1500) as usize;
                    let stack = rustbox_stack::PacketFlowStack::new(inbound.id)
                        .with_mtu(mtu)
                        .with_observability(self.observability.clone());
                    let inbound = TunInbound::new(
                        inbound.id,
                        packet_devices,
                        network_control,
                        self.host.clone(),
                        Box::new(stack),
                        sink.clone(),
                        RuntimeTunInboundConfig {
                            interface_name: config.interface_name,
                            addresses: config.addresses,
                            mtu: config.mtu,
                            route_mode: config.route_mode,
                            dns_mode: config.dns_mode,
                            auto_route: config.auto_route,
                            strict_route: config.strict_route,
                            route_includes: config.route_includes,
                            route_excludes: config.route_excludes,
                            platform_http_proxy: config.platform_http_proxy,
                            auto_redirect: config.auto_redirect,
                        },
                    )
                    .with_observability(self.observability.clone());
                    services.push(Box::new(inbound));
                }
            }
        }

        Ok(ComposedRuntime { engine, services })
    }
}

impl Default for TokioComposition {
    fn default() -> Self {
        Self::new()
    }
}

/// 已装配但由调用方控制生命周期的运行图。
pub struct ComposedRuntime {
    engine: Arc<Engine>,
    services: Vec<Box<dyn Service>>,
}

impl ComposedRuntime {
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.clone()
    }

    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    pub async fn start(&mut self, engine_name: &str) -> Result<(), ComposeError> {
        // 服务按构造顺序启动，确保入口在其依赖图准备好之后开始接流量。
        for service in &mut self.services {
            service
                .start(ServiceContext { engine_name })
                .await
                .map_err(ComposeError::Service)?;
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ComposeError> {
        // 停止时反向释放服务，为后续更复杂的依赖关系预留顺序语义。
        for service in self.services.iter_mut().rev() {
            service.stop().await.map_err(ComposeError::Service)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposeError {
    Config(ConfigError),
    Engine(EngineError),
    Service(ServiceError),
}

fn route_table(compiled: &CompiledConfig) -> RouteTable {
    let mut table = RouteTable::new();
    for rule in &compiled.route_rules {
        match rule {
            CompiledRouteRule::Default(decision) => {
                table = table.with_default(decision.clone());
            }
            CompiledRouteRule::Rule { matcher, decision } => {
                table.push_rule(RouteRule::new(route_matcher(matcher), decision.clone()));
            }
        }
    }

    for rule_set in &compiled.route_rule_sets {
        table.insert_rule_set(
            rule_set.id.clone(),
            RouteRuleSet::new(rule_set.rules.iter().map(route_matcher).collect()),
        );
    }

    if compiled.route_rules.is_empty() {
        table.with_default(RouteDecision::Reject(rustbox_types::RejectReason::NoRoute))
    } else {
        table
    }
}

fn route_matcher(matcher: &CompiledRouteMatcher) -> RouteMatcher {
    match matcher {
        CompiledRouteMatcher::Conditions(conditions) => {
            RouteMatcher::Conditions(Box::new(route_conditions(conditions)))
        }
        CompiledRouteMatcher::Logical {
            mode,
            rules,
            invert,
        } => RouteMatcher::Logical {
            mode: logical_mode(mode),
            rules: rules.iter().map(route_matcher).collect(),
            invert: *invert,
        },
    }
}

fn route_conditions(conditions: &CompiledRouteConditions) -> RouteConditions {
    RouteConditions {
        inbounds: conditions.inbounds.clone(),
        networks: conditions.networks.clone(),
        domains: conditions.domains.clone(),
        domain_suffixes: conditions.domain_suffixes.clone(),
        domain_keywords: conditions.domain_keywords.clone(),
        domain_regexes: conditions.domain_regexes.clone(),
        ip_cidrs: conditions.ip_cidrs.clone(),
        source_ip_cidrs: conditions.source_ip_cidrs.clone(),
        ports: conditions.ports.clone(),
        source_ports: conditions.source_ports.clone(),
        rule_sets: conditions.rule_sets.clone(),
        invert: conditions.invert,
    }
}

fn logical_mode(mode: &LogicalModeConfig) -> LogicalMode {
    match mode {
        LogicalModeConfig::And => LogicalMode::And,
        LogicalModeConfig::Or => LogicalMode::Or,
    }
}

fn transparent_proxy_provider() -> Result<Arc<dyn TransparentProxyProvider>, ComposeError> {
    Ok(Arc::new(rustbox_platform_linux::LinuxPlatform::new()))
}

type TunPlatformCapabilities = (
    Arc<dyn rustbox_host_api::PacketDeviceProvider>,
    Arc<dyn rustbox_host_api::NetworkControl>,
);

fn tun_platform_capabilities() -> Result<TunPlatformCapabilities, ComposeError> {
    #[cfg(target_os = "linux")]
    {
        let platform = Arc::new(rustbox_platform_linux::LinuxPlatform::new());
        Ok((platform.clone(), platform))
    }

    #[cfg(target_os = "windows")]
    {
        let platform = Arc::new(rustbox_platform_windows::WindowsPlatform::new());
        Ok((platform.clone(), platform))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(ComposeError::Config(ConfigError::new(
            "tun inbound requires Linux or Windows packet-device platform capabilities",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_config::{
        InboundConfig, InboundConfigKind, OutboundConfig, OutboundConfigKind, RouteRuleConfig,
    };
    use rustbox_types::Endpoint;

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
            TokioComposition::default_http_proxy(Endpoint::localhost_v4(0)).expect("compose");

        assert_eq!(runtime.engine().outbound_count(), 1);
        assert_eq!(runtime.service_count(), 1);
    }

    #[test]
    fn composes_default_socks5_proxy_runtime_graph() {
        let runtime =
            TokioComposition::default_socks5_proxy(Endpoint::localhost_v4(0)).expect("compose");

        assert_eq!(runtime.engine().outbound_count(), 1);
        assert_eq!(runtime.service_count(), 1);
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

        let runtime = TokioComposition::new()
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

        let runtime = TokioComposition::new()
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

        let runtime = TokioComposition::new()
            .compose_source(source)
            .expect("compose selector");

        assert_eq!(runtime.engine().outbound_count(), 1);
        assert_eq!(runtime.service_count(), 1);
    }

    #[test]
    fn rejects_unimplemented_anytls_data_plane_at_composition() {
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

        let error = match TokioComposition::new().compose_source(source) {
            Ok(_) => panic!("expected unimplemented data plane to be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ComposeError::Config(ConfigError { message }) if message.contains("anytls outbound `anytls`")
        ));
    }

    #[test]
    fn composes_tun_inbound_runtime_graph_on_supported_platforms() {
        let source = SourceConfig {
            inbounds: vec![InboundConfig {
                id: "tun".to_string(),
                kind: InboundConfigKind::Tun(rustbox_config::TunInboundConfig {
                    interface_name: Some("rustbox0".to_string()),
                    addresses: vec![
                        rustbox_types::IpCidr::new(
                            rustbox_types::IpAddress::V4([172, 18, 0, 1]),
                            30,
                        )
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

        let result = TokioComposition::new().compose_source(source);

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let runtime = result.expect("compose tun inbound");
            assert_eq!(runtime.engine().outbound_count(), 1);
            assert_eq!(runtime.service_count(), 1);
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
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
}
