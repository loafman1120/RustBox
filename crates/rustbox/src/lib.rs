//! RustBox 的共享应用接口和运行图装配。
//!
//! CLI、FFI 和其他嵌入方式都使用 [`RustBox`]。Tokio 是项目选定的异步运行时，
//! 不属于需要从公共应用接口隐藏或替换的架构层。

use rustbox_config::{
    CompiledConfig, CompiledInboundKind, CompiledOutboundKind, CompiledRouteConditions,
    CompiledRouteMatcher, CompiledRouteRule, ConfigCompiler, ConfigError, LogicalModeConfig,
    SourceConfig,
};
use rustbox_control::{ControlState, EngineCommand, EngineSnapshot, EngineState};
use rustbox_control_api::{ControlApiConfig, ControlApiState};
use rustbox_host_api::{
    NoopObservabilitySink, ObservabilitySink, TokioHost, TransparentProxyProvider,
};
use rustbox_inbound_anytls::{AnyTlsInbound, AnyTlsServerConfig};
use rustbox_inbound_http::{HttpInboundCredentials, HttpProxyInbound};
use rustbox_inbound_socks5::{
    MixedInbound, MixedInboundCredentials, Socks5Inbound, Socks5InboundCredentials,
};
use rustbox_inbound_transparent::{
    TransparentInboundConfig as RuntimeTransparentInboundConfig, TransparentProxyInbound,
};
use rustbox_inbound_tun::{TunInbound, TunInboundConfig as RuntimeTunInboundConfig};
use rustbox_kernel::{Engine, EngineError, FlowSink, Service, ServiceContext, ServiceError};
use rustbox_observability::ObservabilityStore;
use rustbox_outbound_anytls::{AnyTlsOutbound, AnyTlsTlsConfig};
use rustbox_outbound_direct::DirectOutbound;
use rustbox_outbound_http::{HttpProxyCredentials, HttpProxyOutbound};
use rustbox_outbound_shadowsocks::ShadowsocksOutbound;
use rustbox_outbound_socks5::{Socks5Credentials, Socks5Outbound};
use rustbox_outbound_trojan::{TrojanOutbound, TrojanTlsConfig};
use rustbox_outbound_vless::{VlessOutbound, VlessTlsConfig};
use rustbox_outbound_vmess::{VmessOutbound, VmessTlsConfig};
use rustbox_route::{
    LogicalMode, RouteConditions, RouteMatcher, RouteRule, RouteRuleSet, RouteTable,
};
use rustbox_types::{Endpoint, Host, RouteDecision};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// 内部运行图构造器。外部调用方应使用 [`RustBox`]。
struct RuntimeGraphBuilder {
    host: Arc<TokioHost>,
    observability: Arc<dyn ObservabilitySink>,
}

impl RuntimeGraphBuilder {
    fn new() -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    fn with_observability(observability: Arc<dyn ObservabilitySink>) -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability,
        }
    }

    #[cfg(test)]
    fn default_http_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_default_http_proxy(listen)
    }

    #[cfg(test)]
    fn default_socks5_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_default_socks5_proxy(listen)
    }

    #[cfg(test)]
    fn compose_default_http_proxy(self, listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        let source = SourceConfig::default_http_proxy(listen);
        self.compose_source(source)
    }

    #[cfg(test)]
    fn compose_default_socks5_proxy(
        self,
        listen: Endpoint,
    ) -> Result<ComposedRuntime, ComposeError> {
        let source = SourceConfig::default_socks5_proxy(listen);
        self.compose_source(source)
    }

    fn compose_source(self, source: SourceConfig) -> Result<ComposedRuntime, ComposeError> {
        // 组合根接受 SourceConfig，但仍然先走完整配置流水线。
        let parsed = ConfigCompiler::parse(source).map_err(ComposeError::Config)?;
        let normalized = ConfigCompiler::normalize(parsed).map_err(ComposeError::Config)?;
        let validated = ConfigCompiler::validate(normalized).map_err(ComposeError::Config)?;
        let compiled = ConfigCompiler::compile(validated).map_err(ComposeError::Config)?;
        self.compose(compiled)
    }

    fn compose(self, compiled: CompiledConfig) -> Result<ComposedRuntime, ComposeError> {
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
                CompiledOutboundKind::Vmess {
                    server,
                    uuid,
                    security,
                    alter_id,
                    tls,
                    transport,
                } => {
                    if alter_id.is_some_and(|value| value != 0) {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "vmess outbound `{}` supports only alter_id=0 AEAD",
                            outbound.logical_id
                        ))));
                    }
                    if transport.as_deref().is_some_and(|value| value != "tcp") {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "vmess outbound `{}` currently supports only tcp transport",
                            outbound.logical_id
                        ))));
                    }
                    let tls = tls.as_ref();
                    let runtime_outbound = VmessOutbound::new(
                        outbound.id,
                        server.clone(),
                        uuid,
                        security.as_deref(),
                        VmessTlsConfig {
                            enabled: tls.is_some_and(|value| value.enabled),
                            server_name: tls.and_then(|value| value.server_name.clone()),
                            insecure: tls.is_some_and(|value| value.insecure),
                            alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                        },
                        self.host.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Vless {
                    server,
                    uuid,
                    flow,
                    tls,
                    transport,
                } => {
                    if flow.as_deref().is_some_and(|value| !value.is_empty()) {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "vless outbound `{}` currently supports only plain VLESS without Vision flow",
                            outbound.logical_id
                        ))));
                    }
                    if transport.as_deref().is_some_and(|value| value != "tcp") {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "vless outbound `{}` currently supports only tcp transport",
                            outbound.logical_id
                        ))));
                    }
                    let tls = tls.as_ref();
                    let runtime_outbound = VlessOutbound::new(
                        outbound.id,
                        server.clone(),
                        uuid,
                        VlessTlsConfig {
                            enabled: tls.is_some_and(|value| value.enabled),
                            server_name: tls.and_then(|value| value.server_name.clone()),
                            insecure: tls.is_some_and(|value| value.insecure),
                            alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                        },
                        self.host.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::Trojan {
                    server,
                    password,
                    tls,
                    transport,
                } => {
                    if transport.as_deref().is_some_and(|value| value != "tcp") {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "trojan outbound `{}` currently supports only tcp transport",
                            outbound.logical_id
                        ))));
                    }
                    if tls.as_ref().is_some_and(|value| !value.enabled) {
                        return Err(ComposeError::Config(ConfigError::new(format!(
                            "trojan outbound `{}` requires TLS",
                            outbound.logical_id
                        ))));
                    }
                    let tls = tls.as_ref();
                    let runtime_outbound = TrojanOutbound::new(
                        outbound.id,
                        server.clone(),
                        password,
                        TrojanTlsConfig {
                            server_name: tls.and_then(|value| value.server_name.clone()),
                            insecure: tls.is_some_and(|value| value.insecure),
                            alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                        },
                        self.host.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
                CompiledOutboundKind::AnyTls {
                    server,
                    password,
                    tls,
                } => {
                    let tls = tls.as_ref();
                    let runtime_outbound = AnyTlsOutbound::new(
                        outbound.id,
                        server.clone(),
                        password,
                        AnyTlsTlsConfig {
                            server_name: tls.and_then(|value| value.server_name.clone()),
                            insecure: tls.is_some_and(|value| value.insecure),
                            alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                        },
                        self.host.clone(),
                    )
                    .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                    .with_observability(self.observability.clone());
                    builder = builder
                        .register_outbound(Box::new(runtime_outbound))
                        .map_err(ComposeError::Engine)?;
                }
            }
        }

        let engine = Arc::new(builder.build().map_err(ComposeError::Engine)?);
        let sink: Arc<dyn FlowSink> = engine.clone();
        let mut services: Vec<Box<dyn Service>> = Vec::new();
        let platform_proxy_listen =
            compiled
                .inbounds
                .iter()
                .find_map(|inbound| match &inbound.kind {
                    CompiledInboundKind::Mixed { listen, .. }
                    | CompiledInboundKind::HttpConnect { listen, .. } => Some(listen.clone()),
                    _ => None,
                });

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
                CompiledInboundKind::AnyTls {
                    listen,
                    password,
                    tls,
                } => {
                    let certificate_pem =
                        std::fs::read_to_string(&tls.certificate_path).map_err(|error| {
                            ComposeError::Config(ConfigError::new(format!(
                                "read AnyTLS certificate `{}`: {error}",
                                tls.certificate_path
                            )))
                        })?;
                    let private_key_pem =
                        std::fs::read_to_string(&tls.private_key_path).map_err(|error| {
                            ComposeError::Config(ConfigError::new(format!(
                                "read AnyTLS private key `{}`: {error}",
                                tls.private_key_path
                            )))
                        })?;
                    let inbound = AnyTlsInbound::new(
                        inbound.id,
                        listen,
                        AnyTlsServerConfig {
                            password,
                            certificate_pem,
                            private_key_pem,
                            alpn: tls.alpn,
                        },
                        self.host.clone(),
                        self.host.clone(),
                        sink.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
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
                    let dns_servers = config
                        .dns_hijack
                        .iter()
                        .map(|target| match target.endpoint.host {
                            Host::Ip(ip) => Ok(ip),
                            Host::Domain(_) => Err(ComposeError::Config(ConfigError::new(
                                "TUN dns_hijack endpoints must use literal IP addresses",
                            ))),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let platform_proxy = if config.platform_http_proxy {
                        Some(rustbox_host_api::PlatformProxyConfig {
                            listen: platform_proxy_listen.clone().ok_or_else(|| {
                                ComposeError::Config(ConfigError::new(
                                    "TUN platform_http_proxy requires a mixed or http-connect inbound",
                                ))
                            })?,
                            bypass: vec!["<local>".to_string()],
                        })
                    } else {
                        None
                    };
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
                            dns_servers,
                            platform_proxy,
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

impl Default for RuntimeGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared application options used by CLI, FFI, and embedded hosts.
pub struct RustBoxOptions {
    observability: Arc<dyn ObservabilitySink>,
    control_grpc: Option<ControlGrpcOptions>,
}

struct ControlGrpcOptions {
    config: ControlApiConfig,
    observability: Arc<ObservabilityStore>,
}

impl RustBoxOptions {
    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    /// Enable the native control gRPC service as part of the RustBox lifecycle.
    ///
    /// The supplied store should also be included in `observability` so data-plane
    /// events are visible through the control API.
    pub fn with_control_grpc(
        mut self,
        config: ControlApiConfig,
        observability: Arc<ObservabilityStore>,
    ) -> Self {
        self.control_grpc = Some(ControlGrpcOptions {
            config,
            observability,
        });
        self
    }
}

impl Default for RustBoxOptions {
    fn default() -> Self {
        Self {
            observability: Arc::new(NoopObservabilitySink),
            control_grpc: None,
        }
    }
}

/// CLI、FFI 和嵌入式宿主共用的 RustBox 接口。
///
/// 构造函数完成配置校验和运行图装配；`start`、`stop` 和 `reload` 负责生命周期。
/// 调用方不需要了解组合根、服务启动顺序或 Tokio host 的存在。
pub struct RustBox {
    source: SourceConfig,
    observability: Arc<dyn ObservabilitySink>,
    runtime: ComposedRuntime,
    snapshot: EngineSnapshot,
    control_grpc: Option<ControlGrpcService>,
}

/// 共享 RustBox 生命周期接口返回的错误。
pub type RustBoxError = ComposeError;

impl RustBox {
    pub fn new(source: SourceConfig) -> Result<Self, RustBoxError> {
        Self::with_options(source, RustBoxOptions::default())
    }

    pub fn with_observability(
        source: SourceConfig,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Result<Self, RustBoxError> {
        Self::with_options(
            source,
            RustBoxOptions::default().with_observability(observability),
        )
    }

    pub fn with_options(
        source: SourceConfig,
        options: RustBoxOptions,
    ) -> Result<Self, RustBoxError> {
        if let Some(control) = &options.control_grpc {
            control
                .config
                .validate()
                .map_err(|error| ComposeError::Control(error.message))?;
        }
        let observability = options.observability;
        let runtime = RuntimeGraphBuilder::with_observability(observability.clone())
            .compose_source(source.clone())?;
        let snapshot = EngineSnapshot {
            state: EngineState::Prepared,
            generation: 0,
            inbound_count: runtime.service_count(),
            outbound_count: runtime.engine().outbound_count(),
        };
        let control_grpc = options
            .control_grpc
            .map(|options| ControlGrpcService::new(options, snapshot.clone()));
        Ok(Self {
            source,
            observability,
            runtime,
            snapshot,
            control_grpc,
        })
    }

    pub fn default_http_proxy(listen: Endpoint) -> Result<Self, RustBoxError> {
        Self::new(SourceConfig::default_http_proxy(listen))
    }

    pub fn default_http_proxy_with_observability(
        listen: Endpoint,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Result<Self, RustBoxError> {
        Self::with_observability(SourceConfig::default_http_proxy(listen), observability)
    }

    pub fn default_socks5_proxy(listen: Endpoint) -> Result<Self, RustBoxError> {
        Self::new(SourceConfig::default_socks5_proxy(listen))
    }

    pub fn default_socks5_proxy_with_observability(
        listen: Endpoint,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Result<Self, RustBoxError> {
        Self::with_observability(SourceConfig::default_socks5_proxy(listen), observability)
    }

    pub fn snapshot(&self) -> &EngineSnapshot {
        &self.snapshot
    }

    pub fn control_grpc_addr(&self) -> Option<SocketAddr> {
        self.control_grpc.as_ref().map(|service| service.listen())
    }

    /// Wait for the next coarse control command issued through the configured API.
    pub async fn next_control_command(&mut self) -> Option<EngineCommand> {
        match &mut self.control_grpc {
            Some(service) => service.next_command().await,
            None => None,
        }
    }

    pub async fn start(&mut self) -> Result<(), RustBoxError> {
        if self.snapshot.state == EngineState::Running {
            return Err(ComposeError::State(
                "RustBox is already running".to_string(),
            ));
        }
        if matches!(
            self.snapshot.state,
            EngineState::Stopped | EngineState::Failed
        ) {
            self.runtime = RuntimeGraphBuilder::with_observability(self.observability.clone())
                .compose_source(self.source.clone())?;
            self.snapshot.inbound_count = self.runtime.service_count();
            self.snapshot.outbound_count = self.runtime.engine().outbound_count();
            self.snapshot.state = EngineState::Prepared;
        }
        if let Err(error) = self.runtime.start("rustbox").await {
            self.snapshot.state = EngineState::Failed;
            self.sync_control_snapshot();
            return Err(error);
        }
        self.snapshot.state = EngineState::Running;
        self.sync_control_snapshot();
        if let Some(control) = &mut self.control_grpc {
            control.start();
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), RustBoxError> {
        if self.snapshot.state != EngineState::Running {
            return Ok(());
        }
        self.snapshot.state = EngineState::Stopping;
        self.sync_control_snapshot();
        let runtime_result = self.runtime.stop().await;
        self.snapshot.state = if runtime_result.is_ok() {
            EngineState::Stopped
        } else {
            EngineState::Failed
        };
        self.sync_control_snapshot();
        let control_result = match &mut self.control_grpc {
            Some(control) => control.stop().await,
            None => Ok(()),
        };
        runtime_result?;
        control_result?;
        Ok(())
    }

    pub async fn reload(&mut self, source: SourceConfig) -> Result<(), RustBoxError> {
        let next = RuntimeGraphBuilder::with_observability(self.observability.clone())
            .compose_source(source.clone())?;
        let was_running = self.snapshot.state == EngineState::Running;

        if was_running {
            self.stop().await?;
        }

        self.source = source;
        self.runtime = next;
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        self.snapshot.inbound_count = self.runtime.service_count();
        self.snapshot.outbound_count = self.runtime.engine().outbound_count();
        self.snapshot.state = EngineState::Prepared;

        if was_running && let Err(error) = self.start().await {
            self.snapshot.state = EngineState::Failed;
            return Err(error);
        }
        Ok(())
    }

    fn sync_control_snapshot(&self) {
        if let Some(control) = &self.control_grpc {
            control.replace_snapshot(self.snapshot.clone());
        }
    }
}

struct ControlGrpcService {
    config: ControlApiConfig,
    state: Arc<Mutex<ControlState>>,
    observability: Arc<ObservabilityStore>,
    command_tx: mpsc::UnboundedSender<EngineCommand>,
    command_rx: mpsc::UnboundedReceiver<EngineCommand>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), rustbox_control_api::ControlApiError>>>,
}

impl ControlGrpcService {
    fn new(options: ControlGrpcOptions, snapshot: EngineSnapshot) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Self {
            config: options.config,
            state: Arc::new(Mutex::new(ControlState::new(snapshot))),
            observability: options.observability,
            command_tx,
            command_rx,
            shutdown: None,
            task: None,
        }
    }

    fn listen(&self) -> SocketAddr {
        self.config.listen
    }

    fn replace_snapshot(&self, snapshot: EngineSnapshot) {
        if let Ok(mut state) = self.state.lock() {
            state.replace_snapshot(snapshot);
        }
    }

    fn start(&mut self) {
        if self.task.is_some() {
            return;
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let state = ControlApiState::new(self.observability.clone(), self.state.clone())
            .with_command_sender(self.command_tx.clone());
        let config = self.config.clone();
        self.shutdown = Some(shutdown_tx);
        self.task = Some(tokio::spawn(async move {
            rustbox_control_api::serve_grpc(config, state, async {
                let _ = shutdown_rx.await;
            })
            .await
        }));
    }

    async fn stop(&mut self) -> Result<(), ComposeError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(ComposeError::Control(error.to_string())),
            Err(error) => Err(ComposeError::Control(format!(
                "control gRPC task failed: {error}"
            ))),
        }
    }

    async fn next_command(&mut self) -> Option<EngineCommand> {
        self.command_rx.recv().await
    }
}

/// RustBox 内部已经装配好的运行图。
struct ComposedRuntime {
    engine: Arc<Engine>,
    services: Vec<Box<dyn Service>>,
}

impl ComposedRuntime {
    fn engine(&self) -> Arc<Engine> {
        self.engine.clone()
    }

    fn service_count(&self) -> usize {
        self.services.len()
    }

    async fn start(&mut self, engine_name: &str) -> Result<(), ComposeError> {
        // 服务按构造顺序启动，确保入口在其依赖图准备好之后开始接流量。
        for service in &mut self.services {
            service
                .start(ServiceContext { engine_name })
                .await
                .map_err(ComposeError::Service)?;
        }
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ComposeError> {
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
    Control(String),
    Engine(EngineError),
    Service(ServiceError),
    State(String),
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
    rustbox_platform::transparent_proxy_provider().ok_or_else(|| {
        ComposeError::Config(ConfigError::new(
            "transparent inbound requires platform transparent-proxy capabilities",
        ))
    })
}

type TunPlatformCapabilities = (
    Arc<dyn rustbox_host_api::PacketDeviceProvider>,
    Arc<dyn rustbox_host_api::NetworkControl>,
);

fn tun_platform_capabilities() -> Result<TunPlatformCapabilities, ComposeError> {
    rustbox_platform::tun_capabilities().ok_or_else(|| {
        ComposeError::Config(ConfigError::new(
            "tun inbound requires platform packet-device capabilities",
        ))
    })
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

        let result = RuntimeGraphBuilder::new().compose_source(source);

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
