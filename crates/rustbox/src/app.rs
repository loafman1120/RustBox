use crate::{
    ComposeError, RuntimeCapabilities, RuntimeGraphBuilder,
    control::{ControlPlaneResources, ControlServices},
    runtime::RuntimeSupervisor,
};
use rustbox_clash_api::ClashApiConfig;
use rustbox_config::SourceConfig;
use rustbox_control::{EngineCommand, EngineSnapshot, EngineState};
use rustbox_control_api::ControlApiConfig;
use rustbox_control_service::{ControlCatalog, ControlCommand};
use rustbox_dns_core::{DnsQuery, DnsResponse};
use rustbox_kernel::{NoopObservabilitySink, ObservabilitySink};
use rustbox_observability::ObservabilityStore;
use rustbox_types::Endpoint;
use std::{net::SocketAddr, sync::Arc};

/// Shared application options used by CLI, Flutter, and embedded hosts.
pub struct RustBoxOptions {
    observability: Arc<dyn ObservabilitySink>,
    capabilities: RuntimeCapabilities,
    control_grpc: Option<ControlGrpcOptions>,
    clash_api: Option<ClashApiOptions>,
}

pub(crate) struct ControlGrpcOptions {
    pub(crate) config: ControlApiConfig,
    pub(crate) observability: Arc<ObservabilityStore>,
}

pub(crate) struct ClashApiOptions {
    pub(crate) config: ClashApiConfig,
    pub(crate) observability: Arc<ObservabilityStore>,
}

impl RustBoxOptions {
    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    /// Replace the platform capabilities used by the runtime composition root.
    pub fn with_capabilities(mut self, capabilities: RuntimeCapabilities) -> Self {
        self.capabilities = capabilities;
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

    /// Enable the Clash/Mihomo-compatible HTTP and WebSocket control service.
    pub fn with_clash_api(
        mut self,
        config: ClashApiConfig,
        observability: Arc<ObservabilityStore>,
    ) -> Self {
        self.clash_api = Some(ClashApiOptions {
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
            capabilities: RuntimeCapabilities::default(),
            control_grpc: None,
            clash_api: None,
        }
    }
}

/// CLI、Flutter bridge 和嵌入式宿主共用的 RustBox 接口。
///
/// 构造函数完成配置校验和运行图装配；`start`、`stop` 和 `reload` 负责生命周期。
/// 调用方不需要了解组合根、服务启动顺序或 Tokio host 的存在。
pub struct RustBox {
    source: SourceConfig,
    observability: Arc<dyn ObservabilitySink>,
    capabilities: RuntimeCapabilities,
    runtime: RuntimeSupervisor,
    snapshot: EngineSnapshot,
    control: Option<ControlServices>,
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
        if let Some(control) = &options.clash_api {
            control
                .config
                .validate()
                .map_err(|error| ComposeError::Control(error.message))?;
        }
        let observability = options.observability;
        let capabilities = options.capabilities;
        let runtime =
            RuntimeGraphBuilder::with_capabilities(capabilities.clone(), observability.clone())
                .compose_source(source.clone())?;
        let snapshot = EngineSnapshot {
            state: EngineState::Prepared,
            generation: 0,
            inbound_count: runtime.service_count(),
            outbound_count: runtime.outbound_count(),
        };
        let grpc_config = options
            .control_grpc
            .as_ref()
            .map(|value| value.config.clone());
        let clash_config = options.clash_api.as_ref().map(|value| value.config.clone());
        let control_observability = options
            .control_grpc
            .as_ref()
            .map(|value| value.observability.clone())
            .or_else(|| {
                options
                    .clash_api
                    .as_ref()
                    .map(|value| value.observability.clone())
            });
        let control = control_observability.map(|observability| {
            ControlServices::new(
                grpc_config,
                clash_config,
                ControlPlaneResources {
                    observability,
                    snapshot: snapshot.clone(),
                    outbound_groups: runtime.outbound_groups(),
                    rule_sets: runtime.rule_sets(),
                    catalog: Arc::new(ControlCatalog::from_source(&source)),
                    outbound_probe: runtime.outbound_probe(),
                },
            )
        });
        Ok(Self {
            source,
            observability,
            capabilities,
            runtime: RuntimeSupervisor::new(runtime),
            snapshot,
            control,
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

    pub fn snapshot(&self) -> &EngineSnapshot {
        &self.snapshot
    }

    /// Resolve through the configured DNS rule/cache/FakeIP/transport graph.
    pub async fn resolve_dns(&self, query: DnsQuery) -> Result<DnsResponse, RustBoxError> {
        self.runtime.resolve_dns(query).await
    }

    pub fn control_grpc_addr(&self) -> Option<SocketAddr> {
        self.control.as_ref().and_then(ControlServices::grpc_listen)
    }

    pub fn clash_api_addr(&self) -> Option<SocketAddr> {
        self.control
            .as_ref()
            .and_then(ControlServices::clash_listen)
    }

    /// Wait for the next coarse control command issued through the configured API.
    pub async fn next_control_command(&mut self) -> Option<ControlCommand> {
        match &mut self.control {
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
            let runtime = RuntimeGraphBuilder::with_capabilities(
                self.capabilities.clone(),
                self.observability.clone(),
            )
            .compose_source(self.source.clone())?;
            if let Some(control) = &self.control {
                control.replace_outbound_groups(runtime.outbound_groups());
                control.replace_rule_sets(runtime.rule_sets());
                control.replace_outbound_probe(runtime.outbound_probe());
            }
            self.runtime = RuntimeSupervisor::new(runtime);
            self.snapshot.inbound_count = self.runtime.service_count();
            self.snapshot.outbound_count = self.runtime.outbound_count();
            self.snapshot.state = EngineState::Prepared;
        }
        if let Err(error) = self.runtime.start(self.snapshot.generation).await {
            self.snapshot.state = EngineState::Failed;
            self.sync_control_snapshot();
            return Err(error);
        }
        self.snapshot.state = EngineState::Running;
        self.sync_control_snapshot();
        if let Some(control) = &mut self.control
            && let Err(error) = control.start().await
        {
            let _ = self.runtime.stop().await;
            self.snapshot.state = EngineState::Failed;
            self.sync_control_snapshot();
            return Err(error);
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
        let control_result = match &mut self.control {
            Some(control) => control.stop().await,
            None => Ok(()),
        };
        runtime_result?;
        control_result?;
        Ok(())
    }

    pub async fn reload(&mut self, source: SourceConfig) -> Result<(), RustBoxError> {
        let next = RuntimeGraphBuilder::with_capabilities(
            self.capabilities.clone(),
            self.observability.clone(),
        )
        .compose_source(source.clone())?;
        let was_running = self.snapshot.state == EngineState::Running;
        let next_generation = self.snapshot.generation.saturating_add(1);

        if was_running {
            if let Err(error) = self.runtime.reload(next, next_generation).await {
                self.snapshot.state = EngineState::Failed;
                self.sync_control_snapshot();
                return Err(error);
            }
            self.snapshot.state = EngineState::Running;
        } else {
            self.runtime.replace(next, next_generation);
            self.snapshot.state = EngineState::Prepared;
        }
        let catalog = Arc::new(ControlCatalog::from_source(&source));
        self.source = source;
        if let Some(control) = &self.control {
            control.replace_outbound_groups(self.runtime.outbound_groups());
            control.replace_rule_sets(self.runtime.rule_sets());
            control.replace_catalog(catalog);
            control.replace_outbound_probe(self.runtime.outbound_probe());
        }
        self.snapshot.generation = next_generation;
        self.snapshot.inbound_count = self.runtime.service_count();
        self.snapshot.outbound_count = self.runtime.outbound_count();
        self.sync_control_snapshot();
        Ok(())
    }

    /// Rebuild after a native interface notification. The old TUN is stopped
    /// first so default-interface detection cannot accidentally select the
    /// TUN's own /1 routes as the new physical path.
    pub async fn reconcile_network_change(&mut self) -> Result<(), RustBoxError> {
        if self.snapshot.state != EngineState::Running {
            return Ok(());
        }
        self.stop().await?;
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        self.start().await
    }

    /// Cancel a single active flow through the kernel's Tokio cancellation token.
    pub fn close_connection(&self, flow_id: u64) -> bool {
        self.runtime.close_connection(flow_id)
    }

    pub fn close_all_connections(&self) -> usize {
        self.runtime.close_all_connections()
    }

    /// Execute a command received from any control transport.
    pub async fn apply_control_command(
        &mut self,
        command: EngineCommand,
    ) -> Result<bool, RustBoxError> {
        match command {
            EngineCommand::Reload(source) => {
                self.reload(*source).await?;
                Ok(true)
            }
            EngineCommand::CloseConnection(flow_id) => Ok(self.close_connection(flow_id)),
            EngineCommand::CloseAllConnections => {
                self.close_all_connections();
                Ok(true)
            }
            EngineCommand::RefreshRuleSet(tag) => Ok(self.runtime.refresh_rule_set(&tag)),
            EngineCommand::TriggerUrlTest(tag) => Ok(self.runtime.trigger_urltest(&tag)),
            EngineCommand::Stop => {
                self.stop().await?;
                Ok(true)
            }
            EngineCommand::ReplaceRouteTable(_)
            | EngineCommand::EnableOutbound(_)
            | EngineCommand::DisableOutbound(_) => Ok(false),
        }
    }

    pub async fn apply_control_request(
        &mut self,
        request: ControlCommand,
    ) -> Result<bool, RustBoxError> {
        let result = self.apply_control_command(request.command.clone()).await;
        match &result {
            Ok(accepted) => request.respond(Ok(*accepted)),
            Err(error) => request.respond(Err(format!("{error:?}"))),
        }
        result
    }

    fn sync_control_snapshot(&self) {
        if let Some(control) = &self.control {
            control.replace_snapshot(self.snapshot.clone());
        }
    }
}
