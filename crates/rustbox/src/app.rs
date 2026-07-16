use crate::{
    ComposeError, RuntimeGraphBuilder, control::ControlGrpcService, runtime::RuntimeSupervisor,
};
use rustbox_config::SourceConfig;
use rustbox_control::{EngineCommand, EngineSnapshot, EngineState};
use rustbox_control_api::ControlApiConfig;
use rustbox_dns_core::{DnsQuery, DnsResponse};
use rustbox_kernel::{NoopObservabilitySink, ObservabilitySink};
use rustbox_observability::ObservabilityStore;
use rustbox_types::Endpoint;
use std::{net::SocketAddr, sync::Arc};

/// Shared application options used by CLI, Flutter, and embedded hosts.
pub struct RustBoxOptions {
    observability: Arc<dyn ObservabilitySink>,
    control_grpc: Option<ControlGrpcOptions>,
}

pub(crate) struct ControlGrpcOptions {
    pub(crate) config: ControlApiConfig,
    pub(crate) observability: Arc<ObservabilityStore>,
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

/// CLI、Flutter bridge 和嵌入式宿主共用的 RustBox 接口。
///
/// 构造函数完成配置校验和运行图装配；`start`、`stop` 和 `reload` 负责生命周期。
/// 调用方不需要了解组合根、服务启动顺序或 Tokio host 的存在。
pub struct RustBox {
    source: SourceConfig,
    observability: Arc<dyn ObservabilitySink>,
    runtime: RuntimeSupervisor,
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
            outbound_count: runtime.outbound_count(),
        };
        let control_grpc = options.control_grpc.map(|options| {
            ControlGrpcService::new(options, snapshot.clone(), runtime.outbound_groups())
        });
        Ok(Self {
            source,
            observability,
            runtime: RuntimeSupervisor::new(runtime),
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

    pub fn snapshot(&self) -> &EngineSnapshot {
        &self.snapshot
    }

    /// Resolve through the configured DNS rule/cache/FakeIP/transport graph.
    pub async fn resolve_dns(&self, query: DnsQuery) -> Result<DnsResponse, RustBoxError> {
        self.runtime.resolve_dns(query).await
    }

    pub fn control_grpc_addr(&self) -> Option<SocketAddr> {
        self.control_grpc.as_ref().map(ControlGrpcService::listen)
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
            let runtime = RuntimeGraphBuilder::with_observability(self.observability.clone())
                .compose_source(self.source.clone())?;
            if let Some(control) = &self.control_grpc {
                control.replace_outbound_groups(runtime.outbound_groups());
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
        if let Some(control) = &mut self.control_grpc
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
        self.source = source;
        if let Some(control) = &self.control_grpc {
            control.replace_outbound_groups(self.runtime.outbound_groups());
        }
        self.snapshot.generation = next_generation;
        self.snapshot.inbound_count = self.runtime.service_count();
        self.snapshot.outbound_count = self.runtime.outbound_count();
        self.sync_control_snapshot();
        Ok(())
    }

    fn sync_control_snapshot(&self) {
        if let Some(control) = &self.control_grpc {
            control.replace_snapshot(self.snapshot.clone());
        }
    }
}
