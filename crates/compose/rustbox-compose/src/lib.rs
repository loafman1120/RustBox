//! 具体组合根。
//!
//! 本 crate 位于 L4 Composition，把 `CompiledConfig` 变成真实运行图。
//! 只有组合根知道 TokioHost、inbound、outbound、内核和观测 sink 的装配关系。

use rustbox_config::{
    CompiledConfig, CompiledInbound, CompiledOutbound, CompiledRouteRule, ConfigCompiler,
    ConfigError, SourceConfig,
};
use rustbox_host_api::{NoopObservabilitySink, ObservabilitySink};
use rustbox_inbound_http::HttpProxyInbound;
use rustbox_inbound_socks5::Socks5Inbound;
use rustbox_kernel::{Engine, EngineError, FlowSink, Service, ServiceContext, ServiceError};
use rustbox_outbound_direct::DirectOutbound;
use rustbox_route::RouteTable;
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
        let validated = ConfigCompiler::validate(parsed).map_err(ComposeError::Config)?;
        let compiled = ConfigCompiler::compile(validated).map_err(ComposeError::Config)?;
        self.compose(compiled)
    }

    pub fn compose(self, compiled: CompiledConfig) -> Result<ComposedRuntime, ComposeError> {
        // 关键装配点：路由表、内核、出站、inbound 服务都在这里显式连线。
        let router = route_table(&compiled);
        let mut builder =
            Engine::builder(Box::new(router)).observability(self.observability.clone());

        for outbound in &compiled.outbounds {
            match outbound {
                CompiledOutbound::Direct { id, .. } => {
                    builder = builder
                        .register_outbound(Box::new(
                            DirectOutbound::new(*id, self.host.clone())
                                .with_observability(self.observability.clone()),
                        ))
                        .map_err(ComposeError::Engine)?;
                }
            }
        }

        let engine = Arc::new(builder.build().map_err(ComposeError::Engine)?);
        let sink: Arc<dyn FlowSink> = engine.clone();
        let mut services: Vec<Box<dyn Service>> = Vec::new();

        for inbound in compiled.inbounds {
            match inbound {
                CompiledInbound::HttpConnect { id, listen, .. } => {
                    services.push(Box::new(
                        HttpProxyInbound::new(
                            id,
                            listen,
                            self.host.clone(),
                            self.host.clone(),
                            sink.clone(),
                        )
                        .with_observability(self.observability.clone()),
                    ));
                }
                CompiledInbound::Socks5 { id, listen, .. } => {
                    services.push(Box::new(
                        Socks5Inbound::new(
                            id,
                            listen,
                            self.host.clone(),
                            self.host.clone(),
                            sink.clone(),
                        )
                        .with_observability(self.observability.clone()),
                    ));
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
        }
    }

    if compiled.route_rules.is_empty() {
        table.with_default(RouteDecision::Reject(rustbox_types::RejectReason::NoRoute))
    } else {
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::Endpoint;

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
}
