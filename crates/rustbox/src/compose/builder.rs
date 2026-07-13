use super::{compose_engine, compose_inbounds};
use crate::{ComposeError, runtime::ComposedRuntime};
use rustbox_config::{CompiledConfig, ConfigCompiler, SourceConfig};
use rustbox_kernel::FlowSink;
use rustbox_kernel::{NoopObservabilitySink, ObservabilitySink, TokioHost};
#[cfg(test)]
use rustbox_types::Endpoint;
use std::sync::Arc;

pub(crate) struct RuntimeGraphBuilder {
    host: Arc<TokioHost>,
    observability: Arc<dyn ObservabilitySink>,
}

impl RuntimeGraphBuilder {
    pub(crate) fn new() -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub(crate) fn with_observability(observability: Arc<dyn ObservabilitySink>) -> Self {
        Self {
            host: Arc::new(TokioHost::new()),
            observability,
        }
    }

    #[cfg(test)]
    pub(crate) fn default_http_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_source(SourceConfig::default_http_proxy(listen))
    }

    #[cfg(test)]
    pub(crate) fn default_socks5_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_source(SourceConfig::default_socks5_proxy(listen))
    }

    pub(crate) fn compose_source(
        self,
        source: SourceConfig,
    ) -> Result<ComposedRuntime, ComposeError> {
        let parsed = ConfigCompiler::parse(source).map_err(ComposeError::Config)?;
        let normalized = ConfigCompiler::normalize(parsed).map_err(ComposeError::Config)?;
        let validated = ConfigCompiler::validate(normalized).map_err(ComposeError::Config)?;
        let compiled = ConfigCompiler::compile(validated).map_err(ComposeError::Config)?;
        self.compose(compiled)
    }

    fn compose(self, compiled: CompiledConfig) -> Result<ComposedRuntime, ComposeError> {
        let engine = compose_engine(&compiled, &self.host, &self.observability)?;
        let sink: Arc<dyn FlowSink> = engine.clone();
        let services = compose_inbounds(compiled.inbounds, &self.host, &self.observability, sink)?;
        Ok(ComposedRuntime::new(engine, services))
    }
}

impl Default for RuntimeGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
