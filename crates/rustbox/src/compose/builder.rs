use super::{compose_engine, compose_inbounds, dns::compose_dns};
use crate::{ComposeError, RuntimeCapabilities, ruleset::RuleSetService, runtime::ComposedRuntime};
use rustbox_config::{CompiledConfig, ConfigCompiler, SourceConfig};
use rustbox_kernel::FlowSink;
use rustbox_kernel::{
    DialOptions, NetworkProvider, NetworkProviderPurpose, NoopObservabilitySink, ObservabilitySink,
    TaskScope,
};
#[cfg(test)]
use rustbox_types::Endpoint;
use std::sync::Arc;

pub(crate) struct RuntimeGraphBuilder {
    capabilities: RuntimeCapabilities,
    host: Arc<dyn NetworkProvider>,
    observability: Arc<dyn ObservabilitySink>,
}

impl RuntimeGraphBuilder {
    pub(crate) fn new() -> Self {
        Self::with_capabilities(
            RuntimeCapabilities::default(),
            Arc::new(NoopObservabilitySink),
        )
    }

    pub(crate) fn with_capabilities(
        capabilities: RuntimeCapabilities,
        observability: Arc<dyn ObservabilitySink>,
    ) -> Self {
        let host = capabilities.network.create(
            NetworkProviderPurpose::Inbound,
            DialOptions::default(),
            None,
        );
        Self {
            capabilities,
            host,
            observability,
        }
    }

    #[cfg(test)]
    pub(crate) fn default_http_proxy(listen: Endpoint) -> Result<ComposedRuntime, ComposeError> {
        Self::new().compose_source(SourceConfig::default_http_proxy(listen))
    }

    pub(crate) fn compose_source(
        self,
        source: SourceConfig,
    ) -> Result<ComposedRuntime, ComposeError> {
        let parsed = ConfigCompiler::parse(source).map_err(ComposeError::Config)?;
        let normalized = ConfigCompiler::normalize(parsed).map_err(ComposeError::Config)?;
        let validated = ConfigCompiler::validate(normalized).map_err(ComposeError::Config)?;
        let compiled = ConfigCompiler::compile(&validated).map_err(ComposeError::Config)?;
        self.compose(compiled)
    }

    fn compose(self, compiled: CompiledConfig) -> Result<ComposedRuntime, ComposeError> {
        super::dependency::validate_runtime_dependencies(&compiled)?;
        let dns_composition = compose_dns(&compiled)?;
        let dns = dns_composition.as_ref().map(|dns| dns.subsystem.clone());
        let reverse_dns = dns.as_ref().map(|dns| dns.reverse_dns());
        let session_tasks = TaskScope::new();
        let (engine, outbound_groups, rule_set_store, runtime_outbounds) = compose_engine(
            &compiled,
            &self.capabilities,
            &self.observability,
            dns.clone(),
            reverse_dns,
            &session_tasks,
        )?;
        if let Some(dns) = &dns_composition {
            dns.bind(&runtime_outbounds)?;
        }
        let urltest = crate::urltest::UrlTestService::from_compiled(
            &compiled,
            runtime_outbounds,
            outbound_groups.clone(),
        );
        let urltest_controller = urltest.controller();
        let has_dynamic_rule_sets = compiled.route_rule_sets.iter().any(|rule_set| {
            !matches!(
                rule_set.source,
                rustbox_config::RouteRuleSetSourceConfig::Inline
            )
        });
        let rule_sets = RuleSetService::new(compiled.route_rule_sets, rule_set_store);
        let rule_set_controller = rule_sets.controller();
        let sink: Arc<dyn FlowSink> = engine.clone();
        let mut services = compose_inbounds(
            compiled.inbounds,
            &self.host,
            &self.capabilities,
            &self.observability,
            &sink,
        )?;
        if !urltest.is_empty() {
            services.push(Box::new(urltest));
        }
        if has_dynamic_rule_sets {
            services.insert(0, Box::new(rule_sets));
        }
        Ok(ComposedRuntime::new(
            engine,
            services,
            outbound_groups,
            dns,
            session_tasks,
            urltest_controller,
            rule_set_controller,
        ))
    }
}

impl Default for RuntimeGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
