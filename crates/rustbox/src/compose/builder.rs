use super::{compose_engine, compose_inbounds};
use crate::{ComposeError, RuntimeCapabilities, ruleset::RuleSetService, runtime::ComposedRuntime};
use rustbox_config::{
    CompiledConfig, CompiledOutboundKind, ConfigCompiler, ConfigError, SourceConfig,
};
use rustbox_dns_core::{DnsConfig, DnsServerConfig, DnsSubsystem};
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
        let dns = compose_dns(&compiled)?.map(Arc::new);
        let reverse_dns = dns.as_ref().map(|dns| dns.reverse_dns());
        let session_tasks = TaskScope::new();
        let (engine, outbound_groups, rule_set_store) = compose_engine(
            &compiled,
            &self.capabilities,
            &self.observability,
            dns.clone(),
            reverse_dns,
            &session_tasks,
        )?;
        let sink: Arc<dyn FlowSink> = engine.clone();
        let mut services = compose_inbounds(
            compiled.inbounds,
            &self.host,
            &self.capabilities,
            &self.observability,
            &sink,
        )?;
        if compiled.route_rule_sets.iter().any(|rule_set| {
            !matches!(
                rule_set.source,
                rustbox_config::RouteRuleSetSourceConfig::Inline
            )
        }) {
            services.insert(
                0,
                Box::new(RuleSetService::new(
                    compiled.route_rule_sets,
                    rule_set_store,
                )),
            );
        }
        Ok(ComposedRuntime::new(
            engine,
            services,
            outbound_groups,
            dns,
            session_tasks,
        ))
    }
}

fn compose_dns(compiled: &CompiledConfig) -> Result<Option<DnsSubsystem>, ComposeError> {
    let Some(dns) = &compiled.dns else {
        return Ok(None);
    };
    let mut servers = Vec::with_capacity(dns.servers.len());
    for server in &dns.servers {
        if let Some(outbound_id) = server.outbound {
            let direct = compiled.outbounds.iter().any(|outbound| {
                outbound.id == outbound_id && matches!(outbound.kind, CompiledOutboundKind::Direct)
            });
            if !direct {
                return Err(ComposeError::Config(ConfigError::new(format!(
                    "DNS server `{}` uses a non-direct outbound; transport socket injection is not available yet",
                    server.id
                ))));
            }
        }
        servers.push(DnsServerConfig {
            id: server.id.clone(),
            protocol: server.protocol,
            endpoint: server.endpoint.clone(),
            outbound: None,
        });
    }
    let config = DnsConfig {
        servers,
        rules: dns.rules.clone(),
        final_server: Some(dns.final_server.clone()),
        cache: dns.cache.clone(),
        fake_ip: dns.fake_ip.clone(),
        hijack: dns.hijack.clone(),
    };
    DnsSubsystem::from_config(config)
        .map(Some)
        .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))
}

impl Default for RuntimeGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
