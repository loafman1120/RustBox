//! Metadata enrichment pipeline contracts.

use rustbox_host_api::BoxFuture;
use rustbox_kernel::{InspectError, MetadataEnricher};
use rustbox_types::{FlowMeta, Host, ProtocolHint};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticDomainEnricher {
    domain: Host,
}

impl StaticDomainEnricher {
    pub fn new(domain: Host) -> Self {
        Self { domain }
    }
}

impl MetadataEnricher for StaticDomainEnricher {
    fn name(&self) -> &'static str {
        "static-domain"
    }

    fn enrich(&self, mut meta: FlowMeta) -> BoxFuture<'_, Result<FlowMeta, InspectError>> {
        Box::pin(async move {
            meta.domain = Some(self.domain.clone());
            Ok(meta)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticProtocolHintEnricher {
    hint: ProtocolHint,
}

impl StaticProtocolHintEnricher {
    pub fn new(hint: ProtocolHint) -> Self {
        Self { hint }
    }
}

impl MetadataEnricher for StaticProtocolHintEnricher {
    fn name(&self) -> &'static str {
        "static-protocol-hint"
    }

    fn enrich(&self, mut meta: FlowMeta) -> BoxFuture<'_, Result<FlowMeta, InspectError>> {
        Box::pin(async move {
            meta.protocol_hint = Some(self.hint);
            Ok(meta)
        })
    }
}
