//! 元数据增强模块。
//!
//! inspect 模块在路由前补充 FlowMeta，保持“观察/补充”和“路由决策”分离。

use rustbox_kernel::BoxFuture;
use rustbox_kernel::{InspectError, MetadataEnricher};
use rustbox_types::{FlowMeta, Host, ProtocolHint};

/// 测试和固定策略使用的域名增强器。
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

/// 测试和固定策略使用的协议提示增强器。
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
