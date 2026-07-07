//! 路由评估契约与基础实现。
//!
//! 路由层只消费 `FlowMeta` 并返回 `RouteDecision`，不发起 DNS、进程查询或 I/O。

use rustbox_types::{FlowMeta, OutboundId, RejectReason, RouteDecision};
use std::collections::HashMap;

/// 纯路由决策接口。
pub trait Router: Send + Sync {
    fn route(&self, flow: &FlowMeta) -> RouteDecision;
}

/// 始终转发到同一个 outbound 的最小路由器，主要用于默认图和测试。
#[derive(Clone, Debug)]
pub struct StaticRouter {
    outbound: OutboundId,
}

impl StaticRouter {
    pub fn new(outbound: OutboundId) -> Self {
        Self { outbound }
    }
}

impl Router for StaticRouter {
    fn route(&self, _flow: &FlowMeta) -> RouteDecision {
        RouteDecision::Forward(self.outbound)
    }
}

#[derive(Clone, Debug)]
pub struct RejectRouter {
    reason: RejectReason,
}

impl RejectRouter {
    pub fn new(reason: RejectReason) -> Self {
        Self { reason }
    }
}

impl Router for RejectRouter {
    fn route(&self, _flow: &FlowMeta) -> RouteDecision {
        RouteDecision::Reject(self.reason.clone())
    }
}

/// 当前的简单路由表：支持默认规则和精确域名覆盖。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteTable {
    default: Option<RouteDecision>,
    by_domain: HashMap<String, RouteDecision>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default(mut self, decision: RouteDecision) -> Self {
        self.default = Some(decision);
        self
    }

    pub fn insert_domain(
        &mut self,
        domain: impl Into<String>,
        decision: RouteDecision,
    ) -> Option<RouteDecision> {
        self.by_domain.insert(domain.into(), decision)
    }
}

impl Router for RouteTable {
    fn route(&self, flow: &FlowMeta) -> RouteDecision {
        let domain_match = flow.domain.as_ref().and_then(|host| match host {
            rustbox_types::Host::Domain(domain) => self.by_domain.get(domain),
            rustbox_types::Host::Ip(_) => None,
        });

        domain_match
            .or(self.default.as_ref())
            .cloned()
            .unwrap_or(RouteDecision::Reject(RejectReason::NoRoute))
    }
}
