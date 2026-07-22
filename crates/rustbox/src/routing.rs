use rustbox_config::{CompiledConfig, CompiledRouteRule};
use rustbox_control::OutboundGroupRegistry;
use rustbox_route::{
    RouteAction, RouteConditions, RouteMatcher, RouteRule, RouteRuleSet, RouteStep, RouteTable,
    Router,
};
use rustbox_types::FlowMeta;
use rustbox_types::{Host, IpCidr, PortRange, RejectReason, RouteDecision};
use std::sync::Arc;

pub(crate) struct RuntimeRouter {
    table: RouteTable,
    groups: Arc<OutboundGroupRegistry>,
}

impl RuntimeRouter {
    pub(crate) fn new(table: RouteTable, groups: Arc<OutboundGroupRegistry>) -> Self {
        Self { table, groups }
    }
}

impl Router for RuntimeRouter {
    fn route(&self, flow: &FlowMeta) -> RouteDecision {
        self.groups.resolve(self.table.route(flow))
    }

    fn route_step(&self, flow: &FlowMeta, start_rule: usize) -> RouteStep {
        let mut step = self.table.route_step(flow, start_rule);
        if let RouteAction::Final(decision) = &mut step.action {
            let (resolved, chain) = self.groups.resolve_with_chain(decision.clone());
            *decision = resolved;
            step.outbound_chain = chain;
        }
        step
    }
}

pub(crate) fn route_table(compiled: &CompiledConfig) -> RouteTable {
    let mut table = RouteTable::new();
    if let Some(dns) = &compiled.dns {
        for target in &dns.hijack {
            let mut conditions = RouteConditions::default();
            if let Some(network) = target.network {
                conditions.networks.push(network);
            }
            conditions
                .ports
                .push(PortRange::single(target.endpoint.port));
            match target.endpoint.host {
                Host::Ip(address) => conditions.ip_cidrs.push(
                    IpCidr::new(address, if address.is_ipv4() { 32 } else { 128 })
                        .expect("valid host CIDR"),
                ),
                Host::Domain(ref domain) => conditions.domains.push(domain.clone()),
            }
            table.push_rule(RouteRule::with_action(
                RouteMatcher::Conditions(Box::new(conditions)),
                RouteAction::Final(RouteDecision::Hijack(rustbox_types::dns_hijack_service_id())),
            ));
        }
    }
    for rule in &compiled.route_rules {
        match rule {
            CompiledRouteRule::Default(decision) => {
                table = table.with_default(decision.clone());
            }
            CompiledRouteRule::Rule { matcher, action } => {
                table.push_rule(RouteRule::with_action(matcher.clone(), action.clone()));
            }
        }
    }

    for rule_set in &compiled.route_rule_sets {
        table.insert_rule_set(
            rule_set.id.clone(),
            RouteRuleSet::new(rule_set.rules.clone()),
        );
    }

    if compiled.route_rules.is_empty() {
        table.with_default(RouteDecision::Reject(RejectReason::NoRoute))
    } else {
        table
    }
}
