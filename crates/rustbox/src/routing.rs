use rustbox_config::{
    CompiledConfig, CompiledRouteConditions, CompiledRouteMatcher, CompiledRouteRule,
    LogicalModeConfig,
};
use rustbox_control::OutboundGroupRegistry;
use rustbox_route::{
    LogicalMode, RouteConditions, RouteMatcher, RouteRule, RouteRuleSet, RouteTable, Router,
};
use rustbox_types::FlowMeta;
use rustbox_types::{RejectReason, RouteDecision};
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
}

pub(crate) fn route_table(compiled: &CompiledConfig) -> RouteTable {
    let mut table = RouteTable::new();
    for rule in &compiled.route_rules {
        match rule {
            CompiledRouteRule::Default(decision) => {
                table = table.with_default(decision.clone());
            }
            CompiledRouteRule::Rule { matcher, decision } => {
                table.push_rule(RouteRule::new(route_matcher(matcher), decision.clone()));
            }
        }
    }

    for rule_set in &compiled.route_rule_sets {
        table.insert_rule_set(
            rule_set.id.clone(),
            RouteRuleSet::new(rule_set.rules.iter().map(route_matcher).collect()),
        );
    }

    if compiled.route_rules.is_empty() {
        table.with_default(RouteDecision::Reject(RejectReason::NoRoute))
    } else {
        table
    }
}

fn route_matcher(matcher: &CompiledRouteMatcher) -> RouteMatcher {
    match matcher {
        CompiledRouteMatcher::Conditions(conditions) => {
            RouteMatcher::Conditions(Box::new(route_conditions(conditions)))
        }
        CompiledRouteMatcher::Logical {
            mode,
            rules,
            invert,
        } => RouteMatcher::Logical {
            mode: logical_mode(mode),
            rules: rules.iter().map(route_matcher).collect(),
            invert: *invert,
        },
    }
}

fn route_conditions(conditions: &CompiledRouteConditions) -> RouteConditions {
    RouteConditions {
        inbounds: conditions.inbounds.clone(),
        networks: conditions.networks.clone(),
        protocols: conditions.protocols.clone(),
        domains: conditions.domains.clone(),
        domain_suffixes: conditions.domain_suffixes.clone(),
        domain_keywords: conditions.domain_keywords.clone(),
        domain_regexes: conditions.domain_regexes.clone(),
        ip_cidrs: conditions.ip_cidrs.clone(),
        source_ip_cidrs: conditions.source_ip_cidrs.clone(),
        ports: conditions.ports.clone(),
        source_ports: conditions.source_ports.clone(),
        rule_sets: conditions.rule_sets.clone(),
        invert: conditions.invert,
    }
}

fn logical_mode(mode: &LogicalModeConfig) -> LogicalMode {
    match mode {
        LogicalModeConfig::And => LogicalMode::And,
        LogicalModeConfig::Or => LogicalMode::Or,
    }
}
