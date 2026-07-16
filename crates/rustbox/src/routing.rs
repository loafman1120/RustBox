use rustbox_config::{
    CompiledConfig, CompiledRouteConditions, CompiledRouteMatcher, CompiledRouteRule,
    LogicalModeConfig,
};
use rustbox_control::OutboundGroupRegistry;
use rustbox_route::{
    LogicalMode, RouteAction, RouteConditions, RouteMatcher, RouteRule, RouteRuleSet, RouteStep,
    RouteTable, Router,
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
            *decision = self.groups.resolve(decision.clone());
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
                Host::Ip(address) => conditions
                    .ip_cidrs
                    .push(IpCidr::new(address, address.max_prefix_len()).expect("valid host CIDR")),
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
                table.push_rule(RouteRule::with_action(
                    route_matcher(matcher),
                    action.clone(),
                ));
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

pub(crate) fn route_matcher(matcher: &CompiledRouteMatcher) -> RouteMatcher {
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
        process_names: conditions.process_names.clone(),
        process_paths: conditions.process_paths.clone(),
        package_names: conditions.package_names.clone(),
        user_ids: conditions.user_ids.clone(),
        user_names: conditions.user_names.clone(),
        interfaces: conditions.interfaces.clone(),
        wifi_ssids: conditions.wifi_ssids.clone(),
        wifi_bssids: conditions.wifi_bssids.clone(),
        network_types: conditions.network_types.clone(),
        invert: conditions.invert,
    }
}

fn logical_mode(mode: &LogicalModeConfig) -> LogicalMode {
    match mode {
        LogicalModeConfig::And => LogicalMode::And,
        LogicalModeConfig::Or => LogicalMode::Or,
    }
}
