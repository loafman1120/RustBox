//! 路由评估契约与基础实现。
//!
//! 路由层只消费 `FlowMeta` 并返回 `RouteDecision`，不发起 DNS、进程查询或 I/O。

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use rustbox_types::{
    FlowMeta, Host, InboundId, IpAddress, IpCidr, Network, OutboundId, PortRange, RejectReason,
    RouteDecision,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
    matcher: RouteMatcher,
    decision: RouteDecision,
}

impl RouteRule {
    pub fn new(matcher: RouteMatcher, decision: RouteDecision) -> Self {
        Self { matcher, decision }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalMode {
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMatcher {
    Conditions(Box<RouteConditions>),
    Logical {
        mode: LogicalMode,
        rules: Vec<RouteMatcher>,
        invert: bool,
    },
}

impl RouteMatcher {
    pub fn matches(&self, flow: &FlowMeta, rule_sets: &HashMap<String, RouteRuleSet>) -> bool {
        match self {
            Self::Conditions(conditions) => conditions.matches(flow, rule_sets),
            Self::Logical {
                mode,
                rules,
                invert,
            } => {
                let matched = match mode {
                    LogicalMode::And => rules.iter().all(|rule| rule.matches(flow, rule_sets)),
                    LogicalMode::Or => rules.iter().any(|rule| rule.matches(flow, rule_sets)),
                };
                if *invert { !matched } else { matched }
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteConditions {
    pub inbounds: Vec<InboundId>,
    pub networks: Vec<Network>,
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ip_cidrs: Vec<IpCidr>,
    pub source_ip_cidrs: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub rule_sets: Vec<String>,
    pub invert: bool,
}

impl RouteConditions {
    pub fn matches(&self, flow: &FlowMeta, rule_sets: &HashMap<String, RouteRuleSet>) -> bool {
        let matched = self.matches_without_invert(flow, rule_sets);
        if self.invert { !matched } else { matched }
    }

    fn matches_without_invert(
        &self,
        flow: &FlowMeta,
        rule_sets: &HashMap<String, RouteRuleSet>,
    ) -> bool {
        if !self.inbounds.is_empty() && !self.inbounds.contains(&flow.inbound) {
            return false;
        }
        if !self.networks.is_empty() && !self.networks.contains(&flow.network) {
            return false;
        }
        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|range| range.contains(flow.destination.port))
        {
            return false;
        }
        if !self.source_ports.is_empty()
            && !self
                .source_ports
                .iter()
                .any(|range| range.contains(flow.source.port))
        {
            return false;
        }

        if self.has_destination_matchers() && !self.matches_destination(flow) {
            return false;
        }

        if !self.source_ip_cidrs.is_empty() && !self.matches_source_ip(flow) {
            return false;
        }

        if !self.rule_sets.is_empty()
            && !self.rule_sets.iter().any(|id| {
                rule_sets
                    .get(id)
                    .is_some_and(|rule_set| rule_set.matches(flow, rule_sets))
            })
        {
            return false;
        }

        true
    }

    fn has_destination_matchers(&self) -> bool {
        !self.domains.is_empty()
            || !self.domain_suffixes.is_empty()
            || !self.domain_keywords.is_empty()
            || !self.domain_regexes.is_empty()
            || !self.ip_cidrs.is_empty()
    }

    fn matches_destination(&self, flow: &FlowMeta) -> bool {
        let domain = flow_domain(flow);
        if let Some(domain) = domain.as_deref()
            && (contains_case_insensitive(&self.domains, domain)
                || self
                    .domain_suffixes
                    .iter()
                    .any(|suffix| domain_matches_suffix(domain, suffix))
                || self
                    .domain_keywords
                    .iter()
                    .any(|keyword| domain.contains(&keyword.to_ascii_lowercase()))
                || self
                    .domain_regexes
                    .iter()
                    .any(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(domain))))
        {
            return true;
        }

        destination_ip(flow)
            .is_some_and(|ip| self.ip_cidrs.iter().any(|cidr| cidr_contains(*cidr, ip)))
    }

    fn matches_source_ip(&self, flow: &FlowMeta) -> bool {
        source_ip(flow).is_some_and(|ip| {
            self.source_ip_cidrs
                .iter()
                .any(|cidr| cidr_contains(*cidr, ip))
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteRuleSet {
    pub rules: Vec<RouteMatcher>,
}

impl RouteRuleSet {
    pub fn new(rules: Vec<RouteMatcher>) -> Self {
        Self { rules }
    }

    pub fn matches(&self, flow: &FlowMeta, rule_sets: &HashMap<String, RouteRuleSet>) -> bool {
        self.rules
            .iter()
            .any(|matcher| matcher.matches(flow, rule_sets))
    }
}

/// 顺序路由表：第一条匹配规则获胜，未命中时使用默认决策。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteTable {
    rules: Vec<RouteRule>,
    rule_sets: HashMap<String, RouteRuleSet>,
    default: Option<RouteDecision>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default(mut self, decision: RouteDecision) -> Self {
        self.default = Some(decision);
        self
    }

    pub fn push_rule(&mut self, rule: RouteRule) {
        self.rules.push(rule);
    }

    pub fn insert_rule_set(
        &mut self,
        id: impl Into<String>,
        rule_set: RouteRuleSet,
    ) -> Option<RouteRuleSet> {
        self.rule_sets.insert(id.into(), rule_set)
    }

    pub fn insert_domain(
        &mut self,
        domain: impl Into<String>,
        decision: RouteDecision,
    ) -> Option<RouteDecision> {
        let matcher = RouteMatcher::Conditions(
            RouteConditions {
                domains: vec![domain.into()],
                ..RouteConditions::default()
            }
            .into(),
        );
        self.rules.push(RouteRule::new(matcher, decision));
        None
    }
}

impl Router for RouteTable {
    fn route(&self, flow: &FlowMeta) -> RouteDecision {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches(flow, &self.rule_sets))
            .map(|rule| rule.decision.clone())
            .or_else(|| self.default.clone())
            .unwrap_or(RouteDecision::Reject(RejectReason::NoRoute))
    }
}

fn flow_domain(flow: &FlowMeta) -> Option<String> {
    match flow.domain.as_ref().unwrap_or(&flow.destination.host) {
        Host::Domain(domain) => Some(domain.to_ascii_lowercase()),
        Host::Ip(_) => None,
    }
}

fn destination_ip(flow: &FlowMeta) -> Option<IpAddress> {
    match flow.destination.host {
        Host::Ip(ip) => Some(ip),
        Host::Domain(_) => None,
    }
}

fn source_ip(flow: &FlowMeta) -> Option<IpAddress> {
    match flow.source.host {
        Host::Ip(ip) => Some(ip),
        Host::Domain(_) => None,
    }
}

fn contains_case_insensitive(values: &[String], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(candidate))
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let suffix = suffix.to_ascii_lowercase();
    domain == suffix
        || domain
            .strip_suffix(&suffix)
            .is_some_and(|head| head.ends_with('.'))
}

fn cidr_contains(cidr: IpCidr, address: IpAddress) -> bool {
    let Ok(network) = ip_net(cidr) else {
        return false;
    };
    network.contains(&ip_addr(address))
}

fn ip_net(cidr: IpCidr) -> Result<IpNet, ipnet::PrefixLenError> {
    match cidr.address {
        IpAddress::V4(octets) => {
            Ipv4Net::new(Ipv4Addr::from(octets), cidr.prefix_len).map(IpNet::V4)
        }
        IpAddress::V6(octets) => {
            Ipv6Net::new(Ipv6Addr::from(octets), cidr.prefix_len).map(IpNet::V6)
        }
    }
}

fn ip_addr(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_types::{Endpoint, FlowId, InboundId};

    #[test]
    fn routes_first_matching_rule_before_default() {
        let proxy = outbound_id(1);
        let direct = outbound_id(2);
        let mut table = RouteTable::new().with_default(RouteDecision::Forward(direct));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                domain_suffixes: vec!["example.test".to_string()],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));

        assert_eq!(
            table.route(&flow_with_domain("api.example.test")),
            RouteDecision::Forward(proxy)
        );
        assert_eq!(
            table.route(&flow_with_domain("other.test")),
            RouteDecision::Forward(direct)
        );
    }

    #[test]
    fn matches_network_port_cidr_and_invert() {
        let direct = outbound_id(1);
        let block = RouteDecision::Reject(RejectReason::Policy);
        let mut table = RouteTable::new().with_default(RouteDecision::Forward(direct));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                networks: vec![Network::Tcp],
                ip_cidrs: vec![IpCidr::new(IpAddress::V4([10, 0, 0, 0]), 8).expect("cidr")],
                ports: vec![PortRange::single(443)],
                invert: true,
                ..RouteConditions::default()
            })),
            block.clone(),
        ));

        assert_eq!(
            table.route(&flow_with_ip([10, 1, 2, 3], 443)),
            RouteDecision::Forward(direct)
        );
        assert_eq!(table.route(&flow_with_ip([10, 1, 2, 3], 80)), block);
    }

    #[test]
    fn matches_rule_set_from_outer_rule() {
        let proxy = outbound_id(1);
        let mut table =
            RouteTable::new().with_default(RouteDecision::Reject(RejectReason::NoRoute));
        table.insert_rule_set(
            "ads",
            RouteRuleSet::new(vec![RouteMatcher::Conditions(Box::new(RouteConditions {
                domain_keywords: vec!["ads".to_string()],
                ..RouteConditions::default()
            }))]),
        );
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                rule_sets: vec!["ads".to_string()],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));

        assert_eq!(
            table.route(&flow_with_domain("cdn.ads.example.test")),
            RouteDecision::Forward(proxy)
        );
    }

    fn flow_with_domain(domain: &str) -> FlowMeta {
        FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).expect("non-zero")),
            network: Network::Tcp,
            source: Endpoint::localhost_v4(12000),
            destination: Endpoint::new(Host::domain(domain), 443),
            inbound: InboundId::new(NonZeroU64::new(1).expect("non-zero")),
            domain: Some(Host::domain(domain)),
            protocol_hint: None,
        }
    }

    fn flow_with_ip(ip: [u8; 4], port: u16) -> FlowMeta {
        FlowMeta {
            destination: Endpoint::new(Host::Ip(IpAddress::V4(ip)), port),
            domain: None,
            ..flow_with_domain("example.test")
        }
    }

    fn outbound_id(value: u64) -> OutboundId {
        OutboundId::new(NonZeroU64::new(value).expect("non-zero"))
    }
}
