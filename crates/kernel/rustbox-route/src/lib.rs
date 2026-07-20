//! 路由评估契约与基础实现。
//!
//! 路由层只消费 `FlowMeta` 并返回 `RouteDecision`，不发起 DNS、进程查询或 I/O。

use arc_swap::ArcSwap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use rustbox_types::{
    FlowMeta, Host, InboundId, IpAddress, IpCidr, Network, NetworkType, OutboundId, PortRange,
    ProtocolHint, RejectReason, RouteDecision,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

/// A route rule may either finish routing or mutate per-flow route state and
/// continue evaluating later rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Final(RouteDecision),
    Options(RouteOptions),
    Resolve(RouteResolve),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteOptions {
    pub override_host: Option<Host>,
    pub override_port: Option<u16>,
    pub udp_timeout: Option<Duration>,
    pub udp_connect: Option<bool>,
    pub udp_disable_domain_unmapping: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteResolve {
    pub server: Option<String>,
    pub strategy: ResolveStrategy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ResolveStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteStep {
    pub action: RouteAction,
    pub next_rule: usize,
    /// Index of the rule that produced this step. `None` means the table default.
    pub matched_rule_index: Option<usize>,
    /// Resolved outbound chain in Clash order: leaf first, outer group last.
    pub outbound_chain: Vec<OutboundId>,
}

/// 纯路由决策接口。
pub trait Router: Send + Sync {
    fn route(&self, flow: &FlowMeta) -> RouteDecision;

    fn route_step(&self, flow: &FlowMeta, _start_rule: usize) -> RouteStep {
        RouteStep {
            action: RouteAction::Final(self.route(flow)),
            next_rule: usize::MAX,
            matched_rule_index: None,
            outbound_chain: Vec::new(),
        }
    }
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
    action: RouteAction,
}

impl RouteRule {
    pub fn new(matcher: RouteMatcher, decision: RouteDecision) -> Self {
        Self {
            matcher,
            action: RouteAction::Final(decision),
        }
    }

    pub fn with_action(matcher: RouteMatcher, action: RouteAction) -> Self {
        Self { matcher, action }
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
    pub protocols: Vec<ProtocolHint>,
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ip_cidrs: Vec<IpCidr>,
    pub source_ip_cidrs: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub rule_sets: Vec<String>,
    pub process_names: Vec<String>,
    pub process_paths: Vec<String>,
    pub package_names: Vec<String>,
    pub user_ids: Vec<u32>,
    pub user_names: Vec<String>,
    pub interfaces: Vec<String>,
    pub wifi_ssids: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub network_types: Vec<NetworkType>,
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
        if !self.protocols.is_empty()
            && !flow
                .protocol_hint
                .is_some_and(|protocol| self.protocols.contains(&protocol))
        {
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

        let platform = &flow.platform;
        let process = platform.process.as_ref();
        if !self.process_names.is_empty()
            && !process
                .and_then(|value| value.name.as_deref())
                .is_some_and(|value| contains_case_insensitive(&self.process_names, value))
        {
            return false;
        }
        if !self.process_paths.is_empty()
            && !process
                .and_then(|value| value.path.as_deref())
                .is_some_and(|value| contains_case_insensitive(&self.process_paths, value))
        {
            return false;
        }
        if !self.package_names.is_empty()
            && !process
                .and_then(|value| value.package_name.as_deref())
                .is_some_and(|value| contains_case_insensitive(&self.package_names, value))
        {
            return false;
        }
        if !self.user_ids.is_empty()
            && !process
                .and_then(|value| value.user_id)
                .is_some_and(|value| self.user_ids.contains(&value))
        {
            return false;
        }
        if !self.user_names.is_empty()
            && !process
                .and_then(|value| value.user_name.as_deref())
                .is_some_and(|value| contains_case_insensitive(&self.user_names, value))
        {
            return false;
        }
        if !self.interfaces.is_empty()
            && !platform
                .interface
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(&self.interfaces, value))
        {
            return false;
        }
        if !self.wifi_ssids.is_empty()
            && !platform
                .wifi_ssid
                .as_deref()
                .is_some_and(|value| self.wifi_ssids.iter().any(|candidate| candidate == value))
        {
            return false;
        }
        if !self.wifi_bssids.is_empty()
            && !platform
                .wifi_bssid
                .as_deref()
                .is_some_and(|value| contains_case_insensitive(&self.wifi_bssids, value))
        {
            return false;
        }
        if !self.network_types.is_empty()
            && !platform
                .network_type
                .is_some_and(|value| self.network_types.contains(&value))
        {
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

#[derive(Clone)]
pub struct RuleSetStore {
    snapshot: Arc<ArcSwap<HashMap<String, RouteRuleSet>>>,
}

impl RuleSetStore {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn replace(&self, id: impl Into<String>, rule_set: RouteRuleSet) {
        let current = self.snapshot.load();
        let mut next = (**current).clone();
        next.insert(id.into(), rule_set);
        self.snapshot.store(Arc::new(next));
    }

    pub fn remove(&self, id: &str) {
        let current = self.snapshot.load();
        if !current.contains_key(id) {
            return;
        }
        let mut next = (**current).clone();
        next.remove(id);
        self.snapshot.store(Arc::new(next));
    }

    pub fn snapshot(&self) -> Arc<HashMap<String, RouteRuleSet>> {
        self.snapshot.load_full()
    }
}

impl Default for RuleSetStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RuleSetStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleSetStore")
            .field("count", &self.snapshot.load().len())
            .finish()
    }
}

impl PartialEq for RuleSetStore {
    fn eq(&self, other: &Self) -> bool {
        *self.snapshot.load_full() == *other.snapshot.load_full()
    }
}

impl Eq for RuleSetStore {}

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
    rule_sets: RuleSetStore,
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
        let id = id.into();
        let previous = self.rule_sets.snapshot().get(&id).cloned();
        self.rule_sets.replace(id, rule_set);
        previous
    }

    pub fn rule_set_store(&self) -> RuleSetStore {
        self.rule_sets.clone()
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
        let rule_sets = self.rule_sets.snapshot();
        self.rules
            .iter()
            .filter(|rule| rule.matcher.matches(flow, &rule_sets))
            .find_map(|rule| match &rule.action {
                RouteAction::Final(decision) => Some(decision.clone()),
                RouteAction::Options(_) | RouteAction::Resolve(_) => None,
            })
            .or_else(|| self.default.clone())
            .unwrap_or(RouteDecision::Reject(RejectReason::NoRoute))
    }

    fn route_step(&self, flow: &FlowMeta, start_rule: usize) -> RouteStep {
        let rule_sets = self.rule_sets.snapshot();
        for (index, rule) in self.rules.iter().enumerate().skip(start_rule) {
            if rule.matcher.matches(flow, &rule_sets) {
                return RouteStep {
                    action: rule.action.clone(),
                    next_rule: index.saturating_add(1),
                    matched_rule_index: Some(index),
                    outbound_chain: Vec::new(),
                };
            }
        }
        RouteStep {
            action: RouteAction::Final(
                self.default
                    .clone()
                    .unwrap_or(RouteDecision::Reject(RejectReason::NoRoute)),
            ),
            next_rule: usize::MAX,
            matched_rule_index: None,
            outbound_chain: Vec::new(),
        }
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
    fn continues_after_non_final_action_and_uses_updated_metadata() {
        let proxy = outbound_id(1);
        let mut table =
            RouteTable::new().with_default(RouteDecision::Reject(RejectReason::NoRoute));
        table.push_rule(RouteRule::with_action(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                domain_suffixes: vec!["example.test".to_string()],
                ..RouteConditions::default()
            })),
            RouteAction::Options(RouteOptions {
                override_host: Some(Host::domain("edge.internal")),
                override_port: Some(8443),
                ..RouteOptions::default()
            }),
        ));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                domains: vec!["edge.internal".to_string()],
                ports: vec![PortRange::single(8443)],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));

        let mut flow = flow_with_domain("api.example.test");
        let first = table.route_step(&flow, 0);
        let RouteAction::Options(options) = first.action else {
            panic!("expected route options")
        };
        flow.destination.host = options.override_host.expect("override host");
        flow.destination.port = options.override_port.expect("override port");
        flow.domain = Some(flow.destination.host.clone());
        let second = table.route_step(&flow, first.next_rule);
        assert_eq!(
            second.action,
            RouteAction::Final(RouteDecision::Forward(proxy))
        );
    }

    #[test]
    fn rule_set_store_replaces_snapshot_without_rebuilding_table() {
        let proxy = outbound_id(1);
        let direct = outbound_id(2);
        let mut table = RouteTable::new().with_default(RouteDecision::Forward(direct));
        table.insert_rule_set("dynamic", RouteRuleSet::new(Vec::new()));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                rule_sets: vec!["dynamic".to_string()],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));
        assert_eq!(
            table.route(&flow_with_domain("ads.example")),
            RouteDecision::Forward(direct)
        );

        table.rule_set_store().replace(
            "dynamic",
            RouteRuleSet::new(vec![RouteMatcher::Conditions(Box::new(RouteConditions {
                domain_keywords: vec!["ads".to_string()],
                ..RouteConditions::default()
            }))]),
        );
        assert_eq!(
            table.route(&flow_with_domain("ads.example")),
            RouteDecision::Forward(proxy)
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

    #[test]
    fn matches_sniffed_protocol() {
        let proxy = outbound_id(1);
        let direct = outbound_id(2);
        let mut table = RouteTable::new().with_default(RouteDecision::Forward(direct));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                protocols: vec![ProtocolHint::Quic],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));
        let mut flow = flow_with_ip([203, 0, 113, 1], 443);
        flow.network = Network::Udp;
        flow.protocol_hint = Some(ProtocolHint::Quic);

        assert_eq!(table.route(&flow), RouteDecision::Forward(proxy));
        flow.protocol_hint = Some(ProtocolHint::Dns);
        assert_eq!(table.route(&flow), RouteDecision::Forward(direct));
    }

    #[test]
    fn matches_process_and_platform_network_metadata() {
        let proxy = outbound_id(1);
        let direct = outbound_id(2);
        let mut table = RouteTable::new().with_default(RouteDecision::Forward(direct));
        table.push_rule(RouteRule::new(
            RouteMatcher::Conditions(Box::new(RouteConditions {
                process_names: vec!["browser.exe".into()],
                package_names: vec!["com.example.browser".into()],
                interfaces: vec!["wlan0".into()],
                wifi_ssids: vec!["Office".into()],
                network_types: vec![NetworkType::Wifi],
                ..RouteConditions::default()
            })),
            RouteDecision::Forward(proxy),
        ));
        let mut flow = flow_with_domain("example.test");
        flow.platform.interface = Some("WLAN0".into());
        flow.platform.wifi_ssid = Some("Office".into());
        flow.platform.network_type = Some(NetworkType::Wifi);
        flow.platform.process = Some(rustbox_types::ProcessMetadata {
            name: Some("Browser.EXE".into()),
            package_name: Some("com.example.browser".into()),
            ..Default::default()
        });

        assert_eq!(table.route(&flow), RouteDecision::Forward(proxy));
        flow.platform.wifi_ssid = Some("Guest".into());
        assert_eq!(table.route(&flow), RouteDecision::Forward(direct));
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
            platform: Default::default(),
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
