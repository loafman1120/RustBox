use rustbox_config::{CompiledConfig, CompiledOutboundKind};
use rustbox_types::{OutboundId, RouteDecision};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundGroupKind {
    Selector,
    UrlTest,
}

impl OutboundGroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selector => "selector",
            Self::UrlTest => "urltest",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundGroupItem {
    pub tag: String,
    pub kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundGroupSnapshot {
    pub tag: String,
    pub kind: OutboundGroupKind,
    pub selectable: bool,
    pub selected: String,
    pub items: Vec<OutboundGroupItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectOutboundError {
    GroupNotFound(String),
    NotSelectable(String),
    OutboundNotFound { group: String, outbound: String },
    StateUnavailable,
}

impl fmt::Display for SelectOutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupNotFound(group) => write!(f, "selector not found: {group}"),
            Self::NotSelectable(group) => write!(f, "outbound is not a selector: {group}"),
            Self::OutboundNotFound { group, outbound } => {
                write!(f, "outbound `{outbound}` not found in selector `{group}`")
            }
            Self::StateUnavailable => f.write_str("outbound group state is unavailable"),
        }
    }
}

#[derive(Debug)]
struct GroupState {
    id: OutboundId,
    tag: String,
    kind: OutboundGroupKind,
    items: Vec<GroupItemState>,
    selected: usize,
}

#[derive(Debug)]
struct GroupItemState {
    tag: String,
    kind: String,
    decision: RouteDecision,
}

#[derive(Debug, Default)]
struct RegistryState {
    groups: Vec<GroupState>,
    by_id: HashMap<OutboundId, usize>,
    by_tag: HashMap<String, usize>,
}

/// Runtime state shared by the route resolver and the control API.
///
/// A selection affects routing decisions made after the update. Streams and
/// datagram relays that already resolved an outbound keep using that outbound.
#[derive(Debug, Default)]
pub struct OutboundGroupRegistry {
    state: RwLock<RegistryState>,
}

impl OutboundGroupRegistry {
    pub fn from_compiled(config: &CompiledConfig) -> Self {
        let tags = config
            .outbounds
            .iter()
            .map(|outbound| (outbound.id, outbound.logical_id.clone()))
            .collect::<HashMap<_, _>>();
        let kinds = config
            .outbounds
            .iter()
            .map(|outbound| (outbound.id, outbound_kind_name(&outbound.kind).to_string()))
            .collect::<HashMap<_, _>>();
        let decisions = config
            .outbounds
            .iter()
            .map(|outbound| {
                let decision = if matches!(outbound.kind, CompiledOutboundKind::Block) {
                    use rustbox_types::RejectReason;
                    RouteDecision::Reject(RejectReason::Policy)
                } else {
                    RouteDecision::Forward(outbound.id)
                };
                (outbound.id, decision)
            })
            .collect::<HashMap<_, _>>();

        let mut state = RegistryState::default();
        for outbound in &config.outbounds {
            let (kind, children, selected) = match &outbound.kind {
                CompiledOutboundKind::Selector {
                    outbounds,
                    selected,
                } => (OutboundGroupKind::Selector, outbounds, selected),
                CompiledOutboundKind::UrlTest {
                    outbounds,
                    selected,
                    ..
                } => (OutboundGroupKind::UrlTest, outbounds, selected),
                _ => continue,
            };
            let items = children
                .iter()
                .filter_map(|id| {
                    Some(GroupItemState {
                        tag: tags.get(id)?.clone(),
                        kind: kinds.get(id)?.clone(),
                        decision: decisions.get(id)?.clone(),
                    })
                })
                .collect::<Vec<_>>();
            let selected = items
                .iter()
                .position(|item| item.decision == *selected)
                .unwrap_or(0);
            let index = state.groups.len();
            state.by_id.insert(outbound.id, index);
            state.by_tag.insert(outbound.logical_id.clone(), index);
            state.groups.push(GroupState {
                id: outbound.id,
                tag: outbound.logical_id.clone(),
                kind,
                items,
                selected,
            });
        }
        Self {
            state: RwLock::new(state),
        }
    }

    pub fn resolve(&self, decision: RouteDecision) -> RouteDecision {
        let RouteDecision::Forward(id) = decision else {
            return decision;
        };
        let Ok(state) = self.state.read() else {
            return RouteDecision::Forward(id);
        };
        let Some(group) = state
            .by_id
            .get(&id)
            .and_then(|index| state.groups.get(*index))
        else {
            return RouteDecision::Forward(id);
        };
        group
            .items
            .get(group.selected)
            .map(|item| item.decision.clone())
            .unwrap_or(RouteDecision::Forward(group.id))
    }

    pub fn list(&self) -> Vec<OutboundGroupSnapshot> {
        self.state
            .read()
            .map(|state| state.groups.iter().map(snapshot).collect())
            .unwrap_or_default()
    }

    pub fn select(
        &self,
        group_tag: &str,
        outbound_tag: &str,
    ) -> Result<OutboundGroupSnapshot, SelectOutboundError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| SelectOutboundError::StateUnavailable)?;
        let index = state
            .by_tag
            .get(group_tag)
            .copied()
            .ok_or_else(|| SelectOutboundError::GroupNotFound(group_tag.to_string()))?;
        let group = &mut state.groups[index];
        if group.kind != OutboundGroupKind::Selector {
            return Err(SelectOutboundError::NotSelectable(group_tag.to_string()));
        }
        group.selected = group
            .items
            .iter()
            .position(|item| item.tag == outbound_tag)
            .ok_or_else(|| SelectOutboundError::OutboundNotFound {
                group: group_tag.to_string(),
                outbound: outbound_tag.to_string(),
            })?;
        Ok(snapshot(group))
    }
}

fn snapshot(group: &GroupState) -> OutboundGroupSnapshot {
    OutboundGroupSnapshot {
        tag: group.tag.clone(),
        kind: group.kind,
        selectable: group.kind == OutboundGroupKind::Selector,
        selected: group
            .items
            .get(group.selected)
            .map(|item| item.tag.clone())
            .unwrap_or_default(),
        items: group
            .items
            .iter()
            .map(|item| OutboundGroupItem {
                tag: item.tag.clone(),
                kind: item.kind.clone(),
            })
            .collect(),
    }
}

fn outbound_kind_name(kind: &CompiledOutboundKind) -> &'static str {
    match kind {
        CompiledOutboundKind::Direct => "direct",
        CompiledOutboundKind::Block => "block",
        CompiledOutboundKind::Socks5 { .. } => "socks",
        CompiledOutboundKind::Http { .. } => "http",
        CompiledOutboundKind::Shadowsocks { .. } => "shadowsocks",
        CompiledOutboundKind::Selector { .. } => "selector",
        CompiledOutboundKind::UrlTest { .. } => "urltest",
        CompiledOutboundKind::Vmess { .. } => "vmess",
        CompiledOutboundKind::Vless { .. } => "vless",
        CompiledOutboundKind::Trojan { .. } => "trojan",
        CompiledOutboundKind::AnyTls { .. } => "anytls",
        CompiledOutboundKind::Hysteria2 { .. } => "hysteria2",
        CompiledOutboundKind::Naive { .. } => "naive",
        CompiledOutboundKind::Tuic { .. } => "tuic",
        CompiledOutboundKind::WireGuard { .. } => "wireguard",
        CompiledOutboundKind::ShadowTls { .. } => "shadowtls",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_config::{CompiledOutbound, CompiledRouteRule};
    use rustbox_types::{RejectReason, RouteDecision};

    #[test]
    fn selector_switch_changes_the_resolved_route() {
        let direct = outbound_id(1);
        let block = outbound_id(2);
        let selector = outbound_id(3);
        let registry = OutboundGroupRegistry::from_compiled(&CompiledConfig {
            inbounds: Vec::new(),
            outbounds: vec![
                CompiledOutbound {
                    id: direct,
                    logical_id: "direct".into(),
                    dial: Default::default(),
                    kind: CompiledOutboundKind::Direct,
                },
                CompiledOutbound {
                    id: block,
                    logical_id: "block".into(),
                    dial: Default::default(),
                    kind: CompiledOutboundKind::Block,
                },
                CompiledOutbound {
                    id: selector,
                    logical_id: "select".into(),
                    dial: Default::default(),
                    kind: CompiledOutboundKind::Selector {
                        outbounds: vec![direct, block],
                        selected: RouteDecision::Forward(direct),
                    },
                },
            ],
            dns: None,
            route_rule_sets: Vec::new(),
            route_rules: vec![CompiledRouteRule::Default(RouteDecision::Forward(selector))],
        });

        assert_eq!(
            registry.resolve(RouteDecision::Forward(selector)),
            RouteDecision::Forward(direct)
        );
        let selected = registry.select("select", "block").expect("select block");
        assert_eq!(selected.selected, "block");
        assert_eq!(
            registry.resolve(RouteDecision::Forward(selector)),
            RouteDecision::Reject(RejectReason::Policy)
        );
    }

    #[test]
    fn rejects_manual_selection_for_urltest() {
        let direct = outbound_id(1);
        let automatic = outbound_id(2);
        let registry = OutboundGroupRegistry::from_compiled(&CompiledConfig {
            inbounds: Vec::new(),
            outbounds: vec![
                CompiledOutbound {
                    id: direct,
                    logical_id: "direct".into(),
                    dial: Default::default(),
                    kind: CompiledOutboundKind::Direct,
                },
                CompiledOutbound {
                    id: automatic,
                    logical_id: "auto".into(),
                    dial: Default::default(),
                    kind: CompiledOutboundKind::UrlTest {
                        outbounds: vec![direct],
                        selected: RouteDecision::Forward(direct),
                        url: "https://www.gstatic.com/generate_204".into(),
                        interval_seconds: 300,
                        tolerance_ms: 50,
                    },
                },
            ],
            dns: None,
            route_rule_sets: Vec::new(),
            route_rules: Vec::new(),
        });

        assert!(!registry.list()[0].selectable);
        assert_eq!(
            registry.select("auto", "direct"),
            Err(SelectOutboundError::NotSelectable("auto".into()))
        );
    }

    fn outbound_id(value: u64) -> OutboundId {
        OutboundId::new(NonZeroU64::new(value).expect("non-zero outbound id"))
    }
}
