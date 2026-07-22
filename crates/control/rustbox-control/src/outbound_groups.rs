use rustbox_config::{CompiledConfig, CompiledOutboundKind};
use rustbox_types::{OutboundId, RouteDecision};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub url_test_time: i64,
    pub url_test_delay: Option<u32>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_success_time: Option<i64>,
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
    tolerance_ms: u16,
    failure_threshold: u32,
    cache_path: Option<PathBuf>,
}

#[derive(Debug)]
struct GroupItemState {
    id: OutboundId,
    tag: String,
    kind: String,
    decision: RouteDecision,
    delay_ms: Option<u32>,
    tested_at: i64,
    last_success_at: Option<i64>,
    consecutive_failures: u32,
    last_error: Option<String>,
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
            let (kind, children, selected, tolerance_ms, failure_threshold, cache_path) =
                match &outbound.kind {
                    CompiledOutboundKind::Selector {
                        outbounds,
                        selected,
                        cache_path,
                    } => (
                        OutboundGroupKind::Selector,
                        outbounds,
                        selected,
                        0,
                        1,
                        cache_path,
                    ),
                    CompiledOutboundKind::UrlTest {
                        outbounds,
                        selected,
                        tolerance_ms,
                        failure_threshold,
                        cache_path,
                        ..
                    } => (
                        OutboundGroupKind::UrlTest,
                        outbounds,
                        selected,
                        *tolerance_ms,
                        *failure_threshold,
                        cache_path,
                    ),
                    _ => continue,
                };
            let items = children
                .iter()
                .filter_map(|id| {
                    Some(GroupItemState {
                        id: *id,
                        tag: tags.get(id)?.clone(),
                        kind: kinds.get(id)?.clone(),
                        decision: decisions.get(id)?.clone(),
                        delay_ms: None,
                        tested_at: 0,
                        last_success_at: None,
                        consecutive_failures: 0,
                        last_error: None,
                    })
                })
                .collect::<Vec<_>>();
            let selected = cache_path
                .as_ref()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .and_then(|tag| items.iter().position(|item| item.tag == tag.trim()))
                .or_else(|| items.iter().position(|item| item.decision == *selected))
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
                tolerance_ms,
                failure_threshold,
                cache_path: cache_path.as_ref().map(PathBuf::from),
            });
        }
        Self {
            state: RwLock::new(state),
        }
    }

    pub fn resolve(&self, decision: RouteDecision) -> RouteDecision {
        self.resolve_with_chain(decision).0
    }

    pub fn resolve_with_chain(&self, decision: RouteDecision) -> (RouteDecision, Vec<OutboundId>) {
        let RouteDecision::Forward(id) = decision else {
            return (decision, Vec::new());
        };
        let Ok(state) = self.state.read() else {
            return (RouteDecision::Forward(id), vec![id]);
        };
        let Some(group) = state
            .by_id
            .get(&id)
            .and_then(|index| state.groups.get(*index))
        else {
            return (RouteDecision::Forward(id), vec![id]);
        };
        let resolved = group
            .items
            .get(group.selected)
            .map(|item| item.decision.clone())
            .unwrap_or(RouteDecision::Forward(group.id));
        let mut chain = match resolved {
            RouteDecision::Forward(child) => vec![child],
            _ => Vec::new(),
        };
        chain.push(group.id);
        (resolved, chain)
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
        persist_selection(group);
        Ok(snapshot(group))
    }

    /// Records one probe and atomically re-evaluates the automatic selection.
    pub fn record_urltest_result(
        &self,
        group_id: OutboundId,
        child_id: OutboundId,
        result: Result<Duration, String>,
    ) {
        let Ok(mut state) = self.state.write() else {
            return;
        };
        let Some(index) = state.by_id.get(&group_id).copied() else {
            return;
        };
        let group = &mut state.groups[index];
        if group.kind != OutboundGroupKind::UrlTest {
            return;
        }
        let Some(item) = group.items.iter_mut().find(|item| item.id == child_id) else {
            return;
        };
        item.tested_at = now_millis();
        match result {
            Ok(delay) => {
                item.delay_ms = Some(delay.as_millis().min(u32::MAX as u128) as u32);
                item.last_success_at = Some(item.tested_at);
                item.consecutive_failures = 0;
                item.last_error = None;
            }
            Err(error) => {
                item.consecutive_failures = item.consecutive_failures.saturating_add(1);
                item.last_error = Some(error);
            }
        }
        let current = group.items.get(group.selected);
        let current_healthy = current.is_some_and(|v| {
            v.consecutive_failures < group.failure_threshold && v.delay_ms.is_some()
        });
        let best = group
            .items
            .iter()
            .enumerate()
            .filter(|(_, v)| v.consecutive_failures < group.failure_threshold)
            .filter_map(|(i, v)| Some((i, v.delay_ms?)))
            .min_by_key(|(_, delay)| *delay);
        if let Some((best_index, best_delay)) = best {
            let switch = !current_healthy
                || current.and_then(|v| v.delay_ms).is_some_and(|delay| {
                    best_delay.saturating_add(group.tolerance_ms as u32) < delay
                });
            if switch && group.selected != best_index {
                group.selected = best_index;
                persist_selection(group);
            }
        }
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn persist_selection(group: &GroupState) {
    let (Some(path), Some(item)) = (&group.cache_path, group.items.get(group.selected)) else {
        return;
    };
    let _ = persist_text(path, &item.tag);
}

fn persist_text(path: &Path, value: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, value)?;
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(_) if path.exists() => {
            std::fs::remove_file(path)?;
            std::fs::rename(temporary, path)
        }
        Err(error) => Err(error),
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
                url_test_time: item.tested_at,
                url_test_delay: item.delay_ms,
                consecutive_failures: item.consecutive_failures,
                last_error: item.last_error.clone(),
                last_success_time: item.last_success_at,
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
        CompiledOutboundKind::WireGuard(..) => "wireguard",
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
                        cache_path: None,
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
                        url: "https://www.gstatic.com/generate_204"
                            .parse()
                            .expect("valid test URL"),
                        interval_seconds: 300,
                        tolerance_ms: 50,
                        timeout_seconds: 10,
                        concurrency: 4,
                        failure_threshold: 2,
                        cache_path: None,
                        interrupt_exist_connections: false,
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
        registry.record_urltest_result(automatic, direct, Ok(Duration::from_millis(42)));
        let snapshot = registry.list().remove(0);
        assert_eq!(snapshot.items[0].url_test_delay, Some(42));
        assert!(snapshot.items[0].last_success_time.is_some());
        registry.record_urltest_result(automatic, direct, Err("connection refused".into()));
        let snapshot = registry.list().remove(0);
        assert_eq!(snapshot.items[0].consecutive_failures, 1);
        assert_eq!(
            snapshot.items[0].last_error.as_deref(),
            Some("connection refused")
        );
    }

    fn outbound_id(value: u64) -> OutboundId {
        OutboundId::new(NonZeroU64::new(value).expect("non-zero outbound id"))
    }
}
