//! Transport-neutral application service shared by the gRPC and Clash APIs.

use rustbox_config::{
    InboundConfigKind, OutboundConfigKind, RouteActionConfig, RouteMatcherConfig, RouteRuleConfig,
    SourceConfig,
};
use rustbox_control::{ControlState, EngineCommand, OutboundGroupRegistry, RuleSetRegistry};
use rustbox_observability::ObservabilityStore;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub struct ControlPlaneHandle {
    observability: Arc<ObservabilityStore>,
    control: Arc<Mutex<ControlState>>,
    command_tx: Option<mpsc::Sender<ControlCommand>>,
    outbound_groups: Arc<RwLock<Arc<OutboundGroupRegistry>>>,
    rule_sets: Arc<RwLock<Arc<RuleSetRegistry>>>,
    catalog: Arc<RwLock<Arc<ControlCatalog>>>,
    outbound_probe: Arc<RwLock<Option<Arc<dyn OutboundProbe>>>>,
}

impl ControlPlaneHandle {
    pub fn new(observability: Arc<ObservabilityStore>, control: Arc<Mutex<ControlState>>) -> Self {
        Self {
            observability,
            control,
            command_tx: None,
            outbound_groups: Arc::new(RwLock::new(Arc::new(OutboundGroupRegistry::default()))),
            rule_sets: Arc::new(RwLock::new(Arc::new(RuleSetRegistry::default()))),
            catalog: Arc::new(RwLock::new(Arc::new(ControlCatalog::default()))),
            outbound_probe: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_command_sender(mut self, command_tx: mpsc::Sender<ControlCommand>) -> Self {
        self.command_tx = Some(command_tx);
        self
    }

    pub fn observability(&self) -> Arc<ObservabilityStore> {
        Arc::clone(&self.observability)
    }

    pub fn control(&self) -> Arc<Mutex<ControlState>> {
        Arc::clone(&self.control)
    }

    pub fn command_sender(&self) -> Option<mpsc::Sender<ControlCommand>> {
        self.command_tx.clone()
    }

    pub fn outbound_groups(&self) -> Result<Arc<OutboundGroupRegistry>, &'static str> {
        self.outbound_groups
            .read()
            .map(|value| value.clone())
            .map_err(|_| "outbound group state lock is poisoned")
    }

    pub fn replace_outbound_groups(&self, groups: Arc<OutboundGroupRegistry>) {
        if let Ok(mut current) = self.outbound_groups.write() {
            *current = groups;
        }
    }

    pub fn rule_sets(&self) -> Result<Arc<RuleSetRegistry>, &'static str> {
        self.rule_sets
            .read()
            .map(|value| value.clone())
            .map_err(|_| "rule-set state lock is poisoned")
    }

    pub fn replace_rule_sets(&self, rule_sets: Arc<RuleSetRegistry>) {
        if let Ok(mut current) = self.rule_sets.write() {
            *current = rule_sets;
        }
    }

    pub fn catalog(&self) -> Result<Arc<ControlCatalog>, &'static str> {
        self.catalog
            .read()
            .map(|value| value.clone())
            .map_err(|_| "control catalog lock is poisoned")
    }

    pub fn replace_catalog(&self, catalog: Arc<ControlCatalog>) {
        if let Ok(mut current) = self.catalog.write() {
            *current = catalog;
        }
    }

    pub fn replace_outbound_probe(&self, probe: Arc<dyn OutboundProbe>) {
        if let Ok(mut current) = self.outbound_probe.write() {
            *current = Some(probe);
        }
    }

    pub fn outbound_probe(&self) -> Result<Arc<dyn OutboundProbe>, &'static str> {
        self.outbound_probe
            .read()
            .map_err(|_| "outbound probe lock is poisoned")?
            .clone()
            .ok_or("outbound probe service is unavailable")
    }

    pub fn send_detached(&self, command: EngineCommand) -> Result<(), SendCommandError> {
        self.command_tx
            .as_ref()
            .ok_or(SendCommandError::Closed)?
            .try_send(ControlCommand::detached(command))
            .map_err(SendCommandError::from)
    }

    pub async fn execute(&self, command: EngineCommand) -> Result<bool, ExecuteCommandError> {
        let (command, response) = ControlCommand::acknowledged(command);
        self.command_tx
            .as_ref()
            .ok_or(ExecuteCommandError::Send(SendCommandError::Closed))?
            .try_send(command)
            .map_err(SendCommandError::from)
            .map_err(ExecuteCommandError::Send)?;
        response
            .await
            .map_err(|_| ExecuteCommandError::Unavailable)?
            .map_err(ExecuteCommandError::Rejected)
    }
}

pub struct ControlCommand {
    pub command: EngineCommand,
    response: Option<oneshot::Sender<Result<bool, String>>>,
}

impl ControlCommand {
    pub fn detached(command: EngineCommand) -> Self {
        Self {
            command,
            response: None,
        }
    }

    pub fn acknowledged(command: EngineCommand) -> (Self, oneshot::Receiver<Result<bool, String>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                command,
                response: Some(tx),
            },
            rx,
        )
    }

    pub fn respond(mut self, result: Result<bool, String>) {
        if let Some(response) = self.response.take() {
            let _ = response.send(result);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendCommandError {
    Full,
    Closed,
}

impl From<mpsc::error::TrySendError<ControlCommand>> for SendCommandError {
    fn from(value: mpsc::error::TrySendError<ControlCommand>) -> Self {
        match value {
            mpsc::error::TrySendError::Full(_) => Self::Full,
            mpsc::error::TrySendError::Closed(_) => Self::Closed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteCommandError {
    Send(SendCommandError),
    Unavailable,
    Rejected(String),
}

pub type ProbeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

pub trait OutboundProbe: Send + Sync {
    fn probe<'a>(&'a self, tag: &'a str, url: &'a str, timeout: Duration) -> ProbeFuture<'a, u32>;

    fn probe_group<'a>(
        &'a self,
        tag: &'a str,
        url: &'a str,
        timeout: Duration,
    ) -> ProbeFuture<'a, BTreeMap<String, u32>>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlCatalog {
    pub inbounds: Vec<InboundCatalogEntry>,
    pub outbounds: Vec<OutboundCatalogEntry>,
    pub rules: Vec<RuleCatalogEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundCatalogEntry {
    pub tag: String,
    pub kind: String,
    pub listen: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundCatalogEntry {
    pub tag: String,
    pub kind: String,
    pub udp: bool,
    pub children: Vec<String>,
    pub test_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleCatalogEntry {
    pub index: usize,
    pub kind: String,
    pub payload: String,
    pub outbound: String,
    pub size: i64,
}

impl ControlCatalog {
    pub fn from_source(source: &SourceConfig) -> Self {
        let mut rules = Vec::new();
        if let Some(dns) = &source.dns {
            for target in &dns.hijack {
                rules.push(RuleCatalogEntry {
                    index: rules.len(),
                    kind: "DST-PORT".to_string(),
                    payload: target.endpoint.port.to_string(),
                    outbound: "DNS".to_string(),
                    size: -1,
                });
            }
        }
        let offset = rules.len();
        rules.extend(
            source
                .routes
                .iter()
                .enumerate()
                .map(|(index, rule)| rule_entry(offset + index, rule)),
        );
        Self {
            inbounds: source.inbounds.iter().map(inbound_entry).collect(),
            outbounds: source.outbounds.iter().map(outbound_entry).collect(),
            rules,
        }
    }
}

fn inbound_entry(value: &rustbox_config::InboundConfig) -> InboundCatalogEntry {
    let (kind, listen) = match &value.kind {
        InboundConfigKind::Mixed { listen, .. } => ("mixed", Some(listen.to_string())),
        InboundConfigKind::HttpConnect { listen, .. } => ("http", Some(listen.to_string())),
        InboundConfigKind::Socks5 { listen, .. } => ("socks", Some(listen.to_string())),
        InboundConfigKind::AnyTls { listen, .. } => ("anytls", Some(listen.to_string())),
        InboundConfigKind::Tun(_) => ("tun", None),
        InboundConfigKind::Transparent(config) => ("transparent", Some(config.listen.to_string())),
    };
    InboundCatalogEntry {
        tag: value.id.clone(),
        kind: kind.to_string(),
        listen,
    }
}

fn outbound_entry(value: &rustbox_config::OutboundConfig) -> OutboundCatalogEntry {
    let (kind, udp, children, test_url) = match &value.kind {
        OutboundConfigKind::Direct => ("Direct", true, Vec::new(), None),
        OutboundConfigKind::Block => ("Reject", true, Vec::new(), None),
        OutboundConfigKind::Socks5 { .. } => ("Socks5", true, Vec::new(), None),
        OutboundConfigKind::Http { .. } => ("Http", false, Vec::new(), None),
        OutboundConfigKind::Shadowsocks { .. } => ("Shadowsocks", true, Vec::new(), None),
        OutboundConfigKind::Selector { outbounds, .. } => {
            ("Selector", true, outbounds.clone(), None)
        }
        OutboundConfigKind::UrlTest { outbounds, url, .. } => {
            ("URLTest", true, outbounds.clone(), Some(url.clone()))
        }
        OutboundConfigKind::Vmess { .. } => ("VMess", true, Vec::new(), None),
        OutboundConfigKind::Vless { .. } => ("VLESS", true, Vec::new(), None),
        OutboundConfigKind::Trojan { .. } => ("Trojan", true, Vec::new(), None),
        OutboundConfigKind::Hysteria2 { .. } => ("Hysteria2", true, Vec::new(), None),
        OutboundConfigKind::Naive { .. } => ("Naive", false, Vec::new(), None),
        OutboundConfigKind::Tuic { .. } => ("TUIC", true, Vec::new(), None),
        OutboundConfigKind::WireGuard { .. } => ("WireGuard", true, Vec::new(), None),
        OutboundConfigKind::ShadowTls { .. } => ("ShadowTLS", false, Vec::new(), None),
        OutboundConfigKind::AnyTls { .. } => ("AnyTLS", true, Vec::new(), None),
    };
    OutboundCatalogEntry {
        tag: value.id.clone(),
        kind: kind.to_string(),
        udp,
        children,
        test_url,
    }
}

fn rule_entry(index: usize, rule: &RouteRuleConfig) -> RuleCatalogEntry {
    let (kind, payload, outbound) = match rule {
        RouteRuleConfig::Default { outbound } => {
            ("MATCH".to_string(), String::new(), outbound.clone())
        }
        RouteRuleConfig::RejectDefault { .. } => {
            ("MATCH".to_string(), String::new(), "REJECT".to_string())
        }
        RouteRuleConfig::Rule { matcher, action } => {
            let (kind, payload) = matcher_projection(matcher);
            (kind, payload, action_projection(action))
        }
        RouteRuleConfig::Logical { action, .. } => (
            "LOGICAL".to_string(),
            String::new(),
            action_projection(action),
        ),
    };
    RuleCatalogEntry {
        index,
        kind,
        payload,
        outbound,
        size: -1,
    }
}

fn action_projection(action: &RouteActionConfig) -> String {
    match action {
        RouteActionConfig::Outbound(tag) => tag.clone(),
        RouteActionConfig::Reject(_) => "REJECT".to_string(),
        RouteActionConfig::HijackDns => "DNS".to_string(),
        RouteActionConfig::Options(_) => "ROUTE-OPTIONS".to_string(),
        RouteActionConfig::Resolve(_) => "RESOLVE".to_string(),
    }
}

fn matcher_projection(matcher: &RouteMatcherConfig) -> (String, String) {
    let RouteMatcherConfig::Conditions(value) = matcher else {
        return ("LOGICAL".to_string(), String::new());
    };
    let candidates = [
        ("DOMAIN", value.domain.first().cloned()),
        ("DOMAIN-SUFFIX", value.domain_suffix.first().cloned()),
        ("DOMAIN-KEYWORD", value.domain_keyword.first().cloned()),
        ("DOMAIN-REGEX", value.domain_regex.first().cloned()),
        ("IP-CIDR", value.ip_cidr.first().map(ToString::to_string)),
        (
            "SRC-IP-CIDR",
            value.source_ip_cidr.first().map(ToString::to_string),
        ),
        ("DST-PORT", value.port.first().map(ToString::to_string)),
        (
            "SRC-PORT",
            value.source_port.first().map(ToString::to_string),
        ),
        ("RULE-SET", value.rule_set.first().cloned()),
        ("PROCESS-NAME", value.process_name.first().cloned()),
        ("PROCESS-PATH", value.process_path.first().cloned()),
        ("INBOUND", value.inbound.first().cloned()),
    ];
    candidates
        .into_iter()
        .find_map(|(kind, payload)| payload.map(|payload| (kind.to_string(), payload)))
        .unwrap_or_else(|| ("MATCH".to_string(), String::new()))
}
