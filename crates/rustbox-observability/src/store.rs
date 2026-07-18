use super::*;
use crate::format::level_at_least;

/// 可由控制面、嵌入宿主、HTTP/gRPC API 查询的观测状态。
#[derive(Debug)]
pub struct ObservabilityStore {
    inner: Mutex<ObservabilityStoreInner>,
    event_limit: usize,
    connection_limit: usize,
    event_tx: tokio::sync::broadcast::Sender<Event>,
}

impl ObservabilityStore {
    pub fn new(event_limit: usize) -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(event_limit.max(1));
        Self {
            inner: Mutex::new(ObservabilityStoreInner::default()),
            event_limit,
            connection_limit: event_limit,
            event_tx,
        }
    }

    pub fn snapshot(&self) -> ObservabilitySnapshot {
        let inner = self.inner.lock().expect("observability store lock");
        ObservabilitySnapshot {
            metrics: inner.metrics.clone(),
            connections: inner.connections.values().cloned().collect(),
            recent_events: inner.events.iter().cloned().collect(),
        }
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        self.inner
            .lock()
            .expect("observability store lock")
            .metrics
            .clone()
    }

    pub fn connections(&self) -> Vec<ConnectionStats> {
        self.inner
            .lock()
            .expect("observability store lock")
            .connections
            .values()
            .cloned()
            .collect()
    }

    pub fn active_connections(&self) -> Vec<ConnectionStats> {
        self.connections()
            .into_iter()
            .filter(|connection| connection.state == ConnectionState::Active)
            .collect()
    }

    pub fn connection(&self, flow_id: u64) -> Option<ConnectionStats> {
        self.inner
            .lock()
            .expect("observability store lock")
            .connections
            .get(&flow_id)
            .cloned()
    }

    pub fn query_events(&self, query: &ObservabilityQuery) -> Vec<Event> {
        let inner = self.inner.lock().expect("observability store lock");
        let mut events = inner
            .events
            .iter()
            .filter(|event| query.matches(event))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(limit) = query.limit
            && events.len() > limit
        {
            events.drain(0..events.len() - limit);
        }
        events
    }

    /// Subscribe to new structured events without polling the retained ring buffer.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.event_tx.subscribe()
    }

    pub fn traffic(&self) -> TrafficSnapshot {
        let inner = self.inner.lock().expect("observability store lock");
        TrafficSnapshot {
            uplink_bytes: inner.metrics.inbound_to_outbound_bytes,
            downlink_bytes: inner.metrics.outbound_to_inbound_bytes,
            inbounds: inner.inbound_traffic.clone(),
            outbounds: inner.outbound_traffic.clone(),
        }
    }

    fn record(&self, event: Event) {
        let mut inner = self.inner.lock().expect("observability store lock");
        inner.apply_event(&event);
        if let Some(flow_id) = matches!(
            event.kind,
            EventKind::FlowCompleted { .. } | EventKind::FlowFailed { .. }
        )
        .then(|| event.flow_id.map(|id| id.get()))
        .flatten()
        {
            inner.completed_connections.push_back(flow_id);
        }
        while inner.completed_connections.len() > self.connection_limit {
            if let Some(flow_id) = inner.completed_connections.pop_front() {
                inner.connections.remove(&flow_id);
            }
        }
        inner.events.push_back(event.clone());
        if inner.events.len() > self.event_limit {
            inner.events.pop_front();
        }
        drop(inner);
        let _ = self.event_tx.send(event);
    }
}

impl Default for ObservabilityStore {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl ObservabilitySink for ObservabilityStore {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.record(event);
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservabilitySnapshot {
    pub metrics: MetricsSnapshot,
    pub connections: Vec<ConnectionStats>,
    pub recent_events: Vec<Event>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    pub services_started: u64,
    pub services_stopped: u64,
    pub connections_accepted: u64,
    pub flows_accepted: u64,
    pub flows_active: u64,
    pub flows_completed: u64,
    pub flows_failed: u64,
    pub routes_selected: u64,
    pub outbound_connect_attempts: u64,
    pub outbound_connect_successes: u64,
    pub outbound_connect_failures: u64,
    pub inbound_to_outbound_bytes: u64,
    pub outbound_to_inbound_bytes: u64,
    pub diagnostics: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrafficSnapshot {
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub inbounds: HashMap<String, TagTraffic>,
    pub outbounds: HashMap<String, TagTraffic>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TagTraffic {
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionStats {
    pub flow_id: u64,
    pub source: String,
    pub destination: String,
    pub network: String,
    pub state: ConnectionState,
    pub inbound_to_outbound_bytes: u64,
    pub outbound_to_inbound_bytes: u64,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub inbound: String,
    pub outbound: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Active,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservabilityQuery {
    pub min_level: Option<EventLevel>,
    pub target_prefix: Option<String>,
    pub flow_id: Option<u64>,
    pub limit: Option<usize>,
}

impl ObservabilityQuery {
    fn matches(&self, event: &Event) -> bool {
        if let Some(min_level) = self.min_level
            && !level_at_least(event.level, min_level)
        {
            return false;
        }
        if let Some(prefix) = &self.target_prefix
            && !event.target.0.starts_with(prefix)
        {
            return false;
        }
        if let Some(flow_id) = self.flow_id
            && event.flow_id.map(|id| id.get()) != Some(flow_id)
        {
            return false;
        }
        true
    }
}

#[derive(Debug, Default)]
struct ObservabilityStoreInner {
    metrics: MetricsSnapshot,
    connections: HashMap<u64, ConnectionStats>,
    events: std::collections::VecDeque<Event>,
    completed_connections: std::collections::VecDeque<u64>,
    inbound_traffic: HashMap<String, TagTraffic>,
    outbound_traffic: HashMap<String, TagTraffic>,
}

impl ObservabilityStoreInner {
    fn apply_event(&mut self, event: &Event) {
        match &event.kind {
            EventKind::ServiceStarted { .. } => {
                self.metrics.services_started = self.metrics.services_started.saturating_add(1);
            }
            EventKind::ServiceStopped { .. } => {
                self.metrics.services_stopped = self.metrics.services_stopped.saturating_add(1);
            }
            EventKind::ConnectionAccepted { .. } => {
                self.metrics.connections_accepted =
                    self.metrics.connections_accepted.saturating_add(1);
            }
            EventKind::FlowAccepted {
                source,
                destination,
                network,
                inbound,
            } => {
                self.metrics.flows_accepted = self.metrics.flows_accepted.saturating_add(1);
                self.metrics.flows_active = self.metrics.flows_active.saturating_add(1);
                if let Some(flow_id) = event.flow_id.map(|id| id.get()) {
                    self.connections.insert(
                        flow_id,
                        ConnectionStats {
                            flow_id,
                            source: source.clone(),
                            destination: destination.clone(),
                            network: network.clone(),
                            state: ConnectionState::Active,
                            inbound_to_outbound_bytes: 0,
                            outbound_to_inbound_bytes: 0,
                            outcome: None,
                            error: None,
                            inbound: inbound.clone(),
                            outbound: None,
                        },
                    );
                }
            }
            EventKind::RouteSelected { outbound, .. } => {
                self.metrics.routes_selected = self.metrics.routes_selected.saturating_add(1);
                if let Some(connection) = event
                    .flow_id
                    .map(|id| id.get())
                    .and_then(|flow_id| self.connections.get_mut(&flow_id))
                {
                    connection.outbound = outbound.clone();
                }
            }
            EventKind::OutboundConnecting { .. } => {
                self.metrics.outbound_connect_attempts =
                    self.metrics.outbound_connect_attempts.saturating_add(1);
            }
            EventKind::OutboundConnected { .. } => {
                self.metrics.outbound_connect_successes =
                    self.metrics.outbound_connect_successes.saturating_add(1);
            }
            EventKind::OutboundFailed { .. } => {
                self.metrics.outbound_connect_failures =
                    self.metrics.outbound_connect_failures.saturating_add(1);
            }
            EventKind::TrafficRecorded {
                inbound_to_outbound_bytes,
                outbound_to_inbound_bytes,
            } => {
                self.metrics.inbound_to_outbound_bytes = self
                    .metrics
                    .inbound_to_outbound_bytes
                    .saturating_add(*inbound_to_outbound_bytes);
                self.metrics.outbound_to_inbound_bytes = self
                    .metrics
                    .outbound_to_inbound_bytes
                    .saturating_add(*outbound_to_inbound_bytes);
                if let Some(connection) = event
                    .flow_id
                    .map(|id| id.get())
                    .and_then(|flow_id| self.connections.get_mut(&flow_id))
                {
                    connection.inbound_to_outbound_bytes = connection
                        .inbound_to_outbound_bytes
                        .saturating_add(*inbound_to_outbound_bytes);
                    connection.outbound_to_inbound_bytes = connection
                        .outbound_to_inbound_bytes
                        .saturating_add(*outbound_to_inbound_bytes);
                    let inbound = self
                        .inbound_traffic
                        .entry(connection.inbound.clone())
                        .or_default();
                    inbound.uplink_bytes = inbound
                        .uplink_bytes
                        .saturating_add(*inbound_to_outbound_bytes);
                    inbound.downlink_bytes = inbound
                        .downlink_bytes
                        .saturating_add(*outbound_to_inbound_bytes);
                    if let Some(outbound_tag) = &connection.outbound {
                        let outbound = self
                            .outbound_traffic
                            .entry(outbound_tag.clone())
                            .or_default();
                        outbound.uplink_bytes = outbound
                            .uplink_bytes
                            .saturating_add(*inbound_to_outbound_bytes);
                        outbound.downlink_bytes = outbound
                            .downlink_bytes
                            .saturating_add(*outbound_to_inbound_bytes);
                    }
                }
            }
            EventKind::FlowCompleted { outcome } => {
                self.metrics.flows_completed = self.metrics.flows_completed.saturating_add(1);
                self.metrics.flows_active = self.metrics.flows_active.saturating_sub(1);
                if let Some(connection) = event
                    .flow_id
                    .map(|id| id.get())
                    .and_then(|flow_id| self.connections.get_mut(&flow_id))
                {
                    connection.state = ConnectionState::Completed;
                    connection.outcome = Some(outcome.clone());
                }
            }
            EventKind::FlowFailed { error } => {
                self.metrics.flows_failed = self.metrics.flows_failed.saturating_add(1);
                self.metrics.flows_active = self.metrics.flows_active.saturating_sub(1);
                if let Some(connection) = event
                    .flow_id
                    .map(|id| id.get())
                    .and_then(|flow_id| self.connections.get_mut(&flow_id))
                {
                    connection.state = ConnectionState::Failed;
                    connection.error = Some(error.clone());
                }
            }
            EventKind::Diagnostic(_) => {
                self.metrics.diagnostics = self.metrics.diagnostics.saturating_add(1);
            }
            EventKind::ServiceStarting { .. } | EventKind::ServiceStopping { .. } => {}
        }
    }
}
