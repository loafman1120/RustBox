//! gRPC control API over control snapshots and `ObservabilityStore`.
//!
//! This crate sits above the portable core. It translates gRPC requests into
//! value snapshots and coarse control commands without exposing kernel internals.

use rustbox_control::{ControlState, EngineCommand, EngineSnapshot, EngineState};
use rustbox_kernel::{Event, EventKind, EventLevel};
use rustbox_observability::{
    ConnectionState, ConnectionStats, MetricsSnapshot, ObservabilityQuery, ObservabilitySnapshot,
    ObservabilityStore,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tonic::metadata::MetadataMap;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub mod rustbox_control_v1 {
    tonic::include_proto!("rustbox.control.v1");
}

use rustbox_control_v1 as pb;

const DEFAULT_MAX_EVENTS_PER_QUERY: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlApiConfig {
    pub listen: SocketAddr,
    pub auth: AuthPolicy,
    pub max_events_per_query: usize,
}

impl ControlApiConfig {
    pub fn validate(&self) -> Result<(), ControlApiConfigError> {
        self.auth.validate()?;
        if self.max_events_per_query == 0 {
            return Err(ControlApiConfigError::new(
                "max_events_per_query must be greater than zero",
            ));
        }
        if !self.listen.ip().is_loopback() && !self.auth.has_any_token() {
            return Err(ControlApiConfigError::new(
                "control API must configure a bearer token before listening on a non-loopback address",
            ));
        }
        Ok(())
    }
}

impl Default for ControlApiConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 19090)),
            auth: AuthPolicy::disabled(),
            max_events_per_query: DEFAULT_MAX_EVENTS_PER_QUERY,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPolicy {
    observe_token: Option<String>,
    control_token: Option<String>,
}

impl AuthPolicy {
    pub fn disabled() -> Self {
        Self {
            observe_token: None,
            control_token: None,
        }
    }

    pub fn bearer_token(token: impl Into<String>) -> Self {
        let token = token.into();
        Self {
            observe_token: Some(token.clone()),
            control_token: Some(token),
        }
    }

    pub fn observe_only_token(token: impl Into<String>) -> Self {
        Self {
            observe_token: Some(token.into()),
            control_token: None,
        }
    }

    fn has_any_token(&self) -> bool {
        self.observe_token.is_some() || self.control_token.is_some()
    }

    fn validate(&self) -> Result<(), ControlApiConfigError> {
        if self.observe_token.as_deref().is_some_and(str::is_empty)
            || self.control_token.as_deref().is_some_and(str::is_empty)
        {
            return Err(ControlApiConfigError::new(
                "control API bearer tokens must not be empty",
            ));
        }
        Ok(())
    }

    fn authorize(&self, metadata: &MetadataMap, permission: Permission) -> Result<(), Status> {
        match permission {
            Permission::Observe => {
                if let Some(expected) = self.observe_token.as_ref().or(self.control_token.as_ref())
                {
                    verify_metadata_token(metadata, expected)?;
                }
            }
            Permission::Control => {
                if let Some(expected) = &self.control_token {
                    verify_metadata_token(metadata, expected)?;
                } else if self.observe_token.is_some() {
                    return Err(Status::permission_denied(
                        "control token is not configured for this API",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlApiConfigError {
    pub message: String,
}

impl ControlApiConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ControlApiConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ControlApiConfigError {}

#[derive(Clone)]
pub struct ControlApiState {
    observability: Arc<ObservabilityStore>,
    control: Arc<Mutex<ControlState>>,
    command_tx: Option<mpsc::UnboundedSender<EngineCommand>>,
}

impl ControlApiState {
    pub fn new(observability: Arc<ObservabilityStore>, control: Arc<Mutex<ControlState>>) -> Self {
        Self {
            observability,
            control,
            command_tx: None,
        }
    }

    pub fn with_command_sender(mut self, command_tx: mpsc::UnboundedSender<EngineCommand>) -> Self {
        self.command_tx = Some(command_tx);
        self
    }

    pub fn observability(&self) -> Arc<ObservabilityStore> {
        Arc::clone(&self.observability)
    }

    pub fn control(&self) -> Arc<Mutex<ControlState>> {
        Arc::clone(&self.control)
    }
}

#[derive(Debug)]
pub enum ControlApiError {
    Config(ControlApiConfigError),
    Transport(tonic::transport::Error),
}

impl fmt::Display for ControlApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "invalid control API config: {err}"),
            Self::Transport(err) => write!(f, "control API transport failed: {err}"),
        }
    }
}

impl Error for ControlApiError {}

pub async fn serve_grpc(
    config: ControlApiConfig,
    state: ControlApiState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ControlApiError> {
    config.validate().map_err(ControlApiError::Config)?;

    let native = RustBoxControlService::new(
        state.clone(),
        config.auth.clone(),
        config.max_events_per_query,
    );
    Server::builder()
        .add_service(pb::rust_box_control_server::RustBoxControlServer::new(
            native,
        ))
        .serve_with_shutdown(config.listen, shutdown)
        .await
        .map_err(ControlApiError::Transport)
}

#[derive(Clone)]
pub struct RustBoxControlService {
    state: ControlApiState,
    auth: AuthPolicy,
    max_events_per_query: usize,
}

impl RustBoxControlService {
    pub fn new(state: ControlApiState, auth: AuthPolicy, max_events_per_query: usize) -> Self {
        Self {
            state,
            auth,
            max_events_per_query,
        }
    }

    fn control_snapshot(&self) -> Result<EngineSnapshot, Status> {
        self.state
            .control
            .lock()
            .map_err(|_| Status::internal("control state lock is poisoned"))
            .map(|state| state.snapshot().clone())
    }
}

#[tonic::async_trait]
impl pb::rust_box_control_server::RustBoxControl for RustBoxControlService {
    async fn get_metrics(
        &self,
        request: Request<pb::GetMetricsRequest>,
    ) -> Result<Response<pb::MetricsSnapshot>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        Ok(Response::new(metrics_to_proto(
            self.state.observability.metrics(),
        )))
    }

    async fn list_connections(
        &self,
        request: Request<pb::ListConnectionsRequest>,
    ) -> Result<Response<pb::ListConnectionsResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let connections = self
            .state
            .observability
            .connections()
            .into_iter()
            .map(connection_to_proto)
            .collect();
        Ok(Response::new(pb::ListConnectionsResponse { connections }))
    }

    async fn query_events(
        &self,
        request: Request<pb::QueryEventsRequest>,
    ) -> Result<Response<pb::QueryEventsResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let query = query_from_proto(request.into_inner(), self.max_events_per_query)?;
        let events = self
            .state
            .observability
            .query_events(query)
            .into_iter()
            .map(event_to_proto)
            .collect();
        Ok(Response::new(pb::QueryEventsResponse { events }))
    }

    async fn get_observability_snapshot(
        &self,
        request: Request<pb::GetObservabilitySnapshotRequest>,
    ) -> Result<Response<pb::ObservabilitySnapshot>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        Ok(Response::new(observability_to_proto(
            self.state.observability.snapshot(),
        )))
    }

    async fn get_engine_snapshot(
        &self,
        request: Request<pb::GetEngineSnapshotRequest>,
    ) -> Result<Response<pb::EngineSnapshot>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        Ok(Response::new(engine_to_proto(self.control_snapshot()?)))
    }

    async fn stop(
        &self,
        request: Request<pb::StopRequest>,
    ) -> Result<Response<pb::EngineSnapshot>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let snapshot = {
            let mut state = self
                .state
                .control
                .lock()
                .map_err(|_| Status::internal("control state lock is poisoned"))?;
            state.apply_command(EngineCommand::Stop);
            state.snapshot().clone()
        };

        if let Some(command_tx) = &self.state.command_tx {
            let _ = command_tx.send(EngineCommand::Stop);
        }

        Ok(Response::new(engine_to_proto(snapshot)))
    }
}

#[derive(Clone, Copy)]
enum Permission {
    Observe,
    Control,
}

fn verify_metadata_token(metadata: &MetadataMap, expected: &str) -> Result<(), Status> {
    match metadata_token(metadata) {
        Some(token) if token == expected => Ok(()),
        Some(_) => Err(Status::unauthenticated("invalid control API token")),
        None => Err(Status::unauthenticated("missing control API bearer token")),
    }
}

fn metadata_token(metadata: &MetadataMap) -> Option<&str> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .or_else(|| {
            metadata
                .get("x-rustbox-token")
                .and_then(|value| value.to_str().ok())
        })
}

fn bearer_token(value: &str) -> Option<&str> {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
}

fn query_from_proto(
    request: pb::QueryEventsRequest,
    max_events_per_query: usize,
) -> Result<ObservabilityQuery, Status> {
    let min_level = if request.min_level.is_empty() {
        None
    } else {
        Some(parse_level(&request.min_level)?)
    };
    let limit = if request.limit == 0 {
        max_events_per_query
    } else {
        (request.limit as usize).min(max_events_per_query)
    };

    Ok(ObservabilityQuery {
        min_level,
        target_prefix: none_if_empty(request.target_prefix),
        flow_id: (request.flow_id != 0).then_some(request.flow_id),
        limit: Some(limit),
    })
}

fn parse_level(value: &str) -> Result<EventLevel, Status> {
    match value.to_ascii_lowercase().as_str() {
        "trace" => Ok(EventLevel::Trace),
        "debug" => Ok(EventLevel::Debug),
        "info" => Ok(EventLevel::Info),
        "warn" | "warning" => Ok(EventLevel::Warn),
        "error" => Ok(EventLevel::Error),
        _ => Err(Status::invalid_argument(format!(
            "unknown event level `{value}`"
        ))),
    }
}

fn none_if_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn metrics_to_proto(metrics: MetricsSnapshot) -> pb::MetricsSnapshot {
    pb::MetricsSnapshot {
        services_started: metrics.services_started,
        services_stopped: metrics.services_stopped,
        connections_accepted: metrics.connections_accepted,
        flows_accepted: metrics.flows_accepted,
        flows_active: metrics.flows_active,
        flows_completed: metrics.flows_completed,
        flows_failed: metrics.flows_failed,
        routes_selected: metrics.routes_selected,
        outbound_connect_attempts: metrics.outbound_connect_attempts,
        outbound_connect_successes: metrics.outbound_connect_successes,
        outbound_connect_failures: metrics.outbound_connect_failures,
        inbound_to_outbound_bytes: metrics.inbound_to_outbound_bytes,
        outbound_to_inbound_bytes: metrics.outbound_to_inbound_bytes,
        diagnostics: metrics.diagnostics,
    }
}

fn connection_to_proto(connection: ConnectionStats) -> pb::ConnectionStats {
    pb::ConnectionStats {
        flow_id: connection.flow_id,
        source: connection.source,
        destination: connection.destination,
        network: connection.network,
        state: match connection.state {
            ConnectionState::Active => pb::ConnectionState::Active as i32,
            ConnectionState::Completed => pb::ConnectionState::Completed as i32,
            ConnectionState::Failed => pb::ConnectionState::Failed as i32,
        },
        inbound_to_outbound_bytes: connection.inbound_to_outbound_bytes,
        outbound_to_inbound_bytes: connection.outbound_to_inbound_bytes,
        outcome: connection.outcome.unwrap_or_default(),
        error: connection.error.unwrap_or_default(),
    }
}

fn observability_to_proto(snapshot: ObservabilitySnapshot) -> pb::ObservabilitySnapshot {
    pb::ObservabilitySnapshot {
        metrics: Some(metrics_to_proto(snapshot.metrics)),
        connections: snapshot
            .connections
            .into_iter()
            .map(connection_to_proto)
            .collect(),
        recent_events: snapshot
            .recent_events
            .into_iter()
            .map(event_to_proto)
            .collect(),
    }
}

fn event_to_proto(event: Event) -> pb::Event {
    let (kind, message, attributes) = event_kind_to_proto(event.kind);
    pb::Event {
        level: format_level(event.level).to_string(),
        target: event.target.0,
        flow_id: event.flow_id.map(|id| id.get()).unwrap_or_default(),
        kind,
        message,
        attributes,
    }
}

fn event_kind_to_proto(kind: EventKind) -> (String, String, HashMap<String, String>) {
    let mut attributes = HashMap::new();
    let mut insert = |key: &str, value: String| {
        attributes.insert(key.to_string(), value);
    };

    let (kind, message) = match kind {
        EventKind::ServiceStarting { service } => {
            insert("service", service);
            ("service_starting", String::new())
        }
        EventKind::ServiceStarted { service } => {
            insert("service", service);
            ("service_started", String::new())
        }
        EventKind::ServiceStopping { service } => {
            insert("service", service);
            ("service_stopping", String::new())
        }
        EventKind::ServiceStopped { service } => {
            insert("service", service);
            ("service_stopped", String::new())
        }
        EventKind::ConnectionAccepted { listener, peer } => {
            insert("listener", listener);
            insert("peer", peer);
            ("connection_accepted", String::new())
        }
        EventKind::FlowAccepted {
            source,
            destination,
            network,
        } => {
            insert("source", source);
            insert("destination", destination);
            insert("network", network);
            ("flow_accepted", String::new())
        }
        EventKind::RouteSelected { decision } => {
            insert("decision", decision);
            ("route_selected", String::new())
        }
        EventKind::OutboundConnecting { outbound, target } => {
            insert("outbound", outbound);
            insert("target", target);
            ("outbound_connecting", String::new())
        }
        EventKind::OutboundConnected { outbound, target } => {
            insert("outbound", outbound);
            insert("target", target);
            ("outbound_connected", String::new())
        }
        EventKind::OutboundFailed {
            outbound,
            target,
            error,
        } => {
            insert("outbound", outbound);
            insert("target", target);
            ("outbound_failed", error)
        }
        EventKind::FlowCompleted { outcome } => {
            insert("outcome", outcome);
            ("flow_completed", String::new())
        }
        EventKind::TrafficRecorded {
            inbound_to_outbound_bytes,
            outbound_to_inbound_bytes,
        } => {
            insert(
                "inbound_to_outbound_bytes",
                inbound_to_outbound_bytes.to_string(),
            );
            insert(
                "outbound_to_inbound_bytes",
                outbound_to_inbound_bytes.to_string(),
            );
            ("traffic_recorded", String::new())
        }
        EventKind::FlowFailed { error } => ("flow_failed", error),
        EventKind::Diagnostic(message) => ("diagnostic", message),
    };

    (kind.to_string(), message, attributes)
}

fn engine_to_proto(snapshot: EngineSnapshot) -> pb::EngineSnapshot {
    pb::EngineSnapshot {
        state: match snapshot.state {
            EngineState::Created => pb::EngineState::Created as i32,
            EngineState::Prepared => pb::EngineState::Prepared as i32,
            EngineState::Running => pb::EngineState::Running as i32,
            EngineState::Stopping => pb::EngineState::Stopping as i32,
            EngineState::Stopped => pb::EngineState::Stopped as i32,
            EngineState::Failed => pb::EngineState::Failed as i32,
        },
        generation: snapshot.generation,
        inbound_count: snapshot.inbound_count as u64,
        outbound_count: snapshot.outbound_count as u64,
    }
}

fn format_level(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::rust_box_control_server::RustBoxControl;
    use rustbox_kernel::{Event, ObservabilitySink};
    use rustbox_types::FlowId;
    use std::num::NonZeroU64;
    use tonic::Code;

    #[test]
    fn rejects_public_listen_without_token() {
        let config = ControlApiConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], 19090)),
            ..ControlApiConfig::default()
        };

        let error = config
            .validate()
            .expect_err("reject public unauthenticated API");

        assert!(error.message.contains("bearer token"));
    }

    #[tokio::test]
    async fn native_metrics_requires_bearer_token() {
        let service = RustBoxControlService::new(
            sample_state(None),
            AuthPolicy::bearer_token("secret"),
            DEFAULT_MAX_EVENTS_PER_QUERY,
        );

        let error = service
            .get_metrics(Request::new(pb::GetMetricsRequest {}))
            .await
            .expect_err("reject missing token");
        assert_eq!(error.code(), Code::Unauthenticated);

        let mut request = Request::new(pb::GetMetricsRequest {});
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret".parse().expect("metadata"));

        let response = service
            .get_metrics(request)
            .await
            .expect("accept bearer token")
            .into_inner();
        assert_eq!(response.flows_completed, 1);
    }

    #[tokio::test]
    async fn query_events_caps_result_limit() {
        let service = RustBoxControlService::new(sample_state(None), AuthPolicy::disabled(), 1);

        let response = service
            .query_events(Request::new(pb::QueryEventsRequest {
                min_level: String::new(),
                target_prefix: "rustbox.kernel".to_string(),
                flow_id: 0,
                limit: 10,
            }))
            .await
            .expect("query")
            .into_inner();

        assert_eq!(response.events.len(), 1);
    }

    #[tokio::test]
    async fn stop_updates_state_and_sends_command() {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let service = RustBoxControlService::new(
            sample_state(Some(command_tx)),
            AuthPolicy::disabled(),
            DEFAULT_MAX_EVENTS_PER_QUERY,
        );

        let response = service
            .stop(Request::new(pb::StopRequest {}))
            .await
            .expect("stop")
            .into_inner();

        assert_eq!(response.state, pb::EngineState::Stopping as i32);
        assert_eq!(
            command_rx.recv().await.expect("command"),
            EngineCommand::Stop
        );
    }

    fn sample_state(command_tx: Option<mpsc::UnboundedSender<EngineCommand>>) -> ControlApiState {
        let store = Arc::new(ObservabilityStore::default());
        let flow_id = FlowId::new(NonZeroU64::new(7).expect("non-zero"));
        store_event(
            &store,
            Event::new(
                EventLevel::Info,
                "rustbox.kernel.flow",
                Some(flow_id),
                EventKind::FlowAccepted {
                    source: "127.0.0.1:1000".to_string(),
                    destination: "example.test:443".to_string(),
                    network: "Tcp".to_string(),
                },
            ),
        );
        store_event(
            &store,
            Event::new(
                EventLevel::Debug,
                "rustbox.kernel.traffic",
                Some(flow_id),
                EventKind::TrafficRecorded {
                    inbound_to_outbound_bytes: 4,
                    outbound_to_inbound_bytes: 6,
                },
            ),
        );
        store_event(
            &store,
            Event::new(
                EventLevel::Info,
                "rustbox.kernel.flow",
                Some(flow_id),
                EventKind::FlowCompleted {
                    outcome: "Forwarded".to_string(),
                },
            ),
        );

        let control = Arc::new(Mutex::new(ControlState::new(EngineSnapshot {
            state: EngineState::Running,
            generation: 1,
            inbound_count: 1,
            outbound_count: 1,
        })));
        let state = ControlApiState::new(store, control);
        if let Some(command_tx) = command_tx {
            state.with_command_sender(command_tx)
        } else {
            state
        }
    }

    fn store_event(store: &ObservabilityStore, event: Event) {
        block_on_ready(store.emit(event));
    }

    fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
        use core::pin::pin;
        use core::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
