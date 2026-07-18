//! gRPC control API over control snapshots and `ObservabilityStore`.
//!
//! This crate sits above the portable core. It translates gRPC requests into
//! value snapshots and coarse control commands without exposing kernel internals.

use rustbox_control::{
    ControlState, EngineCommand, EngineSnapshot, EngineState, OutboundGroupKind,
    OutboundGroupRegistry, OutboundGroupSnapshot, RuleSetRegistry, RuleSetState,
    SelectOutboundError,
};
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
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Duration};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::metadata::MetadataMap;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub mod rustbox_control_v1 {
    tonic::include_proto!("rustbox.control.v1");
}

pub mod daemon {
    tonic::include_proto!("daemon");
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
    command_tx: Option<mpsc::Sender<ControlCommand>>,
    outbound_groups: Arc<RwLock<Arc<OutboundGroupRegistry>>>,
    rule_sets: Arc<RwLock<Arc<RuleSetRegistry>>>,
    started_at: Instant,
}

impl ControlApiState {
    pub fn new(observability: Arc<ObservabilityStore>, control: Arc<Mutex<ControlState>>) -> Self {
        Self {
            observability,
            control,
            command_tx: None,
            outbound_groups: Arc::new(RwLock::new(Arc::new(OutboundGroupRegistry::default()))),
            rule_sets: Arc::new(RwLock::new(Arc::new(RuleSetRegistry::default()))),
            started_at: Instant::now(),
        }
    }

    pub fn with_command_sender(mut self, command_tx: mpsc::Sender<ControlCommand>) -> Self {
        self.command_tx = Some(command_tx);
        self
    }

    pub fn with_outbound_groups(self, groups: Arc<OutboundGroupRegistry>) -> Self {
        self.replace_outbound_groups(groups);
        self
    }

    pub fn replace_outbound_groups(&self, groups: Arc<OutboundGroupRegistry>) {
        if let Ok(mut current) = self.outbound_groups.write() {
            *current = groups;
        }
    }

    pub fn with_rule_sets(self, rule_sets: Arc<RuleSetRegistry>) -> Self {
        self.replace_rule_sets(rule_sets);
        self
    }

    pub fn replace_rule_sets(&self, rule_sets: Arc<RuleSetRegistry>) {
        if let Ok(mut current) = self.rule_sets.write() {
            *current = rule_sets;
        }
    }

    fn rule_sets(&self) -> Result<Arc<RuleSetRegistry>, Status> {
        self.rule_sets
            .read()
            .map(|rule_sets| rule_sets.clone())
            .map_err(|_| Status::internal("rule-set state lock is poisoned"))
    }

    fn outbound_groups(&self) -> Result<Arc<OutboundGroupRegistry>, Status> {
        self.outbound_groups
            .read()
            .map(|groups| groups.clone())
            .map_err(|_| Status::internal("outbound group state lock is poisoned"))
    }

    pub fn observability(&self) -> Arc<ObservabilityStore> {
        Arc::clone(&self.observability)
    }

    pub fn control(&self) -> Arc<Mutex<ControlState>> {
        Arc::clone(&self.control)
    }
}

pub struct ControlCommand {
    pub command: EngineCommand,
    response: Option<oneshot::Sender<Result<bool, String>>>,
}

impl ControlCommand {
    fn detached(command: EngineCommand) -> Self {
        Self {
            command,
            response: None,
        }
    }

    fn acknowledged(command: EngineCommand) -> (Self, oneshot::Receiver<Result<bool, String>>) {
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

#[derive(Debug)]
pub enum ControlApiError {
    Config(ControlApiConfigError),
    Bind(std::io::Error),
    Transport(tonic::transport::Error),
}

impl fmt::Display for ControlApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "invalid control API config: {err}"),
            Self::Bind(err) => write!(f, "failed to bind control API: {err}"),
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
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(ControlApiError::Bind)?;
    serve_grpc_with_listener(config, state, listener, shutdown).await
}

/// Serve on an already-bound Tokio listener.
///
/// Binding separately lets lifecycle owners report address conflicts before
/// declaring the engine started and preserves the actual address for port `0`.
pub async fn serve_grpc_with_listener(
    config: ControlApiConfig,
    state: ControlApiState,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ControlApiError> {
    config.validate().map_err(ControlApiError::Config)?;

    let native = RustBoxControlService::new(
        state.clone(),
        config.auth.clone(),
        config.max_events_per_query,
    );
    let sing_box = SingBoxStartedService::new(state, config.auth);
    Server::builder()
        .add_service(pb::rust_box_control_server::RustBoxControlServer::new(
            native,
        ))
        .add_service(daemon::started_service_server::StartedServiceServer::new(
            sing_box,
        ))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
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
    type WatchConnectionsStream = ReceiverStream<Result<pb::ConnectionUpdate, Status>>;
    type StreamTrafficStream = ReceiverStream<Result<pb::TrafficSnapshot, Status>>;
    type StreamLogsStream = ReceiverStream<Result<pb::Event, Status>>;

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
            .active_connections()
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
            .query_events(&query)
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
        if let Some(command_tx) = &self.state.command_tx {
            command_tx
                .try_send(ControlCommand::detached(EngineCommand::Stop))
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        Status::resource_exhausted("control command queue is full")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        Status::unavailable("control command processor is unavailable")
                    }
                })?;
        }

        let snapshot = {
            let mut state = self
                .state
                .control
                .lock()
                .map_err(|_| Status::internal("control state lock is poisoned"))?;
            state.apply_command(EngineCommand::Stop);
            state.snapshot().clone()
        };

        Ok(Response::new(engine_to_proto(snapshot)))
    }

    async fn reload(
        &self,
        request: Request<pb::ReloadRequest>,
    ) -> Result<Response<pb::EngineSnapshot>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let source = rustbox_config_file::parse_toml_source(&request.into_inner().config_toml)
            .map_err(|error| Status::invalid_argument(error.message))?;
        let command = EngineCommand::Reload(Box::new(source));
        self.send_command(command.clone())?;
        let snapshot = {
            let mut state = self
                .state
                .control
                .lock()
                .map_err(|_| Status::internal("control state lock is poisoned"))?;
            state.apply_command(command);
            state.snapshot().clone()
        };
        Ok(Response::new(engine_to_proto(snapshot)))
    }

    async fn close_connection(
        &self,
        request: Request<pb::CloseConnectionRequest>,
    ) -> Result<Response<pb::CloseConnectionResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let flow_id = request.into_inner().flow_id;
        if flow_id == 0 {
            return Err(Status::invalid_argument("flow_id must be non-zero"));
        }
        let accepted = self
            .execute_command(EngineCommand::CloseConnection(flow_id))
            .await?;
        Ok(Response::new(pb::CloseConnectionResponse { accepted }))
    }

    async fn watch_connections(
        &self,
        request: Request<pb::WatchConnectionsRequest>,
    ) -> Result<Response<Self::WatchConnectionsStream>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let include_initial = request.into_inner().include_initial;
        let store = self.state.observability.clone();
        let mut events = store.subscribe();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            if include_initial {
                for connection in store.active_connections() {
                    if tx
                        .send(Ok(connection_update(
                            pb::ConnectionUpdateKind::Snapshot,
                            connection,
                        )))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            loop {
                match events.recv().await {
                    Ok(event) => {
                        let Some(flow_id) = event.flow_id.map(|id| id.get()) else {
                            continue;
                        };
                        if let Some(connection) = store.connection(flow_id)
                            && tx
                                .send(Ok(connection_update(
                                    pb::ConnectionUpdateKind::Upsert,
                                    connection,
                                )))
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn stream_traffic(
        &self,
        request: Request<pb::StreamTrafficRequest>,
    ) -> Result<Response<Self::StreamTrafficStream>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let interval_ms = request.into_inner().interval_ms.clamp(100, 60_000) as u64;
        let store = self.state.observability.clone();
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut timer = time::interval(Duration::from_millis(interval_ms));
            timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            let mut previous = store.traffic();
            let mut previous_at = Instant::now();
            loop {
                timer.tick().await;
                let current = store.traffic();
                let now = Instant::now();
                let elapsed_ms = now.duration_since(previous_at).as_millis().max(1) as u64;
                let message = traffic_to_proto(
                    &current,
                    current
                        .uplink_bytes
                        .saturating_sub(previous.uplink_bytes)
                        .saturating_mul(1000)
                        / elapsed_ms,
                    current
                        .downlink_bytes
                        .saturating_sub(previous.downlink_bytes)
                        .saturating_mul(1000)
                        / elapsed_ms,
                );
                previous = current;
                previous_at = now;
                if tx.send(Ok(message)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn stream_logs(
        &self,
        request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let request = request.into_inner();
        let min_level = if request.min_level.is_empty() {
            None
        } else {
            Some(parse_level(&request.min_level)?)
        };
        let target_prefix = none_if_empty(request.target_prefix);
        let flow_id = (request.flow_id != 0).then_some(request.flow_id);
        let mut events = self.state.observability.subscribe();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event)
                        if event_matches(&event, min_level, target_prefix.as_deref(), flow_id) =>
                    {
                        if tx.send(Ok(event_to_proto(event))).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_runtime_status(
        &self,
        request: Request<pb::GetRuntimeStatusRequest>,
    ) -> Result<Response<pb::RuntimeStatus>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let observability = self.state.observability.snapshot();
        Ok(Response::new(pb::RuntimeStatus {
            engine: Some(engine_to_proto(self.control_snapshot()?)),
            uptime_seconds: self.state.started_at.elapsed().as_secs(),
            memory_bytes: process_memory_bytes(),
            active_connections: observability.metrics.flows_active,
            retained_events: observability.recent_events.len() as u64,
        }))
    }

    async fn list_rule_sets(
        &self,
        request: Request<pb::ListRuleSetsRequest>,
    ) -> Result<Response<pb::ListRuleSetsResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let rule_sets = self
            .state
            .rule_sets()?
            .list()
            .into_iter()
            .map(rule_set_to_proto)
            .collect();
        Ok(Response::new(pb::ListRuleSetsResponse { rule_sets }))
    }

    async fn refresh_rule_set(
        &self,
        request: Request<pb::RefreshRuleSetRequest>,
    ) -> Result<Response<pb::OperationResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let tag = request.into_inner().tag;
        if tag.is_empty() {
            return Err(Status::invalid_argument("tag must not be empty"));
        }
        if !self.state.rule_sets()?.contains(&tag) {
            return Err(Status::not_found(format!(
                "rule-set `{tag}` does not exist"
            )));
        }
        let accepted = self
            .execute_command(EngineCommand::RefreshRuleSet(tag))
            .await?;
        Ok(Response::new(pb::OperationResponse {
            accepted,
            message: if accepted {
                "refresh scheduled"
            } else {
                "rule-set is not refreshable"
            }
            .into(),
        }))
    }

    async fn trigger_url_test(
        &self,
        request: Request<pb::TriggerUrlTestRequest>,
    ) -> Result<Response<pb::OperationResponse>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let tag = request.into_inner().group_tag;
        if tag.is_empty() {
            return Err(Status::invalid_argument("group_tag must not be empty"));
        }
        let groups = self.state.outbound_groups()?;
        if !groups
            .list()
            .iter()
            .any(|group| group.tag == tag && group.kind == OutboundGroupKind::UrlTest)
        {
            return Err(Status::not_found(format!(
                "URLTest group `{tag}` does not exist"
            )));
        }
        let accepted = self
            .execute_command(EngineCommand::TriggerUrlTest(tag))
            .await?;
        Ok(Response::new(pb::OperationResponse {
            accepted,
            message: if accepted {
                "URLTest scheduled"
            } else {
                "URLTest is unavailable"
            }
            .into(),
        }))
    }
}

impl RustBoxControlService {
    fn send_command(&self, command: EngineCommand) -> Result<(), Status> {
        let Some(command_tx) = &self.state.command_tx else {
            return Err(Status::unavailable(
                "control command processor is unavailable",
            ));
        };
        command_tx
            .try_send(ControlCommand::detached(command))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    Status::resource_exhausted("control command queue is full")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    Status::unavailable("control command processor is unavailable")
                }
            })
    }

    async fn execute_command(&self, command: EngineCommand) -> Result<bool, Status> {
        let Some(command_tx) = &self.state.command_tx else {
            return Err(Status::unavailable(
                "control command processor is unavailable",
            ));
        };
        let (command, response) = ControlCommand::acknowledged(command);
        command_tx.try_send(command).map_err(command_send_status)?;
        time::timeout(Duration::from_secs(5), response)
            .await
            .map_err(|_| Status::deadline_exceeded("control command timed out"))?
            .map_err(|_| Status::unavailable("control command processor stopped"))?
            .map_err(Status::internal)
    }
}

fn command_send_status(error: mpsc::error::TrySendError<ControlCommand>) -> Status {
    match error {
        mpsc::error::TrySendError::Full(_) => {
            Status::resource_exhausted("control command queue is full")
        }
        mpsc::error::TrySendError::Closed(_) => {
            Status::unavailable("control command processor is unavailable")
        }
    }
}

#[derive(Clone)]
pub struct SingBoxStartedService {
    state: ControlApiState,
    auth: AuthPolicy,
}

impl SingBoxStartedService {
    pub fn new(state: ControlApiState, auth: AuthPolicy) -> Self {
        Self { state, auth }
    }
}

#[tonic::async_trait]
impl daemon::started_service_server::StartedService for SingBoxStartedService {
    type SubscribeGroupsStream = ReceiverStream<Result<daemon::Groups, Status>>;

    async fn subscribe_groups(
        &self,
        request: Request<()>,
    ) -> Result<Response<Self::SubscribeGroupsStream>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Observe)?;
        let state = self.state.clone();
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut previous = None;
            let mut interval = time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                let terminating = match state.control.lock() {
                    Ok(control) => matches!(
                        control.snapshot().state,
                        EngineState::Stopping | EngineState::Stopped | EngineState::Failed
                    ),
                    Err(_) => {
                        let _ =
                            tx.try_send(Err(Status::internal("control state lock is poisoned")));
                        break;
                    }
                };
                if terminating {
                    break;
                }
                let snapshots = match state.outbound_groups() {
                    Ok(groups) => groups.list(),
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                };
                if previous.as_ref() == Some(&snapshots) {
                    continue;
                }
                previous = Some(snapshots.clone());
                if tx
                    .send(Ok(outbound_groups_to_daemon(snapshots)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn select_outbound(
        &self,
        request: Request<daemon::SelectOutboundRequest>,
    ) -> Result<Response<()>, Status> {
        self.auth
            .authorize(request.metadata(), Permission::Control)?;
        let request = request.into_inner();
        if request.group_tag.is_empty() || request.outbound_tag.is_empty() {
            return Err(Status::invalid_argument(
                "groupTag and outboundTag must not be empty",
            ));
        }
        self.state
            .outbound_groups()?
            .select(&request.group_tag, &request.outbound_tag)
            .map_err(select_outbound_status)?;
        Ok(Response::new(()))
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

fn connection_update(
    kind: pb::ConnectionUpdateKind,
    connection: ConnectionStats,
) -> pb::ConnectionUpdate {
    let flow_id = connection.flow_id;
    pb::ConnectionUpdate {
        kind: kind as i32,
        connection: Some(connection_to_proto(connection)),
        flow_id,
    }
}

fn traffic_to_proto(
    snapshot: &rustbox_observability::TrafficSnapshot,
    uplink_bytes_per_second: u64,
    downlink_bytes_per_second: u64,
) -> pb::TrafficSnapshot {
    let tags = |items: &HashMap<String, rustbox_observability::TagTraffic>| {
        let mut items = items
            .iter()
            .map(|(tag, traffic)| pb::TagTraffic {
                tag: tag.clone(),
                uplink_bytes: traffic.uplink_bytes,
                downlink_bytes: traffic.downlink_bytes,
            })
            .collect::<Vec<_>>();
        items.sort_by(|a, b| a.tag.cmp(&b.tag));
        items
    };
    pb::TrafficSnapshot {
        uplink_bytes: snapshot.uplink_bytes,
        downlink_bytes: snapshot.downlink_bytes,
        uplink_bytes_per_second,
        downlink_bytes_per_second,
        inbounds: tags(&snapshot.inbounds),
        outbounds: tags(&snapshot.outbounds),
    }
}

fn event_matches(
    event: &Event,
    min_level: Option<EventLevel>,
    target_prefix: Option<&str>,
    flow_id: Option<u64>,
) -> bool {
    let rank = |level| match level {
        EventLevel::Trace => 0,
        EventLevel::Debug => 1,
        EventLevel::Info => 2,
        EventLevel::Warn => 3,
        EventLevel::Error => 4,
    };
    min_level.is_none_or(|minimum| rank(event.level) >= rank(minimum))
        && target_prefix.is_none_or(|prefix| event.target.0.starts_with(prefix))
        && flow_id.is_none_or(|id| event.flow_id.map(|flow| flow.get()) == Some(id))
}

fn rule_set_to_proto(status: rustbox_control::RuleSetStatus) -> pb::RuleSetStatus {
    pb::RuleSetStatus {
        tag: status.tag,
        source: status.source,
        state: match status.state {
            RuleSetState::Idle => "idle",
            RuleSetState::Updating => "updating",
            RuleSetState::Ready => "ready",
            RuleSetState::Failed => "failed",
        }
        .into(),
        last_attempt_time: status.last_attempt_unix_ms.unwrap_or_default(),
        last_success_time: status.last_success_unix_ms.unwrap_or_default(),
        last_error: status.last_error.unwrap_or_default(),
    }
}

fn process_memory_bytes() -> u64 {
    let Ok(pid) = sysinfo::get_current_pid() else {
        return 0;
    };
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map_or(0, |process| process.memory())
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

fn outbound_groups_to_daemon(groups: Vec<OutboundGroupSnapshot>) -> daemon::Groups {
    daemon::Groups {
        group: groups
            .into_iter()
            .map(|group| daemon::Group {
                tag: group.tag,
                r#type: group.kind.as_str().to_string(),
                selectable: group.selectable,
                selected: group.selected,
                is_expand: false,
                items: group
                    .items
                    .into_iter()
                    .map(|item| daemon::GroupItem {
                        tag: item.tag,
                        r#type: item.kind,
                        url_test_time: item.url_test_time,
                        url_test_delay: item.url_test_delay.unwrap_or_default() as i32,
                        consecutive_failures: item.consecutive_failures,
                        last_error: item.last_error.unwrap_or_default(),
                        last_success_time: item.last_success_time.unwrap_or_default(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn select_outbound_status(error: SelectOutboundError) -> Status {
    match error {
        SelectOutboundError::GroupNotFound(_) | SelectOutboundError::OutboundNotFound { .. } => {
            Status::not_found(error.to_string())
        }
        SelectOutboundError::NotSelectable(_) => Status::invalid_argument(error.to_string()),
        SelectOutboundError::StateUnavailable => Status::internal(error.to_string()),
    }
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
        inbound: connection.inbound,
        outbound: connection.outbound.unwrap_or_default(),
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
            inbound,
        } => {
            insert("source", source);
            insert("destination", destination);
            insert("network", network);
            insert("inbound", inbound);
            ("flow_accepted", String::new())
        }
        EventKind::RouteSelected { decision, outbound } => {
            insert("decision", decision);
            if let Some(outbound) = outbound {
                insert("outbound", outbound);
            }
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
    use daemon::started_service_server::StartedService;
    use pb::rust_box_control_server::RustBoxControl;
    use rustbox_kernel::{Event, ObservabilitySink};
    use rustbox_types::FlowId;
    use std::num::NonZeroU64;
    use tokio_stream::StreamExt;
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
        let (command_tx, mut command_rx) = mpsc::channel(1);
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
            command_rx.recv().await.expect("command").command,
            EngineCommand::Stop
        );
    }

    #[tokio::test]
    async fn outbound_group_rpcs_expose_errors_with_sing_box_semantics() {
        let service = SingBoxStartedService::new(sample_state(None), AuthPolicy::disabled());

        let mut groups = service
            .subscribe_groups(Request::new(()))
            .await
            .expect("subscribe groups")
            .into_inner();
        assert!(
            groups
                .next()
                .await
                .expect("initial groups")
                .expect("groups")
                .group
                .is_empty()
        );

        let error = service
            .select_outbound(Request::new(daemon::SelectOutboundRequest {
                group_tag: "missing".into(),
                outbound_tag: "direct".into(),
            }))
            .await
            .expect_err("reject missing selector");
        assert_eq!(error.code(), Code::NotFound);

        let error = service
            .select_outbound(Request::new(daemon::SelectOutboundRequest {
                group_tag: String::new(),
                outbound_tag: "direct".into(),
            }))
            .await
            .expect_err("reject empty selector tag");
        assert_eq!(error.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn selecting_outbound_requires_control_permission() {
        let service = SingBoxStartedService::new(
            sample_state(None),
            AuthPolicy::observe_only_token("observe"),
        );
        let mut request = Request::new(daemon::SelectOutboundRequest {
            group_tag: "select".into(),
            outbound_tag: "direct".into(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer observe".parse().expect("metadata"));

        let error = service
            .select_outbound(request)
            .await
            .expect_err("observe token must not select outbound");
        assert_eq!(error.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn full_command_queue_does_not_publish_stopping_state() {
        let (command_tx, _command_rx) = mpsc::channel(1);
        command_tx
            .try_send(ControlCommand::detached(EngineCommand::Stop))
            .expect("fill command queue");
        let service = RustBoxControlService::new(
            sample_state(Some(command_tx)),
            AuthPolicy::disabled(),
            DEFAULT_MAX_EVENTS_PER_QUERY,
        );

        let error = service
            .stop(Request::new(pb::StopRequest {}))
            .await
            .expect_err("reject full queue");

        assert_eq!(error.code(), Code::ResourceExhausted);
        assert_eq!(
            service.control_snapshot().expect("snapshot").state,
            EngineState::Running
        );
    }

    #[tokio::test]
    async fn close_connection_returns_runtime_result() {
        let (command_tx, mut command_rx) = mpsc::channel(1);
        let service = RustBoxControlService::new(
            sample_state(Some(command_tx)),
            AuthPolicy::disabled(),
            DEFAULT_MAX_EVENTS_PER_QUERY,
        );
        let call = tokio::spawn(async move {
            service
                .close_connection(Request::new(pb::CloseConnectionRequest { flow_id: 7 }))
                .await
                .expect("close connection")
                .into_inner()
        });
        let command = command_rx.recv().await.expect("runtime command");
        assert_eq!(command.command, EngineCommand::CloseConnection(7));
        command.respond(Ok(false));
        assert!(!call.await.expect("RPC task").accepted);
    }

    #[tokio::test]
    async fn streams_logs_and_tagged_traffic() {
        let state = sample_state(None);
        let store = state.observability();
        let service =
            RustBoxControlService::new(state, AuthPolicy::disabled(), DEFAULT_MAX_EVENTS_PER_QUERY);
        let mut logs = service
            .stream_logs(Request::new(pb::StreamLogsRequest {
                min_level: "warn".into(),
                target_prefix: "rustbox.control".into(),
                flow_id: 0,
            }))
            .await
            .expect("log stream")
            .into_inner();
        store_event(
            &store,
            Event::new(
                EventLevel::Warn,
                "rustbox.control.test",
                None,
                EventKind::Diagnostic("streamed".into()),
            ),
        );
        let event = logs.next().await.expect("log item").expect("log event");
        assert_eq!(event.message, "streamed");

        let mut traffic = service
            .stream_traffic(Request::new(pb::StreamTrafficRequest { interval_ms: 100 }))
            .await
            .expect("traffic stream")
            .into_inner();
        let traffic = traffic
            .next()
            .await
            .expect("traffic item")
            .expect("traffic");
        assert_eq!(traffic.uplink_bytes, 4);
        assert_eq!(traffic.inbounds[0].tag, "http-in");
        assert_eq!(traffic.outbounds[0].tag, "direct");
    }

    fn sample_state(command_tx: Option<mpsc::Sender<ControlCommand>>) -> ControlApiState {
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
                    inbound: "http-in".to_string(),
                },
            ),
        );
        store_event(
            &store,
            Event::new(
                EventLevel::Debug,
                "rustbox.kernel.route",
                Some(flow_id),
                EventKind::RouteSelected {
                    decision: "Forward(direct)".into(),
                    outbound: Some("direct".into()),
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
