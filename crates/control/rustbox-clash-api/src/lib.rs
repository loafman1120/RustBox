//! Clash/Mihomo-compatible HTTP, NDJSON and WebSocket control transport.

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, put};
use axum::{Json, Router};
use bytes::Bytes;
use futures_util::stream;
use rustbox_control::{EngineCommand, OutboundGroupKind, SelectOutboundError};
use rustbox_control_service::{
    ControlPlaneHandle, ExecuteCommandError, OutboundCatalogEntry, SendCommandError,
};
use rustbox_kernel::{Event, EventLevel};
use rustbox_observability::{ConnectionStats, ObservabilityStore, format_event};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use sysinfo::{Pid, System};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa_swagger_ui::SwaggerUi;

const MIN_INTERVAL_MS: u64 = 100;
const MAX_INTERVAL_MS: u64 = 60_000;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "RustBox Clash/Mihomo Compatibility API",
        description = "Clash/Mihomo-compatible HTTP and streaming control surface backed by the RustBox shared control plane"
    ),
    paths(
        hello,
        version,
        configs,
        configs_patch,
        configs_reload,
        traffic,
        memory,
        logs,
        connections,
        close_connection,
        close_all_connections,
        proxies,
        proxy,
        select_proxy,
        unfix_proxy,
        proxy_delay,
        groups,
        group,
        group_delay,
        rules,
        disable_rules,
        proxy_providers,
        rule_providers,
        refresh_rule_provider
    ),
    tags(
        (name = "system", description = "Runtime identity and configuration"),
        (name = "observability", description = "Traffic, memory, logs and connections"),
        (name = "proxies", description = "Outbound and group inspection or control"),
        (name = "rules", description = "Routing rules and rule providers")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ClashApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("Clash secret")
                        .build(),
                ),
            );
        }
        openapi.security = Some(vec![SecurityRequirement::new(
            "bearer_auth",
            Vec::<String>::new(),
        )]);
    }
}

pub fn openapi() -> utoipa::openapi::OpenApi {
    ClashApiDoc::openapi()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClashApiConfig {
    pub listen: SocketAddr,
    pub secret: Option<String>,
    pub cors_allowed_origins: Vec<String>,
}

impl Default for ClashApiConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 9090)),
            secret: None,
            cors_allowed_origins: Vec::new(),
        }
    }
}

impl ClashApiConfig {
    pub fn validate(&self) -> Result<(), ClashApiConfigError> {
        if self.secret.as_deref().is_some_and(str::is_empty) {
            return Err(ClashApiConfigError::new(
                "Clash API secret must not be empty",
            ));
        }
        if !self.listen.ip().is_loopback() && self.secret.is_none() {
            return Err(ClashApiConfigError::new(
                "Clash API must configure a secret before listening on a non-loopback address",
            ));
        }
        for origin in &self.cors_allowed_origins {
            if origin != "*" && origin.parse::<HeaderValue>().is_err() {
                return Err(ClashApiConfigError::new(format!(
                    "invalid Clash API CORS origin `{origin}`"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClashApiConfigError {
    pub message: String,
}

impl ClashApiConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ClashApiConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ClashApiConfigError {}

#[derive(Debug)]
pub enum ClashApiError {
    Config(ClashApiConfigError),
    Bind(std::io::Error),
    Serve(std::io::Error),
}

impl fmt::Display for ClashApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "invalid Clash API config: {error}"),
            Self::Bind(error) => write!(f, "failed to bind Clash API: {error}"),
            Self::Serve(error) => write!(f, "Clash API server failed: {error}"),
        }
    }
}

impl Error for ClashApiError {}

#[derive(Clone)]
struct AppState {
    plane: ControlPlaneHandle,
    secret: Option<Arc<str>>,
}

pub async fn serve(
    config: ClashApiConfig,
    plane: ControlPlaneHandle,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ClashApiError> {
    config.validate().map_err(ClashApiError::Config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(ClashApiError::Bind)?;
    serve_with_listener(config, plane, listener, shutdown).await
}

pub async fn serve_with_listener(
    config: ClashApiConfig,
    plane: ControlPlaneHandle,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ClashApiError> {
    config.validate().map_err(ClashApiError::Config)?;
    axum::serve(listener, router(config, plane))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(ClashApiError::Serve)
}

pub fn router(config: ClashApiConfig, plane: ControlPlaneHandle) -> Router {
    let cors = cors_layer(&config.cors_allowed_origins);
    let state = AppState {
        plane,
        secret: config.secret.map(Arc::from),
    };
    let api = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route(
            "/configs",
            get(configs).patch(configs_patch).put(configs_reload),
        )
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(logs))
        .route(
            "/connections",
            get(connections).delete(close_all_connections),
        )
        .route("/connections/{id}", delete(close_connection))
        .route("/proxies", get(proxies))
        .route(
            "/proxies/{name}",
            get(proxy).put(select_proxy).delete(unfix_proxy),
        )
        .route("/proxies/{name}/delay", get(proxy_delay))
        .route("/group", get(groups))
        .route("/group/{name}", get(group))
        .route("/group/{name}/delay", get(group_delay))
        .route("/rules", get(rules))
        .route("/rules/disable", patch(disable_rules))
        .route("/providers/proxies", get(proxy_providers))
        .route("/providers/rules", get(rule_providers))
        .route("/providers/rules/{name}", put(refresh_rule_provider))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/docs/openapi.json", openapi()))
        .merge(api)
        .layer(cors)
        .with_state(state)
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_private_network(true)
        .max_age(Duration::from_secs(300));
    if origins.iter().any(|origin| origin == "*") {
        layer = layer.allow_origin(AllowOrigin::any());
    } else if !origins.is_empty() {
        let values = origins
            .iter()
            .filter_map(|origin| origin.parse::<HeaderValue>().ok())
            .collect::<Vec<_>>();
        layer = layer.allow_origin(values);
    }
    layer
}

async fn authenticate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(expected) = state.secret.as_deref() else {
        return next.run(request).await;
    };
    let header_token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let websocket_token = is_websocket(&request)
        .then(|| {
            request.uri().query().and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "token")
                    .map(|(_, value)| value.into_owned())
            })
        })
        .flatten();
    if header_token.is_some_and(|token| constant_time_eq(token, expected))
        || websocket_token
            .as_deref()
            .is_some_and(|token| constant_time_eq(token, expected))
    {
        next.run(request).await
    } else {
        ApiError::unauthorized().into_response()
    }
}

fn is_websocket(request: &Request) -> bool {
    request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn constant_time_eq(actual: &str, expected: &str) -> bool {
    actual.len() == expected.len() && actual.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
}

#[utoipa::path(get, path = "/", tag = "system", responses((status = 200, description = "Mihomo-compatible greeting")))]
async fn hello() -> Json<Value> {
    Json(json!({"hello": "mihomo"}))
}

#[utoipa::path(get, path = "/version", tag = "system", responses((status = 200, description = "RustBox version using the Mihomo response shape")))]
async fn version() -> Json<Value> {
    Json(json!({"meta": true, "version": format!("RustBox {}", env!("CARGO_PKG_VERSION"))}))
}

#[utoipa::path(get, path = "/configs", tag = "system", responses((status = 200, description = "Current runtime configuration summary"), (status = 401, description = "Unauthorized")))]
async fn configs(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let catalog = state.plane.catalog().map_err(ApiError::internal)?;
    let mut port = 0;
    let mut socks_port = 0;
    let mut mixed_port = 0;
    for inbound in &catalog.inbounds {
        let listen_port = inbound
            .listen
            .as_deref()
            .and_then(|listen| listen.rsplit_once(':'))
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(0);
        match inbound.kind.as_str() {
            "http" => port = listen_port,
            "socks" => socks_port = listen_port,
            "mixed" => mixed_port = listen_port,
            _ => {}
        }
    }
    Ok(Json(json!({
        "port": port,
        "socks-port": socks_port,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": mixed_port,
        "mode": "rule",
        "mode-list": ["rule"],
        "log-level": "info",
        "allow-lan": false,
        "ipv6": true,
        "tun": {"enable": catalog.inbounds.iter().any(|value| value.kind == "tun")}
    })))
}

#[utoipa::path(patch, path = "/configs", tag = "system", responses((status = 400, description = "Selective runtime mutation is intentionally unsupported")))]
async fn configs_patch() -> ApiError {
    ApiError::bad_request("dynamic Clash config patching is not supported")
}

#[derive(Deserialize, utoipa::ToSchema)]
struct ReloadRequest {
    #[serde(default)]
    path: String,
    #[serde(default)]
    payload: String,
}

#[utoipa::path(put, path = "/configs", tag = "system", request_body = ReloadRequest, responses((status = 204, description = "Configuration reloaded"), (status = 400, description = "Invalid reload request"), (status = 401, description = "Unauthorized")))]
async fn configs_reload(
    State(state): State<AppState>,
    Json(request): Json<ReloadRequest>,
) -> Result<StatusCode, ApiError> {
    if !request.path.is_empty() {
        return Err(ApiError::bad_request("path-based reload is not supported"));
    }
    if request.payload.is_empty() {
        return Err(ApiError::bad_request("payload must contain RustBox TOML"));
    }
    let source = rustbox_config_file::parse_toml_source(&request.payload)
        .map_err(|error| ApiError::bad_request(error.message))?;
    execute(&state, EngineCommand::Reload(Box::new(source))).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default, Deserialize, utoipa::IntoParams)]
struct StreamQuery {
    interval: Option<u64>,
    level: Option<String>,
    format: Option<String>,
}

#[utoipa::path(get, path = "/traffic", tag = "observability", params(StreamQuery), responses((status = 200, description = "NDJSON or WebSocket traffic stream")))]
async fn traffic(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let interval = interval(&query);
    if let Ok(ws) = ws {
        return ws
            .on_upgrade(move |socket| {
                traffic_websocket(socket, state.plane.observability(), interval)
            })
            .into_response();
    }
    traffic_ndjson(state.plane.observability(), interval)
}

fn traffic_ndjson(store: Arc<ObservabilityStore>, interval: Duration) -> Response {
    let previous = store.traffic();
    let timer = tokio::time::interval(interval);
    let body = Body::from_stream(stream::unfold(
        (timer, store, previous, Instant::now()),
        |(mut timer, store, previous, previous_at)| async move {
            timer.tick().await;
            let current = store.traffic();
            let now = Instant::now();
            let elapsed = now.duration_since(previous_at).as_millis().max(1) as u64;
            let value = json!({
                "up": current.uplink_bytes.saturating_sub(previous.uplink_bytes).saturating_mul(1000) / elapsed,
                "down": current.downlink_bytes.saturating_sub(previous.downlink_bytes).saturating_mul(1000) / elapsed,
                "upTotal": current.uplink_bytes,
                "downTotal": current.downlink_bytes
            });
            Some((
                Ok::<_, Infallible>(json_line(value)),
                (timer, store, current, now),
            ))
        },
    ));
    ndjson_response(body)
}

async fn traffic_websocket(
    mut socket: WebSocket,
    store: Arc<ObservabilityStore>,
    interval: Duration,
) {
    let mut previous = store.traffic();
    let mut previous_at = Instant::now();
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let current = store.traffic();
        let now = Instant::now();
        let elapsed = now.duration_since(previous_at).as_millis().max(1) as u64;
        let value = json!({
            "up": current.uplink_bytes.saturating_sub(previous.uplink_bytes).saturating_mul(1000) / elapsed,
            "down": current.downlink_bytes.saturating_sub(previous.downlink_bytes).saturating_mul(1000) / elapsed,
            "upTotal": current.uplink_bytes,
            "downTotal": current.downlink_bytes
        });
        previous = current;
        previous_at = now;
        if send_json(&mut socket, &value).await.is_err() {
            break;
        }
    }
}

#[utoipa::path(get, path = "/memory", tag = "observability", params(StreamQuery), responses((status = 200, description = "NDJSON or WebSocket process-memory stream")))]
async fn memory(
    State(_state): State<AppState>,
    Query(query): Query<StreamQuery>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let interval = interval(&query);
    if let Ok(ws) = ws {
        return ws
            .on_upgrade(move |socket| memory_websocket(socket, interval))
            .into_response();
    }
    ndjson_interval(interval, memory_value).into_response()
}

fn memory_value() -> Value {
    let mut system = System::new();
    let pid = Pid::from_u32(std::process::id());
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    json!({"inuse": system.process(pid).map_or(0, |process| process.memory()), "oslimit": 0})
}

async fn memory_websocket(mut socket: WebSocket, interval: Duration) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if send_json(&mut socket, &memory_value()).await.is_err() {
            break;
        }
    }
}

#[utoipa::path(get, path = "/logs", tag = "observability", params(StreamQuery), responses((status = 200, description = "NDJSON or WebSocket structured log stream")))]
async fn logs(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, ApiError> {
    let min_level = parse_level(query.level.as_deref().unwrap_or("info"))?;
    let structured = query.format.as_deref() == Some("structured");
    let receiver = state.plane.observability().subscribe();
    if let Ok(ws) = ws {
        return Ok(ws
            .on_upgrade(move |socket| logs_websocket(socket, receiver, min_level, structured))
            .into_response());
    }
    let body = Body::from_stream(stream::unfold(receiver, move |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(event) if level_rank(event.level) >= level_rank(min_level) => {
                    let bytes = json_line(log_value(&event, structured));
                    return Some((Ok::<_, Infallible>(bytes), receiver));
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    }));
    Ok(ndjson_response(body))
}

async fn logs_websocket(
    mut socket: WebSocket,
    mut receiver: tokio::sync::broadcast::Receiver<Event>,
    min_level: EventLevel,
    structured: bool,
) {
    loop {
        match receiver.recv().await {
            Ok(event) if level_rank(event.level) >= level_rank(min_level) => {
                if send_json(&mut socket, &log_value(&event, structured))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn log_value(event: &Event, structured: bool) -> Value {
    if structured {
        json!({
            "time": OffsetDateTime::now_utc().time().to_string(),
            "level": level_name(event.level),
            "message": format_event(event),
            "fields": []
        })
    } else {
        json!({"type": level_name(event.level), "payload": format_event(event)})
    }
}

#[utoipa::path(get, path = "/connections", tag = "observability", params(StreamQuery), responses((status = 200, description = "Connection snapshot or WebSocket stream")))]
async fn connections(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if let Ok(ws) = ws {
        let interval = interval(&query);
        return ws
            .on_upgrade(move |socket| connections_websocket(socket, state.plane, interval))
            .into_response();
    }
    Json(connections_value(&state.plane)).into_response()
}

async fn connections_websocket(
    mut socket: WebSocket,
    plane: ControlPlaneHandle,
    interval: Duration,
) {
    if send_json(&mut socket, &connections_value(&plane))
        .await
        .is_err()
    {
        return;
    }
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    timer.tick().await;
    loop {
        timer.tick().await;
        if send_json(&mut socket, &connections_value(&plane))
            .await
            .is_err()
        {
            break;
        }
    }
}

fn connections_value(plane: &ControlPlaneHandle) -> Value {
    let store = plane.observability();
    let traffic = store.traffic();
    let rules = plane
        .catalog()
        .map(|catalog| {
            catalog
                .rules
                .iter()
                .cloned()
                .map(|rule| (rule.index, rule))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let connections = store
        .active_connections()
        .into_iter()
        .map(|connection| {
            let rule = connection.rule_index.and_then(|index| rules.get(&index));
            connection_value(connection, rule)
        })
        .collect::<Vec<_>>();
    json!({
        "downloadTotal": traffic.downlink_bytes,
        "uploadTotal": traffic.uplink_bytes,
        "memory": memory_value()["inuse"],
        "connections": connections
    })
}

fn connection_value(
    connection: ConnectionStats,
    rule: Option<&rustbox_control_service::RuleCatalogEntry>,
) -> Value {
    let started = OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(connection.started_at_unix_ms) * 1_000_000,
    )
    .ok()
    .and_then(|value| value.format(&Rfc3339).ok())
    .unwrap_or_default();
    json!({
        "id": connection.flow_id.to_string(),
        "metadata": {
            "network": connection.network.to_ascii_lowercase(),
            "type": connection.protocol.unwrap_or_default(),
            "sourceIP": connection.source_host,
            "sourcePort": connection.source_port.to_string(),
            "destinationIP": connection.destination_host,
            "destinationPort": connection.destination_port.to_string(),
            "host": connection.domain.unwrap_or_default(),
            "dnsMode": "normal",
            "inboundIP": "",
            "inboundPort": "",
            "inboundName": connection.inbound,
            "inboundUser": "",
            "process": connection.process.unwrap_or_default(),
            "processPath": connection.process_path.unwrap_or_default(),
            "remoteDestination": "",
            "sniffHost": "",
            "specialProxy": "",
            "specialRules": "",
            "uid": connection.user_id.unwrap_or_default()
        },
        "upload": connection.inbound_to_outbound_bytes,
        "download": connection.outbound_to_inbound_bytes,
        "start": started,
        "chains": connection.outbound_chain,
        "providerChains": [],
        "rule": rule.map_or("", |value| value.kind.as_str()),
        "rulePayload": rule.map_or("", |value| value.payload.as_str())
    })
}

#[utoipa::path(delete, path = "/connections/{id}", tag = "observability", params(("id" = u64, Path, description = "Flow identifier")), responses((status = 204, description = "Connection closed"), (status = 400, description = "Invalid flow identifier")))]
async fn close_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = id
        .parse::<u64>()
        .map_err(|_| ApiError::bad_request("connection id must be an unsigned integer"))?;
    execute(&state, EngineCommand::CloseConnection(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/connections", tag = "observability", responses((status = 204, description = "All connections closed")))]
async fn close_all_connections(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    execute(&state, EngineCommand::CloseAllConnections).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/proxies", tag = "proxies", responses((status = 200, description = "Mihomo proxy map")))]
async fn proxies(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"proxies": proxy_map(&state)?})))
}

#[utoipa::path(get, path = "/proxies/{name}", tag = "proxies", params(("name" = String, Path, description = "Outbound or group tag")), responses((status = 200, description = "Proxy details"), (status = 404, description = "Proxy not found")))]
async fn proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let value = proxy_map(&state)?
        .remove(&name)
        .ok_or_else(|| ApiError::not_found("Proxy not found"))?;
    Ok(Json(value))
}

fn proxy_map(state: &AppState) -> Result<BTreeMap<String, Value>, ApiError> {
    let catalog = state.plane.catalog().map_err(ApiError::internal)?;
    let groups = state
        .plane
        .outbound_groups()
        .map_err(ApiError::internal)?
        .list();
    let group_by_tag = groups
        .into_iter()
        .map(|group| (group.tag.clone(), group))
        .collect::<HashMap<_, _>>();
    let mut result = BTreeMap::new();
    for outbound in &catalog.outbounds {
        let mut value = leaf_proxy_value(outbound);
        if let Some(group) = group_by_tag.get(&outbound.tag) {
            let histories = group
                .items
                .iter()
                .filter_map(|item| {
                    item.url_test_delay.map(
                        |delay| json!({"time": format_unix_ms(item.url_test_time), "delay": delay}),
                    )
                })
                .collect::<Vec<_>>();
            value = json!({
                "name": outbound.tag,
                "type": if group.kind == OutboundGroupKind::Selector { "Selector" } else { "URLTest" },
                "udp": outbound.udp,
                "xudp": false,
                "tfo": false,
                "alive": group.items.iter().any(|item| item.last_error.is_none()),
                "history": histories,
                "extra": {},
                "all": group.items.iter().map(|item| item.tag.clone()).collect::<Vec<_>>(),
                "now": group.selected,
                "hidden": false,
                "testUrl": outbound.test_url
            });
        }
        result.insert(outbound.tag.clone(), value);
    }
    Ok(result)
}

fn leaf_proxy_value(outbound: &OutboundCatalogEntry) -> Value {
    json!({
        "name": outbound.tag,
        "type": outbound.kind,
        "udp": outbound.udp,
        "xudp": false,
        "tfo": false,
        "alive": true,
        "history": [],
        "extra": {}
    })
}

#[derive(Deserialize, utoipa::ToSchema)]
struct SelectProxyRequest {
    name: String,
}

#[utoipa::path(put, path = "/proxies/{name}", tag = "proxies", params(("name" = String, Path, description = "Selector group tag")), request_body = SelectProxyRequest, responses((status = 204, description = "Selector updated"), (status = 400, description = "Selection rejected")))]
async fn select_proxy(
    State(state): State<AppState>,
    Path(group): Path<String>,
    Json(request): Json<SelectProxyRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .plane
        .outbound_groups()
        .map_err(ApiError::internal)?
        .select(&group, &request.name)
        .map_err(select_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/proxies/{name}", tag = "proxies", params(("name" = String, Path)), responses((status = 400, description = "Automatic group pinning is unsupported")))]
async fn unfix_proxy() -> ApiError {
    ApiError::bad_request("automatic group pinning is not supported")
}

#[derive(Deserialize, utoipa::IntoParams)]
struct DelayQuery {
    #[serde(default)]
    url: String,
    #[serde(default = "default_delay_timeout")]
    timeout: u64,
    expected: Option<String>,
}

fn default_delay_timeout() -> u64 {
    5_000
}

#[utoipa::path(get, path = "/proxies/{name}/delay", tag = "proxies", params(("name" = String, Path, description = "Outbound tag"), DelayQuery), responses((status = 200, description = "Measured delay"), (status = 503, description = "Probe unavailable or failed")))]
async fn proxy_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Result<Json<Value>, ApiError> {
    let _ = &query.expected;
    if query.url.is_empty() {
        return Err(ApiError::bad_request("url must not be empty"));
    }
    let delay = state
        .plane
        .outbound_probe()
        .map_err(ApiError::service_unavailable)?
        .probe(
            &name,
            &query.url,
            Duration::from_millis(query.timeout.clamp(100, 60_000)),
        )
        .await
        .map_err(ApiError::service_unavailable)?;
    Ok(Json(json!({"delay": delay})))
}

#[utoipa::path(get, path = "/group", tag = "proxies", responses((status = 200, description = "Proxy groups")))]
async fn groups(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let values = proxy_map(&state)?
        .into_values()
        .filter(|value| value.get("all").is_some())
        .collect::<Vec<_>>();
    Ok(Json(json!({"proxies": values})))
}

#[utoipa::path(get, path = "/group/{name}", tag = "proxies", params(("name" = String, Path, description = "Group tag")), responses((status = 200, description = "Group details"), (status = 404, description = "Group not found")))]
async fn group(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    proxy(State(state), Path(name)).await
}

#[utoipa::path(get, path = "/group/{name}/delay", tag = "proxies", params(("name" = String, Path, description = "Group tag"), DelayQuery), responses((status = 200, description = "Per-member measured delays"), (status = 503, description = "Probe unavailable or failed")))]
async fn group_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Result<Json<Value>, ApiError> {
    let _ = &query.expected;
    let values = state
        .plane
        .outbound_probe()
        .map_err(ApiError::service_unavailable)?
        .probe_group(
            &name,
            &query.url,
            Duration::from_millis(query.timeout.clamp(100, 60_000)),
        )
        .await
        .map_err(ApiError::service_unavailable)?;
    Ok(Json(json!(values)))
}

#[utoipa::path(get, path = "/rules", tag = "rules", responses((status = 200, description = "Compiled routing rules")))]
async fn rules(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let catalog = state.plane.catalog().map_err(ApiError::internal)?;
    let rules = catalog
        .rules
        .iter()
        .map(|rule| {
            json!({
                "index": rule.index,
                "type": rule.kind,
                "payload": rule.payload,
                "proxy": rule.outbound,
                "size": rule.size
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"rules": rules})))
}

#[utoipa::path(patch, path = "/rules/disable", tag = "rules", responses((status = 400, description = "Temporarily disabling rules is unsupported")))]
async fn disable_rules() -> ApiError {
    ApiError::bad_request("temporarily disabling route rules is not supported")
}

#[utoipa::path(get, path = "/providers/proxies", tag = "proxies", responses((status = 200, description = "Proxy providers; empty when not configured")))]
async fn proxy_providers() -> Json<Value> {
    Json(json!({"providers": {}}))
}

#[utoipa::path(get, path = "/providers/rules", tag = "rules", responses((status = 200, description = "Rule provider snapshots")))]
async fn rule_providers(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let providers = state
        .plane
        .rule_sets()
        .map_err(ApiError::internal)?
        .list()
        .into_iter()
        .map(|provider| {
            let updated = provider
                .last_success_unix_ms
                .map(format_unix_ms)
                .unwrap_or_default();
            (
                provider.tag.clone(),
                json!({
                    "behavior": "classical",
                    "format": "source",
                    "name": provider.tag,
                    "ruleCount": 0,
                    "type": "Rule",
                    "updatedAt": updated,
                    "vehicleType": provider.source
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    Ok(Json(json!({"providers": providers})))
}

#[utoipa::path(put, path = "/providers/rules/{name}", tag = "rules", params(("name" = String, Path, description = "Rule-set tag")), responses((status = 204, description = "Refresh requested"), (status = 404, description = "Rule provider not found")))]
async fn refresh_rule_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    execute(&state, EngineCommand::RefreshRuleSet(name)).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn interval(query: &StreamQuery) -> Duration {
    Duration::from_millis(
        query
            .interval
            .unwrap_or(1_000)
            .clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS),
    )
}

fn ndjson_interval(
    interval: Duration,
    producer: impl Fn() -> Value + Send + Sync + 'static,
) -> Response {
    let producer = Arc::new(producer);
    let timer = tokio::time::interval(interval);
    let body = Body::from_stream(stream::unfold(
        (timer, producer),
        |(mut timer, producer)| async move {
            timer.tick().await;
            let bytes = json_line(producer());
            Some((Ok::<_, Infallible>(bytes), (timer, producer)))
        },
    ));
    ndjson_response(body)
}

fn ndjson_response(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn json_line(value: Value) -> Bytes {
    let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
    bytes.push(b'\n');
    Bytes::from(bytes)
}

async fn send_json(socket: &mut WebSocket, value: &Value) -> Result<(), ()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn parse_level(value: &str) -> Result<EventLevel, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "debug" => Ok(EventLevel::Debug),
        "info" => Ok(EventLevel::Info),
        "warning" | "warn" => Ok(EventLevel::Warn),
        "error" => Ok(EventLevel::Error),
        _ => Err(ApiError::bad_request("unknown log level")),
    }
}

fn level_rank(level: EventLevel) -> u8 {
    match level {
        EventLevel::Trace => 0,
        EventLevel::Debug => 1,
        EventLevel::Info => 2,
        EventLevel::Warn => 3,
        EventLevel::Error => 4,
    }
}

fn level_name(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace | EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warning",
        EventLevel::Error => "error",
    }
}

fn format_unix_ms(value: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_default()
}

async fn execute(state: &AppState, command: EngineCommand) -> Result<bool, ApiError> {
    state
        .plane
        .execute(command)
        .await
        .map_err(|error| match error {
            ExecuteCommandError::Send(SendCommandError::Full) => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "control command queue is full",
            ),
            ExecuteCommandError::Send(SendCommandError::Closed)
            | ExecuteCommandError::Unavailable => {
                ApiError::service_unavailable("control command processor is unavailable")
            }
            ExecuteCommandError::Rejected(message) => ApiError::service_unavailable(message),
        })
}

fn select_error(error: SelectOutboundError) -> ApiError {
    match error {
        SelectOutboundError::GroupNotFound(_) => ApiError::not_found(error.to_string()),
        SelectOutboundError::NotSelectable(_) | SelectOutboundError::OutboundNotFound { .. } => {
            ApiError::bad_request(error.to_string())
        }
        SelectOutboundError::StateUnavailable => ApiError::internal(error.to_string()),
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use rustbox_control::{ControlState, EngineSnapshot};
    use rustbox_control_service::{ControlCatalog, OutboundCatalogEntry};
    use rustbox_kernel::{Event, EventKind, EventLevel, ObservabilitySink};
    use rustbox_observability::ObservabilityStore;
    use rustbox_types::FlowId;
    use std::num::NonZeroU64;
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn test_plane() -> ControlPlaneHandle {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        ControlPlaneHandle::new(
            Arc::new(ObservabilityStore::default()),
            Arc::new(Mutex::new(ControlState::new(EngineSnapshot::created()))),
        )
        .with_command_sender(tx)
    }

    fn test_router(secret: Option<&str>) -> Router {
        router(
            ClashApiConfig {
                secret: secret.map(str::to_string),
                ..ClashApiConfig::default()
            },
            test_plane(),
        )
    }

    #[tokio::test]
    async fn version_requires_bearer_when_secret_is_set() {
        let response = test_router(Some("secret"))
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn version_has_mihomo_shape() {
        let response = test_router(None)
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["meta"], true);
        assert!(value["version"].as_str().unwrap().starts_with("RustBox "));
    }

    #[tokio::test]
    async fn bearer_token_authorizes_regular_http() {
        let response = test_router(Some("secret"))
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn serves_generated_openapi_without_control_authentication() {
        let response = test_router(Some("secret"))
            .oneshot(
                Request::builder()
                    .uri("/docs/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["openapi"], "3.1.0");
        assert!(value["paths"]["/connections"].get("get").is_some());
        assert!(value["paths"]["/proxies/{name}"].get("put").is_some());
        assert_eq!(
            value["components"]["securitySchemes"]["bearer_auth"]["scheme"],
            "bearer"
        );
    }

    #[tokio::test]
    async fn proxies_uses_mihomo_map_shape() {
        let plane = test_plane();
        plane.replace_catalog(Arc::new(ControlCatalog {
            outbounds: vec![OutboundCatalogEntry {
                tag: "direct".to_string(),
                kind: "Direct".to_string(),
                udp: true,
                children: Vec::new(),
                test_url: None,
            }],
            ..ControlCatalog::default()
        }));
        let response = router(ClashApiConfig::default(), plane)
            .oneshot(
                Request::builder()
                    .uri("/proxies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["proxies"]["direct"]["type"], "Direct");
        assert_eq!(value["proxies"]["direct"]["udp"], true);
    }

    #[tokio::test]
    async fn connections_preserves_structured_flow_metadata() {
        let plane = test_plane();
        let flow_id = FlowId::new(NonZeroU64::new(42).unwrap());
        plane
            .observability()
            .emit(Event::new(
                EventLevel::Info,
                "rustbox.kernel.flow",
                Some(flow_id),
                EventKind::FlowAccepted {
                    source: "127.0.0.1:5000".to_string(),
                    destination: "example.test:443".to_string(),
                    source_host: "127.0.0.1".to_string(),
                    source_port: 5000,
                    destination_host: "203.0.113.10".to_string(),
                    destination_port: 443,
                    domain: Some("example.test".to_string()),
                    protocol: Some("Tls".to_string()),
                    process: Some("browser".to_string()),
                    process_path: Some("/browser".to_string()),
                    user_id: Some(1000),
                    network: "Tcp".to_string(),
                    inbound: "mixed".to_string(),
                },
            ))
            .await;
        let response = router(ClashApiConfig::default(), plane)
            .oneshot(
                Request::builder()
                    .uri("/connections")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["connections"][0]["id"], "42");
        assert_eq!(value["connections"][0]["metadata"]["host"], "example.test");
        assert_eq!(value["connections"][0]["metadata"]["sourcePort"], "5000");
    }

    #[test]
    fn rejects_public_listener_without_secret() {
        let config = ClashApiConfig {
            listen: "0.0.0.0:9090".parse().unwrap(),
            ..ClashApiConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
