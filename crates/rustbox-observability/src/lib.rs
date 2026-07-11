//! 具体观测 sink。
//!
//! 可移植 crate 只发出 `rustbox-host-api` 的结构化事件；本 crate 决定事件
//! 如何打印、过滤或记录，避免核心绑定具体日志框架。

use rustbox_host_api::{BoxFuture, Event, EventKind, EventLevel, EventTarget, ObservabilitySink};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

/// 控制台输出目标。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

/// 事件级别过滤器，当前可由 `RUSTBOX_LOG` 配置。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LevelFilter {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl LevelFilter {
    pub fn from_env() -> Self {
        std::env::var("RUSTBOX_LOG")
            .ok()
            .and_then(|value| Self::parse(&value))
            .unwrap_or(Self::Info)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    fn allows(self, level: EventLevel) -> bool {
        match self {
            Self::Trace => true,
            Self::Debug => !matches!(level, EventLevel::Trace),
            Self::Info => matches!(
                level,
                EventLevel::Info | EventLevel::Warn | EventLevel::Error
            ),
            Self::Warn => matches!(level, EventLevel::Warn | EventLevel::Error),
            Self::Error => matches!(level, EventLevel::Error),
            Self::Off => false,
        }
    }
}

/// Concrete destinations selected by an application host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservabilityOutput {
    Console,
    File(PathBuf),
    ConsoleAndFile(PathBuf),
}

/// Fully resolved observability settings, independent of their CLI, file, or
/// environment source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservabilityConfig {
    pub level: LevelFilter,
    pub output: ObservabilityOutput,
}

impl ObservabilityConfig {
    pub fn build(self) -> io::Result<RuntimeObservability> {
        let store = Arc::new(ObservabilityStore::default());
        let mut sink = CompositeObservabilitySink::new().with_sink(store.clone());

        if matches!(
            self.output,
            ObservabilityOutput::Console | ObservabilityOutput::ConsoleAndFile(_)
        ) {
            sink = sink.with_sink(Arc::new(ConsoleObservabilitySink::stderr(self.level)));
        }

        if let ObservabilityOutput::File(path) | ObservabilityOutput::ConsoleAndFile(path) =
            self.output
        {
            sink = sink.with_sink(Arc::new(FileObservabilitySink::append(path, self.level)?));
        }

        Ok(RuntimeObservability {
            sink: Arc::new(sink),
            store,
        })
    }
}

pub struct RuntimeObservability {
    pub sink: Arc<CompositeObservabilitySink>,
    pub store: Arc<ObservabilityStore>,
}

/// 控制台 sink，用于 CLI 默认观测输出。
#[derive(Clone, Debug)]
pub struct ConsoleObservabilitySink {
    stream: ConsoleStream,
    level: LevelFilter,
}

impl ConsoleObservabilitySink {
    pub fn stderr(level: LevelFilter) -> Self {
        Self {
            stream: ConsoleStream::Stderr,
            level,
        }
    }

    pub fn stdout(level: LevelFilter) -> Self {
        Self {
            stream: ConsoleStream::Stdout,
            level,
        }
    }

    pub fn stderr_from_env() -> Self {
        Self::stderr(LevelFilter::from_env())
    }

    pub fn level(&self) -> LevelFilter {
        self.level
    }
}

impl ObservabilitySink for ConsoleObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.level.allows(event.level) {
                return;
            }

            let line = format_event(&event);
            match self.stream {
                ConsoleStream::Stdout => println!("{line}"),
                ConsoleStream::Stderr => eprintln!("{line}"),
            }
        })
    }
}

/// 记录型 sink，供测试和嵌入方断言事件序列。
#[derive(Debug, Default)]
pub struct RecordingObservabilitySink {
    events: Mutex<Vec<Event>>,
}

impl RecordingObservabilitySink {
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .expect("recording observability sink lock")
            .clone()
    }
}

impl ObservabilitySink for RecordingObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("recording observability sink lock")
                .push(event);
        })
    }
}

/// 组合 sink，用于同时输出到 console、文件、metrics store、平台日志或遥测。
#[derive(Clone, Default)]
pub struct CompositeObservabilitySink {
    sinks: Vec<Arc<dyn ObservabilitySink>>,
}

impl CompositeObservabilitySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sink(mut self, sink: Arc<dyn ObservabilitySink>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl ObservabilitySink for CompositeObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            for sink in &self.sinks {
                sink.emit(event.clone()).await;
            }
        })
    }
}

/// 可由控制面、FFI、HTTP/gRPC API 查询的观测状态。
#[derive(Debug)]
pub struct ObservabilityStore {
    inner: Mutex<ObservabilityStoreInner>,
    event_limit: usize,
}

impl ObservabilityStore {
    pub fn new(event_limit: usize) -> Self {
        Self {
            inner: Mutex::new(ObservabilityStoreInner::default()),
            event_limit,
        }
    }

    pub fn snapshot(&self) -> ObservabilitySnapshot {
        let inner = self.inner.lock().expect("observability store lock");
        ObservabilitySnapshot {
            metrics: inner.metrics.clone(),
            connections: inner.connections.values().cloned().collect(),
            recent_events: inner.events.clone(),
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

    pub fn query_events(&self, query: ObservabilityQuery) -> Vec<Event> {
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

    fn record(&self, event: Event) {
        let mut inner = self.inner.lock().expect("observability store lock");
        inner.apply_event(&event);
        inner.events.push(event);
        if inner.events.len() > self.event_limit {
            inner.events.remove(0);
        }
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
    events: Vec<Event>,
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
                        },
                    );
                }
            }
            EventKind::RouteSelected { .. } => {
                self.metrics.routes_selected = self.metrics.routes_selected.saturating_add(1);
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

/// 文件日志 sink。文件 sink 属于宿主适配层，不进入可移植核心。
#[derive(Debug)]
pub struct FileObservabilitySink {
    level: LevelFilter,
    file: Mutex<File>,
}

impl FileObservabilitySink {
    pub fn append(path: impl AsRef<Path>, level: LevelFilter) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            level,
            file: Mutex::new(file),
        })
    }
}

impl ObservabilitySink for FileObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.level.allows(event.level) {
                return;
            }
            let line = format_event(&event);
            let mut file = self.file.lock().expect("file observability sink lock");
            let _ = writeln!(file, "{line}");
        })
    }
}

/// 平台日志后端。Windows ETW、Android logcat、Apple unified logging 等由宿主实现。
pub trait PlatformLogBackend: Send + Sync {
    fn log(&self, event: &Event, formatted: &str);
}

#[derive(Debug)]
pub struct PlatformLogSink<B> {
    level: LevelFilter,
    backend: B,
}

impl<B> PlatformLogSink<B>
where
    B: PlatformLogBackend,
{
    pub fn new(backend: B, level: LevelFilter) -> Self {
        Self { level, backend }
    }
}

impl<B> ObservabilitySink for PlatformLogSink<B>
where
    B: PlatformLogBackend,
{
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.level.allows(event.level) {
                let formatted = format_event(&event);
                self.backend.log(&event, &formatted);
            }
        })
    }
}

/// 远程遥测导出器。HTTP/gRPC/OTLP 客户端由宿主或外层 crate 适配。
pub trait TelemetryExporter: Send + Sync {
    fn export(&self, event: Event) -> BoxFuture<'_, Result<(), TelemetryError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryError {
    pub message: String,
}

impl TelemetryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub struct RemoteTelemetrySink<E> {
    level: LevelFilter,
    exporter: E,
}

impl<E> RemoteTelemetrySink<E>
where
    E: TelemetryExporter,
{
    pub fn new(exporter: E, level: LevelFilter) -> Self {
        Self { level, exporter }
    }
}

impl<E> ObservabilitySink for RemoteTelemetrySink<E>
where
    E: TelemetryExporter,
{
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.level.allows(event.level) {
                let _ = self.exporter.export(event).await;
            }
        })
    }
}

/// 将结构化事件渲染为当前 CLI 友好的单行文本。
pub fn format_event(event: &Event) -> String {
    let flow = event
        .flow_id
        .map(|id| format!(" flow={}", id.get()))
        .unwrap_or_default();

    format!(
        "[{}] {}{} {}",
        format_level(event.level),
        format_target(&event.target),
        flow,
        format_kind(&event.kind)
    )
}

fn format_level(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "TRACE",
        EventLevel::Debug => "DEBUG",
        EventLevel::Info => "INFO",
        EventLevel::Warn => "WARN",
        EventLevel::Error => "ERROR",
    }
}

fn format_target(target: &EventTarget) -> &str {
    target.0.as_str()
}

fn format_kind(kind: &EventKind) -> String {
    match kind {
        EventKind::ServiceStarting { service } => {
            format!("service_starting service={service}")
        }
        EventKind::ServiceStarted { service } => {
            format!("service_started service={service}")
        }
        EventKind::ServiceStopping { service } => {
            format!("service_stopping service={service}")
        }
        EventKind::ServiceStopped { service } => {
            format!("service_stopped service={service}")
        }
        EventKind::ConnectionAccepted { listener, peer } => {
            format!("connection_accepted listener={listener} peer={peer}")
        }
        EventKind::FlowAccepted {
            source,
            destination,
            network,
        } => {
            format!("flow_accepted source={source} destination={destination} network={network}")
        }
        EventKind::RouteSelected { decision } => {
            format!("route_selected decision={decision}")
        }
        EventKind::OutboundConnecting { outbound, target } => {
            format!("outbound_connecting outbound={outbound} target={target}")
        }
        EventKind::OutboundConnected { outbound, target } => {
            format!("outbound_connected outbound={outbound} target={target}")
        }
        EventKind::OutboundFailed {
            outbound,
            target,
            error,
        } => {
            format!("outbound_failed outbound={outbound} target={target} error={error}")
        }
        EventKind::FlowCompleted { outcome } => {
            format!("flow_completed outcome={outcome}")
        }
        EventKind::TrafficRecorded {
            inbound_to_outbound_bytes,
            outbound_to_inbound_bytes,
        } => {
            format!(
                "traffic_recorded inbound_to_outbound_bytes={inbound_to_outbound_bytes} outbound_to_inbound_bytes={outbound_to_inbound_bytes}"
            )
        }
        EventKind::FlowFailed { error } => {
            format!("flow_failed error={error}")
        }
        EventKind::Diagnostic(message) => {
            format!("diagnostic message={message}")
        }
    }
}

fn level_at_least(level: EventLevel, min_level: EventLevel) -> bool {
    level_rank(level) >= level_rank(min_level)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn formats_structured_event_with_flow_id() {
        let event = Event::new(
            EventLevel::Info,
            "rustbox.test",
            Some(rustbox_types::FlowId::new(
                core::num::NonZeroU64::new(7).expect("non-zero"),
            )),
            EventKind::FlowCompleted {
                outcome: "Forwarded".to_string(),
            },
        );

        assert_eq!(
            format_event(&event),
            "[INFO] rustbox.test flow=7 flow_completed outcome=Forwarded"
        );
    }

    #[test]
    fn parses_level_filter() {
        assert_eq!(LevelFilter::parse("debug"), Some(LevelFilter::Debug));
        assert_eq!(LevelFilter::parse("off"), Some(LevelFilter::Off));
        assert_eq!(LevelFilter::parse("loud"), None);
    }

    #[test]
    fn store_tracks_metrics_and_connections() {
        let store = ObservabilityStore::default();
        let flow_id = rustbox_types::FlowId::new(core::num::NonZeroU64::new(9).expect("non-zero"));

        block_on_ready(store.emit(Event::new(
            EventLevel::Info,
            "rustbox.kernel.flow",
            Some(flow_id),
            EventKind::FlowAccepted {
                source: "127.0.0.1:1000".to_string(),
                destination: "example.test:443".to_string(),
                network: "Tcp".to_string(),
            },
        )));
        block_on_ready(store.emit(Event::new(
            EventLevel::Debug,
            "rustbox.kernel.traffic",
            Some(flow_id),
            EventKind::TrafficRecorded {
                inbound_to_outbound_bytes: 4,
                outbound_to_inbound_bytes: 6,
            },
        )));
        block_on_ready(store.emit(Event::new(
            EventLevel::Info,
            "rustbox.kernel.flow",
            Some(flow_id),
            EventKind::FlowCompleted {
                outcome: "Forwarded".to_string(),
            },
        )));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.metrics.flows_accepted, 1);
        assert_eq!(snapshot.metrics.flows_completed, 1);
        assert_eq!(snapshot.metrics.flows_active, 0);
        assert_eq!(snapshot.metrics.inbound_to_outbound_bytes, 4);
        assert_eq!(snapshot.metrics.outbound_to_inbound_bytes, 6);
        assert_eq!(snapshot.connections[0].state, ConnectionState::Completed);
        assert_eq!(snapshot.connections[0].inbound_to_outbound_bytes, 4);
    }

    #[test]
    fn query_filters_recent_events() {
        let store = ObservabilityStore::default();
        block_on_ready(store.emit(Event::new(
            EventLevel::Info,
            "rustbox.kernel.flow",
            None,
            EventKind::Diagnostic("flow".to_string()),
        )));
        block_on_ready(store.emit(Event::new(
            EventLevel::Warn,
            "rustbox.inbound.http",
            None,
            EventKind::Diagnostic("http".to_string()),
        )));

        let events = store.query_events(ObservabilityQuery {
            min_level: Some(EventLevel::Warn),
            target_prefix: Some("rustbox.inbound".to_string()),
            flow_id: None,
            limit: Some(1),
        });

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target.0, "rustbox.inbound.http");
    }

    #[test]
    fn composite_fans_out_events() {
        let first = Arc::new(RecordingObservabilitySink::default());
        let second = Arc::new(RecordingObservabilitySink::default());
        let composite = CompositeObservabilitySink::new()
            .with_sink(first.clone())
            .with_sink(second.clone());

        block_on_ready(composite.emit(Event::new(
            EventLevel::Info,
            "rustbox.test",
            None,
            EventKind::Diagnostic("fanout".to_string()),
        )));

        assert_eq!(first.events().len(), 1);
        assert_eq!(second.events().len(), 1);
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
