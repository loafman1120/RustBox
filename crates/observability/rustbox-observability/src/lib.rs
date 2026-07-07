//! 具体观测 sink。
//!
//! 可移植 crate 只发出 `rustbox-host-api` 的结构化事件；本 crate 决定事件
//! 如何打印、过滤或记录，避免核心绑定具体日志框架。

use rustbox_host_api::{BoxFuture, Event, EventKind, EventLevel, EventTarget, ObservabilitySink};
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
        EventKind::FlowFailed { error } => {
            format!("flow_failed error={error}")
        }
        EventKind::Diagnostic(message) => {
            format!("diagnostic message={message}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
