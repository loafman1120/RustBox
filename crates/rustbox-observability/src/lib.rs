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

mod config;
mod format;
mod sinks;
mod store;

pub use config::*;
pub use format::*;
pub use sinks::*;
pub use store::*;

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
