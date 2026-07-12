use super::*;

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

pub(crate) fn level_at_least(level: EventLevel, min_level: EventLevel) -> bool {
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
