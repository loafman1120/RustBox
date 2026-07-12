use rustbox_control::{EngineSnapshot, EngineState};
use rustbox_observability::MetricsSnapshot;
use std::os::raw::c_char;
use std::ptr;

pub const ABI_VERSION: u32 = 1;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustBoxEngineHandle(pub u64);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxStatusCode {
    Ok = 0,
    InvalidConfig = 1,
    NotFound = 2,
    AlreadyRunning = 3,
    RuntimeError = 4,
    InvalidArgument = 5,
    LockPoisoned = 6,
    InternalError = 7,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxEngineStateCode {
    Created = 0,
    Prepared = 1,
    Running = 2,
    Stopping = 3,
    Stopped = 4,
    Failed = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustBoxFfiEngineSnapshot {
    pub state: RustBoxEngineStateCode,
    pub generation: u64,
    pub inbound_count: u64,
    pub outbound_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RustBoxFfiMetricsSnapshot {
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

/// A diagnostic produced by an FFI call.
///
/// Call `rustbox_diagnostic_clear` before reusing the same value. Successful
/// calls set `message` to null and do not allocate.
#[repr(C)]
#[derive(Debug)]
pub struct RustBoxFfiDiagnostic {
    pub code: RustBoxStatusCode,
    pub message: *mut c_char,
}

impl Default for RustBoxFfiDiagnostic {
    fn default() -> Self {
        Self {
            code: RustBoxStatusCode::Ok,
            message: ptr::null_mut(),
        }
    }
}

impl From<EngineSnapshot> for RustBoxFfiEngineSnapshot {
    fn from(snapshot: EngineSnapshot) -> Self {
        Self {
            state: snapshot.state.into(),
            generation: snapshot.generation,
            inbound_count: snapshot.inbound_count as u64,
            outbound_count: snapshot.outbound_count as u64,
        }
    }
}

impl From<EngineState> for RustBoxEngineStateCode {
    fn from(state: EngineState) -> Self {
        match state {
            EngineState::Created => Self::Created,
            EngineState::Prepared => Self::Prepared,
            EngineState::Running => Self::Running,
            EngineState::Stopping => Self::Stopping,
            EngineState::Stopped => Self::Stopped,
            EngineState::Failed => Self::Failed,
        }
    }
}

impl From<MetricsSnapshot> for RustBoxFfiMetricsSnapshot {
    fn from(metrics: MetricsSnapshot) -> Self {
        Self {
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
}
