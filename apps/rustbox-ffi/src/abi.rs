use rustbox_control::{EngineSnapshot, EngineState};
use std::os::raw::c_char;
use std::ptr;

pub const ABI_VERSION: u32 = 2;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustBoxEngineHandle(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustBoxRequestHandle(pub u64);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxRequestStateCode {
    Pending = 0,
    Succeeded = 1,
    Failed = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxStatusCode {
    Ok = 0,
    InvalidConfig = 1,
    NotFound = 2,
    RuntimeError = 3,
    InvalidArgument = 4,
    LockPoisoned = 5,
    InternalError = 6,
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
