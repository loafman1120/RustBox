//! C ABI facade for RustBox.
//!
//! The ABI uses opaque integer handles, explicit status codes, caller-provided
//! output pointers, and Rust-owned diagnostic strings. Configuration and engine
//! lifecycle semantics remain in the shared Rust crates.

mod abi;
mod boundary;
mod registry;

pub use abi::{
    RustBoxEngineHandle, RustBoxEngineStateCode, RustBoxFfiDiagnostic, RustBoxFfiEngineSnapshot,
    RustBoxRequestHandle, RustBoxRequestStateCode, RustBoxStatusCode,
};

use abi::ABI_VERSION;
use boundary::{RustBoxFfiError, call, ensure_out, parse_config_bytes, write_out};
use registry::{engine_for, registry_lock};
use rustbox::{HostedRequestId, HostedRequestState};
use rustbox_observability::RuntimeObservability;
use std::ffi::CString;

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_ffi_abi_version() -> u32 {
    ABI_VERSION
}

fn create(
    source: rustbox_config::SourceConfig,
    observability: RuntimeObservability,
    out_handle: *mut RustBoxEngineHandle,
) -> Result<(), RustBoxFfiError> {
    ensure_out(out_handle)?;
    let handle = registry_lock()?.create(source, observability)?;
    write_out(out_handle, handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create(
    bytes: *const u8,
    len: usize,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        create(
            parse_config_bytes(bytes, len)?,
            RuntimeObservability::store_only(),
            out_handle,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_start(
    handle: RustBoxEngineHandle,
    out_request: *mut RustBoxRequestHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        ensure_out(out_request)?;
        let request = engine_for(handle)?.start()?;
        write_out(out_request, RustBoxRequestHandle(request.0))
    })
}

fn reload(
    handle: RustBoxEngineHandle,
    source: rustbox_config::SourceConfig,
    out_request: *mut RustBoxRequestHandle,
) -> Result<(), RustBoxFfiError> {
    ensure_out(out_request)?;
    let request = engine_for(handle)?.reload(source)?;
    write_out(out_request, RustBoxRequestHandle(request.0))
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload(
    handle: RustBoxEngineHandle,
    bytes: *const u8,
    len: usize,
    out_request: *mut RustBoxRequestHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        reload(handle, parse_config_bytes(bytes, len)?, out_request)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_snapshot(
    handle: RustBoxEngineHandle,
    out_snapshot: *mut RustBoxFfiEngineSnapshot,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        ensure_out(out_snapshot)?;
        let snapshot = engine_for(handle)?.snapshot()?;
        write_out(out_snapshot, snapshot.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_stop(
    handle: RustBoxEngineHandle,
    out_request: *mut RustBoxRequestHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        ensure_out(out_request)?;
        let request = engine_for(handle)?.stop()?;
        write_out(out_request, RustBoxRequestHandle(request.0))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_request_poll(
    handle: RustBoxEngineHandle,
    request: RustBoxRequestHandle,
    out_state: *mut RustBoxRequestStateCode,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        ensure_out(out_state)?;
        match engine_for(handle)?.poll_request(HostedRequestId(request.0))? {
            HostedRequestState::Pending => write_out(out_state, RustBoxRequestStateCode::Pending),
            HostedRequestState::Succeeded => {
                write_out(out_state, RustBoxRequestStateCode::Succeeded)
            }
            HostedRequestState::Failed(error) => {
                write_out(out_state, RustBoxRequestStateCode::Failed)?;
                Err(RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, error))
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_destroy(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        let engine = engine_for(handle)?;
        engine.destroy()?;
        registry_lock()?.remove_if_same(handle, &engine);
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Releases the current message and resets a diagnostic for reuse.
///
/// # Safety
/// `diagnostic` must be null or point to an initialized diagnostic value.
pub unsafe extern "C" fn rustbox_diagnostic_clear(diagnostic: *mut RustBoxFfiDiagnostic) {
    if diagnostic.is_null() {
        return;
    }
    let message = unsafe { (*diagnostic).message };
    if !message.is_null() {
        unsafe { drop(CString::from_raw(message)) };
    }
    unsafe { diagnostic.write(RustBoxFfiDiagnostic::default()) };
}

#[cfg(test)]
mod tests;
