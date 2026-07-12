//! C ABI facade for RustBox.
//!
//! The ABI uses opaque integer handles, explicit status codes, caller-provided
//! output pointers, and Rust-owned diagnostic strings. Configuration and engine
//! lifecycle semantics remain in the shared Rust crates.

mod abi;
mod boundary;
mod error;
mod registry;

pub use abi::{
    RustBoxEngineHandle, RustBoxEngineStateCode, RustBoxFfiDiagnostic, RustBoxFfiEngineSnapshot,
    RustBoxFfiMetricsSnapshot, RustBoxStatusCode,
};
pub use error::RustBoxFfiError;

use abi::ABI_VERSION;
use boundary::{call, ensure_out, parse_config_bytes, parse_file_config_bytes, write_out};
use registry::{
    default_http_source, default_socks5_source, engine_for, engine_lock, registry_lock,
};
use rustbox::RustBox;
use rustbox_observability::RuntimeObservability;
use std::ffi::CString;
use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_ffi_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_default_http_proxy(
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        RustBox::new(default_http_source(listen_port))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_default_socks5_proxy(
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        RustBox::new(default_socks5_source(listen_port))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_config_toml(
    bytes: *const u8,
    len: usize,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        RustBox::new(parse_config_bytes(bytes, len)?)?;
        Ok(())
    })
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
pub extern "C" fn rustbox_engine_create_default_http_proxy(
    listen_port: u16,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        create(
            default_http_source(listen_port),
            RuntimeObservability::store_only(),
            out_handle,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create_default_socks5_proxy(
    listen_port: u16,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        create(
            default_socks5_source(listen_port),
            RuntimeObservability::store_only(),
            out_handle,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create_from_config_toml(
    bytes: *const u8,
    len: usize,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        let file = parse_file_config_bytes(bytes, len)?;
        let observability = match file.observability {
            Some(config) => config.runtime_config().build().map_err(|error| {
                RustBoxFfiError::new(
                    RustBoxStatusCode::RuntimeError,
                    format!("failed to configure observability output: {error}"),
                )
            })?,
            None => RuntimeObservability::store_only(),
        };
        create(file.source, observability, out_handle)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_start(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || engine_lock(&engine_for(handle)?)?.start())
}

fn reload(
    handle: RustBoxEngineHandle,
    source: rustbox_config::SourceConfig,
) -> Result<(), RustBoxFfiError> {
    engine_lock(&engine_for(handle)?)?.reload(source)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_default_http_proxy(
    handle: RustBoxEngineHandle,
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        reload(handle, default_http_source(listen_port))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_default_socks5_proxy(
    handle: RustBoxEngineHandle,
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        reload(handle, default_socks5_source(listen_port))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_config_toml(
    handle: RustBoxEngineHandle,
    bytes: *const u8,
    len: usize,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        reload(handle, parse_config_bytes(bytes, len)?)
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
        let snapshot = engine_lock(&engine_for(handle)?)?.snapshot()?;
        write_out(out_snapshot, snapshot.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_metrics(
    handle: RustBoxEngineHandle,
    out_metrics: *mut RustBoxFfiMetricsSnapshot,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        ensure_out(out_metrics)?;
        let metrics = engine_lock(&engine_for(handle)?)?.metrics()?;
        write_out(out_metrics, metrics.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_stop(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || engine_lock(&engine_for(handle)?)?.stop())
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_destroy(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    call(diagnostic, || {
        let engine = engine_for(handle)?;
        engine_lock(&engine)?.destroy()?;
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

#[unsafe(no_mangle)]
/// Frees a diagnostic message allocated by this library.
///
/// # Safety
/// `message` must be null or a live pointer returned in a diagnostic.
pub unsafe extern "C" fn rustbox_diagnostic_message_free(message: *mut c_char) {
    if !message.is_null() {
        unsafe { drop(CString::from_raw(message)) };
    }
}

#[cfg(test)]
mod tests;
