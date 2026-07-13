use crate::abi::{RustBoxFfiDiagnostic, RustBoxStatusCode};
use rustbox::HostedError;
use rustbox_config::SourceConfig;
use rustbox_config_file::{ConfigFileError, parse_toml_source};
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RustBoxFfiError {
    pub(crate) code: RustBoxStatusCode,
    pub(crate) diagnostic: String,
}

impl RustBoxFfiError {
    pub(crate) fn new(code: RustBoxStatusCode, diagnostic: impl Into<String>) -> Self {
        Self {
            code,
            diagnostic: diagnostic.into(),
        }
    }

    pub(crate) fn unknown_handle() -> Self {
        Self::new(RustBoxStatusCode::NotFound, "unknown handle")
    }

    pub(crate) fn lock_poisoned() -> Self {
        Self::new(
            RustBoxStatusCode::LockPoisoned,
            "engine table lock is poisoned",
        )
    }
}

impl From<ConfigFileError> for RustBoxFfiError {
    fn from(error: ConfigFileError) -> Self {
        Self::new(RustBoxStatusCode::InvalidConfig, error.message)
    }
}

pub(crate) fn hosted_error(error: HostedError) -> RustBoxFfiError {
    let code = match &error {
        HostedError::UnknownRequest => RustBoxStatusCode::NotFound,
        _ => RustBoxStatusCode::RuntimeError,
    };
    RustBoxFfiError::new(code, error.to_string())
}

pub(crate) fn call(
    diagnostic: *mut RustBoxFfiDiagnostic,
    operation: impl FnOnce() -> Result<(), RustBoxFfiError>,
) -> RustBoxStatusCode {
    let result = catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|panic| {
        let message = if let Some(message) = panic.downcast_ref::<&str>() {
            *message
        } else if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else {
            "unknown panic"
        };
        Err(RustBoxFfiError::new(
            RustBoxStatusCode::InternalError,
            format!("panic inside RustBox FFI: {message}"),
        ))
    });

    match result {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, None);
            RustBoxStatusCode::Ok
        }
        Err(error) => {
            write_diagnostic(diagnostic, error.code, Some(&error.diagnostic));
            error.code
        }
    }
}

pub(crate) fn parse_config_bytes(
    bytes: *const u8,
    len: usize,
) -> Result<SourceConfig, RustBoxFfiError> {
    parse_toml_source(config_text(bytes, len)?).map_err(Into::into)
}

fn config_text<'a>(bytes: *const u8, len: usize) -> Result<&'a str, RustBoxFfiError> {
    if bytes.is_null() {
        return Err(RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            "config bytes pointer must not be null",
        ));
    }
    let bytes = unsafe { slice::from_raw_parts(bytes, len) };
    std::str::from_utf8(bytes).map_err(|error| {
        RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            format!("config bytes must be UTF-8: {error}"),
        )
    })
}

pub(crate) fn ensure_out<T>(out: *mut T) -> Result<(), RustBoxFfiError> {
    if out.is_null() {
        Err(RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            "output pointer must not be null",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn write_out<T>(out: *mut T, value: T) -> Result<(), RustBoxFfiError> {
    ensure_out(out)?;
    unsafe { out.write(value) };
    Ok(())
}

fn write_diagnostic(
    diagnostic: *mut RustBoxFfiDiagnostic,
    code: RustBoxStatusCode,
    message: Option<&str>,
) {
    if diagnostic.is_null() {
        return;
    }
    let message = message
        .map(diagnostic_c_string)
        .map_or(ptr::null_mut(), CString::into_raw);
    unsafe { diagnostic.write(RustBoxFfiDiagnostic { code, message }) };
}

fn diagnostic_c_string(message: &str) -> CString {
    CString::new(message).unwrap_or_else(|error| {
        let bytes = error
            .into_vec()
            .into_iter()
            .map(|byte| if byte == 0 { b'?' } else { byte })
            .collect::<Vec<_>>();
        CString::new(bytes).expect("nul bytes were replaced")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn catches_panics() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();
        let code = call(&mut diagnostic, || panic!("test panic"));
        assert_eq!(code, RustBoxStatusCode::InternalError);
        let message = unsafe { CStr::from_ptr(diagnostic.message) };
        assert_eq!(
            message.to_string_lossy(),
            "panic inside RustBox FFI: test panic"
        );
        unsafe { drop(CString::from_raw(diagnostic.message)) };
    }
}
