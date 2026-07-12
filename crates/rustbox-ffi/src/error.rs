use crate::abi::RustBoxStatusCode;
use rustbox::RustBoxError;
use rustbox_config_file::ConfigFileError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustBoxFfiError {
    pub code: RustBoxStatusCode,
    pub diagnostic: String,
}

impl RustBoxFfiError {
    pub fn new(code: RustBoxStatusCode, diagnostic: impl Into<String>) -> Self {
        Self {
            code,
            diagnostic: diagnostic.into(),
        }
    }

    pub(crate) fn unknown_handle() -> Self {
        Self::new(RustBoxStatusCode::NotFound, "unknown handle")
    }

    pub(crate) fn lock_poisoned(lock: &str) -> Self {
        Self::new(
            RustBoxStatusCode::LockPoisoned,
            format!("FFI {lock} lock is poisoned"),
        )
    }
}

impl From<ConfigFileError> for RustBoxFfiError {
    fn from(error: ConfigFileError) -> Self {
        Self::new(RustBoxStatusCode::InvalidConfig, error.message)
    }
}

impl From<RustBoxError> for RustBoxFfiError {
    fn from(error: RustBoxError) -> Self {
        compose_error(error)
    }
}

pub(crate) fn compose_error(error: RustBoxError) -> RustBoxFfiError {
    RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, format!("{error:?}"))
}
