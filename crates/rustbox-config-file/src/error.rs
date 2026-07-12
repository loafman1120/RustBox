use miette::Diagnostic;
use thiserror::Error;

/// A stable, application-facing configuration diagnostic.
///
/// The public `message` field is retained for the FFI and CLI facades while
/// `Diagnostic` lets richer frontends render the same error consistently.
#[derive(Clone, Debug, Diagnostic, Eq, Error, PartialEq)]
#[error("{message}")]
#[diagnostic(code(rustbox::config))]
pub struct ConfigFileError {
    pub message: String,
}

impl ConfigFileError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn parse(error: impl std::fmt::Display) -> Self {
        Self::new(format!("failed to parse TOML config: {error}"))
    }
}
