use garde::Validate;
use rustbox_observability::{LevelFilter, ObservabilityOutput};
use serde::Deserialize;

use crate::{ConfigFileError, validation};

/// Application-level observability settings carried beside the runtime graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservabilityConfig {
    pub level: Option<LevelFilter>,
    pub output: ObservabilityOutput,
    pub platform: Option<bool>,
    pub remote_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub(super) struct TomlObservabilityConfig {
    #[garde(custom(validation::observability_level))]
    level: Option<String>,
    output: Option<TomlObservabilityOutput>,
    file: Option<String>,
    platform: Option<bool>,
    remote_endpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlObservabilityOutput {
    Console,
    File,
    ConsoleAndFile,
}

impl TomlObservabilityConfig {
    pub(super) fn into_file(self) -> Result<FileObservabilityConfig, ConfigFileError> {
        let level = match self.level.as_deref() {
            Some(value) => Some(LevelFilter::parse(value).ok_or_else(|| {
                ConfigFileError::new(
                    "invalid observability level; expected trace, debug, info, warn, error, or off",
                )
            })?),
            None => None,
        };
        let output = match (
            self.output.unwrap_or(TomlObservabilityOutput::Console),
            self.file,
        ) {
            (TomlObservabilityOutput::Console, None) => ObservabilityOutput::Console,
            (TomlObservabilityOutput::Console, Some(_)) => {
                return Err(ConfigFileError::new(
                    "observability.file requires output = \"file\" or \"console-and-file\"",
                ));
            }
            (TomlObservabilityOutput::File, Some(path)) => ObservabilityOutput::File(path.into()),
            (TomlObservabilityOutput::ConsoleAndFile, Some(path)) => {
                ObservabilityOutput::ConsoleAndFile(path.into())
            }
            (TomlObservabilityOutput::File | TomlObservabilityOutput::ConsoleAndFile, None) => {
                return Err(ConfigFileError::new(
                    "observability output requires a file path",
                ));
            }
        };
        Ok(FileObservabilityConfig {
            level,
            output,
            platform: self.platform,
            remote_endpoint: self.remote_endpoint,
        })
    }
}
