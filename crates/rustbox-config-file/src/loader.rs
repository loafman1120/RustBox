//! Configuration provider orchestration.
//!
//! Keeping provider selection here prevents the TOML document model from
//! depending on filesystem and layering details.

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;

use crate::ConfigFileError;

pub(crate) fn load_toml<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigFileError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ConfigFileError::new(format!(
            "failed to read config file `{}`: {error}",
            path.display()
        ))
    })?;
    parse_toml(&text)
}

pub(crate) fn load_toml_with_env<T: DeserializeOwned>(
    path: &Path,
    env_prefix: &str,
) -> Result<T, ConfigFileError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ConfigFileError::new(format!(
            "failed to read config file `{}`: {error}",
            path.display()
        ))
    })?;
    parse_toml_with_env(&text, env_prefix)
}

pub(crate) fn parse_toml<T: DeserializeOwned>(input: &str) -> Result<T, ConfigFileError> {
    Figment::from(Toml::string(input))
        .extract::<T>()
        .map_err(ConfigFileError::parse)
}

pub(crate) fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigFileError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ConfigFileError::new(format!(
            "failed to read config file `{}`: {error}",
            path.display()
        ))
    })?;
    parse_json(&text)
}

pub(crate) fn parse_json<T: DeserializeOwned>(input: &str) -> Result<T, ConfigFileError> {
    serde_json::from_str(input).map_err(ConfigFileError::parse_json)
}

pub(crate) fn parse_toml_with_env<T: DeserializeOwned>(
    input: &str,
    env_prefix: &str,
) -> Result<T, ConfigFileError> {
    Figment::from(Toml::string(input))
        .merge(Env::prefixed(env_prefix).split("__"))
        .extract::<T>()
        .map_err(ConfigFileError::parse)
}
