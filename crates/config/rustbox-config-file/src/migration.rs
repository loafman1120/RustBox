use crate::{ConfigFileError, SUPPORTED_SCHEMA_VERSION};

pub(crate) fn accept_schema_version(schema_version: u32) -> Result<(), ConfigFileError> {
    if schema_version == SUPPORTED_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ConfigFileError::new(format!(
            "unsupported config schema_version `{schema_version}`"
        )))
    }
}
