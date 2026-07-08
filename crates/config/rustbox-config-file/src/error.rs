#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFileError {
    pub message: String,
}

impl ConfigFileError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
