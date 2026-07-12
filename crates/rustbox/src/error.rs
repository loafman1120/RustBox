use rustbox_config::ConfigError;
use rustbox_kernel::{EngineError, ServiceError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposeError {
    Config(ConfigError),
    Control(String),
    Engine(EngineError),
    Service(ServiceError),
    State(String),
}
