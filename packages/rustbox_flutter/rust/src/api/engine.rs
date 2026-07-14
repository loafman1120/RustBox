use rustbox::{RustBox, RustBoxOptions};
use rustbox_config_file::parse_toml_source;
use rustbox_control::{EngineSnapshot, EngineState};
use rustbox_observability::RuntimeObservability;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeErrorKind {
    InvalidConfig,
    InvalidState,
    Unavailable,
    Runtime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeError {
    pub kind: BridgeErrorKind,
    pub message: String,
}

impl BridgeError {
    fn invalid_config(message: impl Into<String>) -> Self {
        Self {
            kind: BridgeErrorKind::InvalidConfig,
            message: message.into(),
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BridgeError {}

impl From<rustbox::ComposeError> for BridgeError {
    fn from(error: rustbox::ComposeError) -> Self {
        let kind = match &error {
            rustbox::ComposeError::Config(_) => BridgeErrorKind::InvalidConfig,
            rustbox::ComposeError::State(_) => BridgeErrorKind::InvalidState,
            _ => BridgeErrorKind::Runtime,
        };
        Self {
            kind,
            message: format!("{error:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeEngineState {
    Created,
    Prepared,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl From<EngineState> for BridgeEngineState {
    fn from(state: EngineState) -> Self {
        match state {
            EngineState::Created => Self::Created,
            EngineState::Prepared => Self::Prepared,
            EngineState::Running => Self::Running,
            EngineState::Stopping => Self::Stopping,
            EngineState::Stopped => Self::Stopped,
            EngineState::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeEngineSnapshot {
    pub state: BridgeEngineState,
    pub generation: u64,
    pub inbound_count: u64,
    pub outbound_count: u64,
}

impl From<EngineSnapshot> for BridgeEngineSnapshot {
    fn from(snapshot: EngineSnapshot) -> Self {
        Self {
            state: snapshot.state.into(),
            generation: snapshot.generation,
            inbound_count: snapshot.inbound_count as u64,
            outbound_count: snapshot.outbound_count as u64,
        }
    }
}

#[flutter_rust_bridge::frb(opaque)]
pub struct NativeRustBoxEngine {
    engine: tokio::sync::Mutex<RustBox>,
}

impl NativeRustBoxEngine {
    pub fn create(config_toml: String) -> Result<Self, BridgeError> {
        let source = parse_toml_source(&config_toml)
            .map_err(|error| BridgeError::invalid_config(error.message))?;
        let observability = RuntimeObservability::store_only();
        let engine = RustBox::with_options(
            source,
            RustBoxOptions::default().with_observability(observability.sink),
        )?;
        Ok(Self {
            engine: tokio::sync::Mutex::new(engine),
        })
    }

    pub async fn start(&self) -> Result<(), BridgeError> {
        self.engine.lock().await.start().await.map_err(Into::into)
    }

    pub async fn reload(&self, config_toml: String) -> Result<(), BridgeError> {
        let source = parse_toml_source(&config_toml)
            .map_err(|error| BridgeError::invalid_config(error.message))?;
        self.engine
            .lock()
            .await
            .reload(source)
            .await
            .map_err(Into::into)
    }

    pub async fn snapshot(&self) -> BridgeEngineSnapshot {
        self.engine.lock().await.snapshot().clone().into()
    }

    pub async fn stop(&self) -> Result<(), BridgeError> {
        self.engine.lock().await.stop().await.map_err(Into::into)
    }

    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        self.stop().await
    }
}

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:0"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"#;

    #[tokio::test]
    async fn lifecycle_returns_completed_snapshots() {
        let engine = NativeRustBoxEngine::create(CONFIG.to_string()).expect("create");
        assert_eq!(engine.snapshot().await.state, BridgeEngineState::Prepared);
        engine.start().await.expect("start");
        assert_eq!(engine.snapshot().await.state, BridgeEngineState::Running);
        engine.reload(CONFIG.to_string()).await.expect("reload");
        assert_eq!(engine.snapshot().await.generation, 1);
        engine.stop().await.expect("stop");
        engine.shutdown().await.expect("shutdown");
        engine.shutdown().await.expect("repeated shutdown");
    }

    #[test]
    fn invalid_toml_has_stable_category() {
        let error = NativeRustBoxEngine::create("not toml".to_string())
            .err()
            .expect("invalid config");
        assert_eq!(error.kind, BridgeErrorKind::InvalidConfig);
    }
}
