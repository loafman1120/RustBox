//! Coarse handle-based FFI boundary model.
//!
//! This crate intentionally keeps Rust traits, references, and runtime-specific
//! types behind an opaque handle table.

use rustbox_compose::{ComposeError, ComposedRuntime, TokioComposition};
use rustbox_config::{ConfigCompiler, ConfigError, SourceConfig};
use rustbox_control::{EngineSnapshot, EngineState};
use rustbox_types::Endpoint;
use std::collections::HashMap;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustBoxEngineHandle(pub u64);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxStatusCode {
    Ok = 0,
    InvalidConfig = 1,
    NotFound = 2,
    AlreadyRunning = 3,
    RuntimeError = 4,
}

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
}

pub struct FfiEngineTable {
    next: u64,
    engines: HashMap<RustBoxEngineHandle, ManagedEngine>,
}

impl FfiEngineTable {
    pub fn new() -> Self {
        Self {
            next: 1,
            engines: HashMap::new(),
        }
    }

    pub fn validate(source: SourceConfig) -> Result<(), RustBoxFfiError> {
        let parsed = ConfigCompiler::parse(source).map_err(config_error)?;
        let validated = ConfigCompiler::validate(parsed).map_err(config_error)?;
        ConfigCompiler::compile(validated).map_err(config_error)?;
        Ok(())
    }

    pub fn create_default_http_proxy(&mut self, listen: Endpoint) -> RustBoxEngineHandle {
        let handle = RustBoxEngineHandle(self.next);
        self.next = self.next.saturating_add(1);
        let source = SourceConfig::default_http_proxy(listen);
        self.engines.insert(
            handle,
            ManagedEngine {
                source,
                runtime: None,
                snapshot: EngineSnapshot::created(),
            },
        );
        handle
    }

    pub async fn start(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        let managed = self
            .engines
            .get_mut(&handle)
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))?;
        if managed.runtime.is_some() {
            return Err(RustBoxFfiError::new(
                RustBoxStatusCode::AlreadyRunning,
                "engine is already running",
            ));
        }

        let parsed = ConfigCompiler::parse(managed.source.clone()).map_err(config_error)?;
        let validated = ConfigCompiler::validate(parsed).map_err(config_error)?;
        let compiled = ConfigCompiler::compile(validated).map_err(config_error)?;
        let mut runtime = TokioComposition::new()
            .compose(compiled)
            .map_err(compose_error)?;
        runtime.start("rustbox-ffi").await.map_err(compose_error)?;
        managed.snapshot.state = EngineState::Running;
        managed.runtime = Some(runtime);
        Ok(())
    }

    pub async fn stop(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        let managed = self
            .engines
            .get_mut(&handle)
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))?;
        if let Some(runtime) = &mut managed.runtime {
            managed.snapshot.state = EngineState::Stopping;
            runtime.stop().await.map_err(compose_error)?;
            managed.runtime = None;
        }
        managed.snapshot.state = EngineState::Stopped;
        Ok(())
    }

    pub fn snapshot(&self, handle: RustBoxEngineHandle) -> Result<EngineSnapshot, RustBoxFfiError> {
        self.engines
            .get(&handle)
            .map(|managed| managed.snapshot.clone())
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))
    }

    pub fn destroy(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        self.engines
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))
    }
}

impl Default for FfiEngineTable {
    fn default() -> Self {
        Self::new()
    }
}

struct ManagedEngine {
    source: SourceConfig,
    runtime: Option<ComposedRuntime>,
    snapshot: EngineSnapshot,
}

fn config_error(err: ConfigError) -> RustBoxFfiError {
    RustBoxFfiError::new(RustBoxStatusCode::InvalidConfig, err.message)
}

fn compose_error(err: ComposeError) -> RustBoxFfiError {
    RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, format!("{err:?}"))
}
