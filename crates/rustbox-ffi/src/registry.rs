use crate::abi::{RustBoxEngineHandle, RustBoxStatusCode};
use crate::error::{RustBoxFfiError, compose_error};
use rustbox::{RustBox, RustBoxOptions};
use rustbox_config::SourceConfig;
use rustbox_control::{EngineSnapshot, EngineState};
use rustbox_observability::{MetricsSnapshot, ObservabilityStore, RuntimeObservability};
use rustbox_types::Endpoint;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tokio::runtime::{Builder, Runtime};

pub(crate) struct EngineRegistry {
    next: u64,
    engines: HashMap<RustBoxEngineHandle, Arc<Mutex<ManagedEngine>>>,
}

impl EngineRegistry {
    fn new() -> Self {
        Self {
            next: 1,
            engines: HashMap::new(),
        }
    }

    pub(crate) fn create(
        &mut self,
        source: SourceConfig,
        observability: RuntimeObservability,
    ) -> Result<RustBoxEngineHandle, RustBoxFfiError> {
        let engine = RustBox::with_options(
            source,
            RustBoxOptions::default().with_observability(observability.sink.clone()),
        )
        .map_err(compose_error)?;
        let observability_store = observability.store;
        let handle = RustBoxEngineHandle(self.next);
        self.next = self.next.checked_add(1).ok_or_else(|| {
            RustBoxFfiError::new(
                RustBoxStatusCode::InternalError,
                "engine handle space exhausted",
            )
        })?;
        self.engines.insert(
            handle,
            Arc::new(Mutex::new(ManagedEngine {
                engine,
                observability_store,
                runtime: None,
                destroyed: false,
            })),
        );
        Ok(handle)
    }

    fn get(
        &self,
        handle: RustBoxEngineHandle,
    ) -> Result<Arc<Mutex<ManagedEngine>>, RustBoxFfiError> {
        self.engines
            .get(&handle)
            .cloned()
            .ok_or_else(RustBoxFfiError::unknown_handle)
    }

    pub(crate) fn remove_if_same(
        &mut self,
        handle: RustBoxEngineHandle,
        expected: &Arc<Mutex<ManagedEngine>>,
    ) {
        if self
            .engines
            .get(&handle)
            .is_some_and(|current| Arc::ptr_eq(current, expected))
        {
            self.engines.remove(&handle);
        }
    }
}

pub(crate) struct ManagedEngine {
    engine: RustBox,
    observability_store: Arc<ObservabilityStore>,
    runtime: Option<Runtime>,
    destroyed: bool,
}

impl ManagedEngine {
    fn ensure_active(&self) -> Result<(), RustBoxFfiError> {
        if self.destroyed {
            Err(RustBoxFfiError::unknown_handle())
        } else {
            Ok(())
        }
    }

    pub(crate) fn snapshot(&self) -> Result<EngineSnapshot, RustBoxFfiError> {
        self.ensure_active()?;
        Ok(self.engine.snapshot().clone())
    }

    pub(crate) fn metrics(&self) -> Result<MetricsSnapshot, RustBoxFfiError> {
        self.ensure_active()?;
        Ok(self.observability_store.metrics())
    }

    pub(crate) fn start(&mut self) -> Result<(), RustBoxFfiError> {
        self.ensure_active()?;
        if self.engine.snapshot().state == EngineState::Running {
            return Err(RustBoxFfiError::new(
                RustBoxStatusCode::AlreadyRunning,
                "engine is already running",
            ));
        }
        let runtime = new_runtime()?;
        runtime
            .block_on(self.engine.start())
            .map_err(compose_error)?;
        self.runtime = Some(runtime);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> Result<(), RustBoxFfiError> {
        self.ensure_active()?;
        if let Some(runtime) = self.runtime.take() {
            let result = runtime.block_on(self.engine.stop()).map_err(compose_error);
            if result.is_err() && self.engine.snapshot().state == EngineState::Running {
                self.runtime = Some(runtime);
            }
            result?;
        }
        Ok(())
    }

    pub(crate) fn reload(&mut self, source: SourceConfig) -> Result<(), RustBoxFfiError> {
        self.ensure_active()?;
        let runtime = match self.runtime.take() {
            Some(runtime) => runtime,
            None => new_runtime()?,
        };
        let result = runtime
            .block_on(self.engine.reload(source))
            .map_err(compose_error);
        if self.engine.snapshot().state == EngineState::Running {
            self.runtime = Some(runtime);
        }
        result
    }

    pub(crate) fn destroy(&mut self) -> Result<(), RustBoxFfiError> {
        self.ensure_active()?;
        self.stop()?;
        self.destroyed = true;
        Ok(())
    }
}

fn new_runtime() -> Result<Runtime, RustBoxFfiError> {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, error.to_string()))
}

fn registry() -> &'static Mutex<EngineRegistry> {
    static REGISTRY: OnceLock<Mutex<EngineRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(EngineRegistry::new()))
}

pub(crate) fn registry_lock() -> Result<MutexGuard<'static, EngineRegistry>, RustBoxFfiError> {
    registry()
        .lock()
        .map_err(|_| RustBoxFfiError::lock_poisoned("engine table"))
}

pub(crate) fn engine_for(
    handle: RustBoxEngineHandle,
) -> Result<Arc<Mutex<ManagedEngine>>, RustBoxFfiError> {
    registry_lock()?.get(handle)
}

pub(crate) fn engine_lock(
    engine: &Arc<Mutex<ManagedEngine>>,
) -> Result<MutexGuard<'_, ManagedEngine>, RustBoxFfiError> {
    engine
        .lock()
        .map_err(|_| RustBoxFfiError::lock_poisoned("engine"))
}

pub(crate) fn default_http_source(port: u16) -> SourceConfig {
    SourceConfig::default_http_proxy(Endpoint::localhost_v4(port))
}

pub(crate) fn default_socks5_source(port: u16) -> SourceConfig {
    SourceConfig::default_socks5_proxy(Endpoint::localhost_v4(port))
}
