use crate::abi::{RustBoxEngineHandle, RustBoxStatusCode};
use crate::boundary::{RustBoxFfiError, hosted_error};
use rustbox::{HostedRequestId, HostedRequestState, HostedRustBox, RustBoxOptions};
use rustbox_config::SourceConfig;
use rustbox_control::EngineSnapshot;
use rustbox_observability::RuntimeObservability;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

pub(crate) struct EngineRegistry {
    next: u64,
    engines: HashMap<RustBoxEngineHandle, Arc<ManagedEngine>>,
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
        let engine = HostedRustBox::with_options(
            source,
            RustBoxOptions::default().with_observability(observability.sink.clone()),
        )
        .map_err(hosted_error)?;
        let handle = RustBoxEngineHandle(self.next);
        self.next = self.next.checked_add(1).ok_or_else(|| {
            RustBoxFfiError::new(
                RustBoxStatusCode::InternalError,
                "engine handle space exhausted",
            )
        })?;
        self.engines.insert(
            handle,
            Arc::new(ManagedEngine {
                engine,
                destroyed: AtomicBool::new(false),
            }),
        );
        Ok(handle)
    }

    fn get(&self, handle: RustBoxEngineHandle) -> Result<Arc<ManagedEngine>, RustBoxFfiError> {
        self.engines
            .get(&handle)
            .cloned()
            .ok_or_else(RustBoxFfiError::unknown_handle)
    }

    pub(crate) fn remove_if_same(
        &mut self,
        handle: RustBoxEngineHandle,
        expected: &Arc<ManagedEngine>,
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
    engine: HostedRustBox,
    destroyed: AtomicBool,
}

impl ManagedEngine {
    fn ensure_active(&self) -> Result<(), RustBoxFfiError> {
        if self.destroyed.load(Ordering::Acquire) {
            Err(RustBoxFfiError::unknown_handle())
        } else {
            Ok(())
        }
    }

    pub(crate) fn snapshot(&self) -> Result<EngineSnapshot, RustBoxFfiError> {
        self.ensure_active()?;
        self.engine.snapshot().map_err(hosted_error)
    }

    pub(crate) fn start(&self) -> Result<HostedRequestId, RustBoxFfiError> {
        self.ensure_active()?;
        self.engine.start().map_err(hosted_error)
    }

    pub(crate) fn stop(&self) -> Result<HostedRequestId, RustBoxFfiError> {
        self.ensure_active()?;
        self.engine.stop().map_err(hosted_error)
    }

    pub(crate) fn reload(&self, source: SourceConfig) -> Result<HostedRequestId, RustBoxFfiError> {
        self.ensure_active()?;
        self.engine.reload(source).map_err(hosted_error)
    }

    pub(crate) fn poll_request(
        &self,
        request: HostedRequestId,
    ) -> Result<HostedRequestState, RustBoxFfiError> {
        self.ensure_active()?;
        self.engine.poll_request(request).map_err(hosted_error)
    }

    pub(crate) fn destroy(&self) -> Result<(), RustBoxFfiError> {
        self.destroyed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| RustBoxFfiError::unknown_handle())
    }
}

fn registry() -> &'static Mutex<EngineRegistry> {
    static REGISTRY: OnceLock<Mutex<EngineRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(EngineRegistry::new()))
}

pub(crate) fn registry_lock() -> Result<MutexGuard<'static, EngineRegistry>, RustBoxFfiError> {
    registry()
        .lock()
        .map_err(|_| RustBoxFfiError::lock_poisoned())
}

pub(crate) fn engine_for(
    handle: RustBoxEngineHandle,
) -> Result<Arc<ManagedEngine>, RustBoxFfiError> {
    registry_lock()?.get(handle)
}
