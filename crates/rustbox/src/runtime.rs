use crate::ComposeError;
use rustbox_kernel::{Engine, Service, ServiceContext};
use std::sync::Arc;

/// Fully composed data plane and its inbound services.
pub(crate) struct ComposedRuntime {
    engine: Arc<Engine>,
    services: Vec<Box<dyn Service>>,
}

impl ComposedRuntime {
    pub(crate) fn new(engine: Arc<Engine>, services: Vec<Box<dyn Service>>) -> Self {
        Self { engine, services }
    }

    pub(crate) fn engine(&self) -> Arc<Engine> {
        self.engine.clone()
    }

    pub(crate) fn service_count(&self) -> usize {
        self.services.len()
    }

    pub(crate) async fn start(&mut self, engine_name: &str) -> Result<(), ComposeError> {
        for service in &mut self.services {
            service
                .start(ServiceContext { engine_name })
                .await
                .map_err(ComposeError::Service)?;
        }
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ComposeError> {
        for service in self.services.iter_mut().rev() {
            service.stop().await.map_err(ComposeError::Service)?;
        }
        Ok(())
    }
}
