use crate::ComposeError;
use rustbox_kernel::{Engine, Service, ServiceContext, ServiceError, TaskScope};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

const ACCEPT_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// 一代数据面及其 Tokio 任务域。
pub(crate) struct ComposedRuntime {
    generation: u64,
    engine: Arc<Engine>,
    services: Vec<Box<dyn Service>>,
    accept_tasks: TaskScope,
    session_tasks: TaskScope,
}

impl ComposedRuntime {
    pub(crate) fn new(engine: Arc<Engine>, services: Vec<Box<dyn Service>>) -> Self {
        Self {
            generation: 0,
            engine,
            services,
            accept_tasks: TaskScope::new(),
            session_tasks: TaskScope::new(),
        }
    }

    pub(crate) fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.engine.outbound_count()
    }

    pub(crate) fn service_count(&self) -> usize {
        self.services.len()
    }

    pub(crate) async fn start(&mut self) -> Result<(), ComposeError> {
        for index in 0..self.services.len() {
            let ctx = ServiceContext {
                generation: self.generation,
                accept_tasks: self.accept_tasks.clone(),
                session_tasks: self.session_tasks.clone(),
            };
            if let Err(error) = self.services[index].start(ctx).await {
                self.accept_tasks.close();
                self.accept_tasks.cancel();
                self.session_tasks.close();
                self.session_tasks.cancel();
                let _ = tokio::time::timeout(ACCEPT_STOP_TIMEOUT, self.accept_tasks.wait()).await;
                self.session_tasks.wait().await;
                // 失败的 service 也可能已经申请了部分平台资源。
                for service in self.services[..=index].iter_mut().rev() {
                    let _ = service.stop().await;
                }
                return Err(ComposeError::Service(error));
            }
        }
        Ok(())
    }

    /// 停止接入；已提交的 flow 继续持有本代 Engine。
    pub(crate) async fn retire(&mut self) {
        self.accept_tasks.close();
        self.accept_tasks.cancel();
        let _ = tokio::time::timeout(ACCEPT_STOP_TIMEOUT, self.accept_tasks.wait()).await;
        self.session_tasks.close();
    }

    pub(crate) async fn finish(mut self) -> Result<(), ComposeError> {
        if tokio::time::timeout(SESSION_DRAIN_TIMEOUT, self.session_tasks.wait())
            .await
            .is_err()
        {
            self.session_tasks.cancel();
            self.session_tasks.wait().await;
        }

        let mut errors = Vec::new();
        for service in self.services.iter_mut().rev() {
            if let Err(error) = service.stop().await {
                errors.push(error.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ComposeError::Service(ServiceError::new(errors.join("; "))))
        }
    }
}

/// 管理 active generation 和后台排空的旧 generation。
pub(crate) struct RuntimeSupervisor {
    active: Option<ComposedRuntime>,
    retired: Vec<JoinHandle<Result<(), ComposeError>>>,
    retired_errors: Vec<String>,
}

impl RuntimeSupervisor {
    pub(crate) fn new(runtime: ComposedRuntime) -> Self {
        Self {
            active: Some(runtime),
            retired: Vec::new(),
            retired_errors: Vec::new(),
        }
    }

    pub(crate) fn service_count(&self) -> usize {
        self.active
            .as_ref()
            .map_or(0, ComposedRuntime::service_count)
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.active
            .as_ref()
            .map_or(0, ComposedRuntime::outbound_count)
    }

    pub(crate) async fn start(&mut self, generation: u64) -> Result<(), ComposeError> {
        let runtime = self
            .active
            .as_mut()
            .ok_or_else(|| ComposeError::State("runtime is not prepared".into()))?;
        runtime.set_generation(generation);
        runtime.start().await
    }

    pub(crate) fn replace(&mut self, mut runtime: ComposedRuntime, generation: u64) {
        runtime.set_generation(generation);
        self.active = Some(runtime);
    }

    pub(crate) async fn reload(
        &mut self,
        mut next: ComposedRuntime,
        generation: u64,
    ) -> Result<(), ComposeError> {
        if let Some(mut current) = self.active.take() {
            current.retire().await;
            self.retired.push(tokio::spawn(current.finish()));
        }
        next.set_generation(generation);
        if let Err(error) = next.start().await {
            next.retire().await;
            let _ = next.finish().await;
            return Err(error);
        }
        self.active = Some(next);
        self.reap_finished().await;
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ComposeError> {
        let mut errors = std::mem::take(&mut self.retired_errors);
        if let Some(mut active) = self.active.take() {
            active.retire().await;
            if let Err(error) = active.finish().await {
                errors.push(format!("{error:?}"));
            }
        }
        for task in self.retired.drain(..) {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!("{error:?}")),
                Err(error) => errors.push(format!("retired generation task failed: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ComposeError::State(errors.join("; ")))
        }
    }

    async fn reap_finished(&mut self) {
        let mut pending = Vec::new();
        for task in self.retired.drain(..) {
            if task.is_finished() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self.retired_errors.push(format!("{error:?}")),
                    Err(error) => self
                        .retired_errors
                        .push(format!("retired generation task failed: {error}")),
                }
            } else {
                pending.push(task);
            }
        }
        self.retired = pending;
    }
}
