use crate::ComposeError;
use rustbox_control::{OutboundGroupRegistry, RuleSetRegistry};
use rustbox_dns_core::{DnsQuery, DnsResponse, DnsSubsystem};
use rustbox_inspect::FlowEnricher;
use rustbox_kernel::{Engine, Service, ServiceContext, ServiceError, TaskScope};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

const ACCEPT_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// 一代数据面及其 Tokio 任务域。
pub(crate) struct ComposedRuntime {
    generation: u64,
    engine: Arc<Engine<FlowEnricher>>,
    outbound_groups: Arc<OutboundGroupRegistry>,
    dns: Option<Arc<DnsSubsystem>>,
    services: Vec<Box<dyn Service>>,
    accept_tasks: TaskScope,
    session_tasks: TaskScope,
    urltest: crate::urltest::UrlTestController,
    rule_sets: crate::ruleset::RuleSetController,
}

impl ComposedRuntime {
    pub(crate) fn new(
        engine: Arc<Engine<FlowEnricher>>,
        services: Vec<Box<dyn Service>>,
        outbound_groups: Arc<OutboundGroupRegistry>,
        dns: Option<Arc<DnsSubsystem>>,
        session_tasks: TaskScope,
        urltest: crate::urltest::UrlTestController,
        rule_sets: crate::ruleset::RuleSetController,
    ) -> Self {
        Self {
            generation: 0,
            engine,
            outbound_groups,
            dns,
            services,
            accept_tasks: TaskScope::new(),
            session_tasks,
            urltest,
            rule_sets,
        }
    }

    pub(crate) fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.engine.outbound_count()
    }

    pub(crate) fn outbound_groups(&self) -> Arc<OutboundGroupRegistry> {
        self.outbound_groups.clone()
    }

    pub(crate) fn close_connection(&self, flow_id: u64) -> bool {
        self.engine.cancel_flow(flow_id)
    }

    pub(crate) fn trigger_urltest(&self, tag: &str) -> bool {
        self.urltest.trigger(tag)
    }

    pub(crate) fn refresh_rule_set(&self, tag: &str) -> bool {
        self.rule_sets.refresh(tag)
    }

    pub(crate) fn rule_sets(&self) -> Arc<RuleSetRegistry> {
        self.rule_sets.registry()
    }

    pub(crate) fn service_count(&self) -> usize {
        self.services.len()
    }

    pub(crate) async fn resolve_dns(&self, query: DnsQuery) -> Result<DnsResponse, ComposeError> {
        self.dns
            .as_ref()
            .ok_or_else(|| ComposeError::State("DNS subsystem is not configured".to_string()))?
            .resolve(query)
            .await
            .map_err(|error| ComposeError::State(error.message))
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
    retired: Vec<RetiredRuntime>,
    retired_errors: Vec<String>,
}

struct RetiredRuntime {
    engine: Arc<Engine<FlowEnricher>>,
    task: JoinHandle<Result<(), ComposeError>>,
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

    pub(crate) fn outbound_groups(&self) -> Arc<OutboundGroupRegistry> {
        self.active
            .as_ref()
            .map(ComposedRuntime::outbound_groups)
            .unwrap_or_default()
    }

    pub(crate) fn close_connection(&self, flow_id: u64) -> bool {
        let active = self
            .active
            .as_ref()
            .is_some_and(|runtime| runtime.close_connection(flow_id));
        self.retired.iter().fold(active, |found, retired| {
            retired.engine.cancel_flow(flow_id) || found
        })
    }

    pub(crate) fn trigger_urltest(&self, tag: &str) -> bool {
        self.active
            .as_ref()
            .is_some_and(|runtime| runtime.trigger_urltest(tag))
    }

    pub(crate) fn refresh_rule_set(&self, tag: &str) -> bool {
        self.active
            .as_ref()
            .is_some_and(|runtime| runtime.refresh_rule_set(tag))
    }

    pub(crate) fn rule_sets(&self) -> Arc<RuleSetRegistry> {
        self.active
            .as_ref()
            .map(ComposedRuntime::rule_sets)
            .unwrap_or_default()
    }

    pub(crate) async fn resolve_dns(&self, query: DnsQuery) -> Result<DnsResponse, ComposeError> {
        self.active
            .as_ref()
            .ok_or_else(|| ComposeError::State("runtime is not prepared".to_string()))?
            .resolve_dns(query)
            .await
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
            let engine = current.engine.clone();
            self.retired.push(RetiredRuntime {
                engine,
                task: tokio::spawn(current.finish()),
            });
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
        for retired in self.retired.drain(..) {
            match retired.task.await {
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
        for retired in self.retired.drain(..) {
            if retired.task.is_finished() {
                match retired.task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self.retired_errors.push(format!("{error:?}")),
                    Err(error) => self
                        .retired_errors
                        .push(format!("retired generation task failed: {error}")),
                }
            } else {
                pending.push(retired);
            }
        }
        self.retired = pending;
    }
}
