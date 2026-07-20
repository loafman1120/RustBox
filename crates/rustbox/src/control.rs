use crate::ComposeError;
use rustbox_clash_api::{ClashApiConfig, ClashApiError};
use rustbox_control::{ControlState, EngineSnapshot, OutboundGroupRegistry, RuleSetRegistry};
use rustbox_control_api::{ControlApiConfig, ControlApiError, ControlApiState};
use rustbox_control_service::{ControlCatalog, ControlCommand, ControlPlaneHandle, OutboundProbe};
use rustbox_observability::ObservabilityStore;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const CONTROL_COMMAND_CAPACITY: usize = 32;

pub(crate) struct ControlServices {
    plane: ControlPlaneHandle,
    command_rx: mpsc::Receiver<ControlCommand>,
    grpc: Option<GrpcTransport>,
    clash: Option<ClashTransport>,
}

pub(crate) struct ControlPlaneResources {
    pub(crate) observability: Arc<ObservabilityStore>,
    pub(crate) snapshot: EngineSnapshot,
    pub(crate) outbound_groups: Arc<OutboundGroupRegistry>,
    pub(crate) rule_sets: Arc<RuleSetRegistry>,
    pub(crate) catalog: Arc<ControlCatalog>,
    pub(crate) outbound_probe: Arc<dyn OutboundProbe>,
}

struct GrpcTransport {
    config: ControlApiConfig,
    listen: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), ControlApiError>>>,
}

struct ClashTransport {
    config: ClashApiConfig,
    listen: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), ClashApiError>>>,
}

impl ControlServices {
    pub(crate) fn new(
        grpc: Option<ControlApiConfig>,
        clash: Option<ClashApiConfig>,
        resources: ControlPlaneResources,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::channel(CONTROL_COMMAND_CAPACITY);
        let control = Arc::new(Mutex::new(ControlState::new(resources.snapshot)));
        let plane = ControlPlaneHandle::new(resources.observability, control)
            .with_command_sender(command_tx);
        plane.replace_outbound_groups(resources.outbound_groups);
        plane.replace_rule_sets(resources.rule_sets);
        plane.replace_catalog(resources.catalog);
        plane.replace_outbound_probe(resources.outbound_probe);
        Self {
            plane,
            command_rx,
            grpc: grpc.map(|config| GrpcTransport {
                listen: config.listen,
                config,
                shutdown: None,
                task: None,
            }),
            clash: clash.map(|config| ClashTransport {
                listen: config.listen,
                config,
                shutdown: None,
                task: None,
            }),
        }
    }

    pub(crate) fn grpc_listen(&self) -> Option<SocketAddr> {
        self.grpc.as_ref().map(|transport| transport.listen)
    }

    pub(crate) fn clash_listen(&self) -> Option<SocketAddr> {
        self.clash.as_ref().map(|transport| transport.listen)
    }

    pub(crate) fn replace_snapshot(&self, snapshot: EngineSnapshot) {
        if let Ok(mut state) = self.plane.control().lock() {
            state.replace_snapshot(snapshot);
        }
    }

    pub(crate) fn replace_outbound_groups(&self, groups: Arc<OutboundGroupRegistry>) {
        self.plane.replace_outbound_groups(groups);
    }

    pub(crate) fn replace_rule_sets(&self, rule_sets: Arc<RuleSetRegistry>) {
        self.plane.replace_rule_sets(rule_sets);
    }

    pub(crate) fn replace_catalog(&self, catalog: Arc<ControlCatalog>) {
        self.plane.replace_catalog(catalog);
    }

    pub(crate) fn replace_outbound_probe(&self, probe: Arc<dyn OutboundProbe>) {
        self.plane.replace_outbound_probe(probe);
    }

    pub(crate) async fn start(&mut self) -> Result<(), ComposeError> {
        if let Some(grpc) = &mut self.grpc {
            grpc.start(self.plane.clone()).await?;
        }
        if let Some(clash) = &mut self.clash
            && let Err(error) = clash.start(self.plane.clone()).await
        {
            if let Some(grpc) = &mut self.grpc {
                let _ = grpc.stop().await;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ComposeError> {
        let mut errors = Vec::new();
        if let Some(clash) = &mut self.clash
            && let Err(error) = clash.stop().await
        {
            errors.push(format!("{error:?}"));
        }
        if let Some(grpc) = &mut self.grpc
            && let Err(error) = grpc.stop().await
        {
            errors.push(format!("{error:?}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ComposeError::Control(errors.join("; ")))
        }
    }

    pub(crate) async fn next_command(&mut self) -> Option<ControlCommand> {
        self.command_rx.recv().await
    }
}

impl GrpcTransport {
    async fn start(&mut self, plane: ControlPlaneHandle) -> Result<(), ComposeError> {
        if self.task.is_some() {
            return Ok(());
        }
        let listener = tokio::net::TcpListener::bind(self.config.listen)
            .await
            .map_err(|error| {
                ComposeError::Control(format!("failed to bind control gRPC: {error}"))
            })?;
        self.listen = listener.local_addr().map_err(|error| {
            ComposeError::Control(format!("failed to read control gRPC address: {error}"))
        })?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let config = self.config.clone();
        self.shutdown = Some(shutdown_tx);
        self.task = Some(tokio::spawn(async move {
            rustbox_control_api::serve_grpc_with_listener(
                config,
                ControlApiState::from_plane(plane),
                listener,
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        }));
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ComposeError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(ComposeError::Control(error.to_string())),
            Err(error) => Err(ComposeError::Control(format!(
                "control gRPC task failed: {error}"
            ))),
        }
    }
}

impl ClashTransport {
    async fn start(&mut self, plane: ControlPlaneHandle) -> Result<(), ComposeError> {
        if self.task.is_some() {
            return Ok(());
        }
        let listener = tokio::net::TcpListener::bind(self.config.listen)
            .await
            .map_err(|error| ComposeError::Control(format!("failed to bind Clash API: {error}")))?;
        self.listen = listener.local_addr().map_err(|error| {
            ComposeError::Control(format!("failed to read Clash API address: {error}"))
        })?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let config = self.config.clone();
        self.shutdown = Some(shutdown_tx);
        self.task = Some(tokio::spawn(async move {
            rustbox_clash_api::serve_with_listener(config, plane, listener, async {
                let _ = shutdown_rx.await;
            })
            .await
        }));
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ComposeError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(ComposeError::Control(error.to_string())),
            Err(error) => Err(ComposeError::Control(format!(
                "Clash API task failed: {error}"
            ))),
        }
    }
}
