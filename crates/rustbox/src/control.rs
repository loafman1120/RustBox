use crate::{ComposeError, ControlGrpcOptions};
use rustbox_control::{ControlState, EngineCommand, EngineSnapshot};
use rustbox_control_api::ControlApiState;
use rustbox_observability::ObservabilityStore;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub(crate) struct ControlGrpcService {
    config: rustbox_control_api::ControlApiConfig,
    state: Arc<Mutex<ControlState>>,
    observability: Arc<ObservabilityStore>,
    command_tx: mpsc::UnboundedSender<EngineCommand>,
    command_rx: mpsc::UnboundedReceiver<EngineCommand>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), rustbox_control_api::ControlApiError>>>,
}

impl ControlGrpcService {
    pub(crate) fn new(options: ControlGrpcOptions, snapshot: EngineSnapshot) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Self {
            config: options.config,
            state: Arc::new(Mutex::new(ControlState::new(snapshot))),
            observability: options.observability,
            command_tx,
            command_rx,
            shutdown: None,
            task: None,
        }
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.config.listen
    }

    pub(crate) fn replace_snapshot(&self, snapshot: EngineSnapshot) {
        if let Ok(mut state) = self.state.lock() {
            state.replace_snapshot(snapshot);
        }
    }

    pub(crate) fn start(&mut self) {
        if self.task.is_some() {
            return;
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let state = ControlApiState::new(self.observability.clone(), self.state.clone())
            .with_command_sender(self.command_tx.clone());
        let config = self.config.clone();
        self.shutdown = Some(shutdown_tx);
        self.task = Some(tokio::spawn(async move {
            rustbox_control_api::serve_grpc(config, state, async {
                let _ = shutdown_rx.await;
            })
            .await
        }));
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ComposeError> {
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

    pub(crate) async fn next_command(&mut self) -> Option<EngineCommand> {
        self.command_rx.recv().await
    }
}
