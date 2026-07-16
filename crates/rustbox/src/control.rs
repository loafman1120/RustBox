use crate::{ComposeError, ControlGrpcOptions};
use rustbox_control::OutboundGroupRegistry;
use rustbox_control::{ControlState, EngineCommand, EngineSnapshot};
use rustbox_control_api::ControlApiState;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const CONTROL_COMMAND_CAPACITY: usize = 32;

pub(crate) struct ControlGrpcService {
    config: rustbox_control_api::ControlApiConfig,
    listen: SocketAddr,
    api_state: ControlApiState,
    command_rx: mpsc::Receiver<EngineCommand>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), rustbox_control_api::ControlApiError>>>,
}

impl ControlGrpcService {
    pub(crate) fn new(
        options: ControlGrpcOptions,
        snapshot: EngineSnapshot,
        outbound_groups: Arc<OutboundGroupRegistry>,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::channel(CONTROL_COMMAND_CAPACITY);
        let control = Arc::new(Mutex::new(ControlState::new(snapshot)));
        let api_state = ControlApiState::new(options.observability, control)
            .with_command_sender(command_tx.clone())
            .with_outbound_groups(outbound_groups);
        Self {
            listen: options.config.listen,
            config: options.config,
            api_state,
            command_rx,
            shutdown: None,
            task: None,
        }
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn replace_snapshot(&self, snapshot: EngineSnapshot) {
        if let Ok(mut state) = self.api_state.control().lock() {
            state.replace_snapshot(snapshot);
        }
    }

    pub(crate) fn replace_outbound_groups(&self, groups: Arc<OutboundGroupRegistry>) {
        self.api_state.replace_outbound_groups(groups);
    }

    pub(crate) async fn start(&mut self) -> Result<(), ComposeError> {
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
        let state = self.api_state.clone();
        let config = self.config.clone();
        self.shutdown = Some(shutdown_tx);
        self.task = Some(tokio::spawn(async move {
            rustbox_control_api::serve_grpc_with_listener(config, state, listener, async {
                let _ = shutdown_rx.await;
            })
            .await
        }));
        Ok(())
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
