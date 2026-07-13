//! Runtime-owning host for embedding RustBox.
//!
//! [`HostedRustBox`] keeps one Tokio runtime alive on a dedicated worker thread.
//! Callers submit lifecycle commands without blocking a UI/event-loop thread.
//! The worker and the CLI both execute the same asynchronous [`RustBox`]
//! lifecycle; this module only adapts it to request handles for embedding.

use crate::{RustBox, RustBoxError, RustBoxOptions};
use rustbox_config::SourceConfig;
use rustbox_control::EngineSnapshot;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

type Reply<T> = mpsc::SyncSender<Result<T, HostedError>>;

enum Command {
    StartAsync(HostedRequestId),
    StopAsync(HostedRequestId),
    ReloadAsync(HostedRequestId, SourceConfig),
    Snapshot(Reply<EngineSnapshot>),
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HostedRequestId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostedRequestState {
    Pending,
    Succeeded,
    Failed(String),
}

/// Failure returned by the managed host or its underlying RustBox engine.
#[derive(Debug)]
pub enum HostedError {
    Engine(RustBoxError),
    Runtime(String),
    UnknownRequest,
    Unavailable,
}

impl fmt::Display for HostedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "{error:?}"),
            Self::Runtime(error) => write!(formatter, "failed to create Tokio runtime: {error}"),
            Self::UnknownRequest => formatter.write_str("unknown lifecycle request"),
            Self::Unavailable => formatter.write_str("RustBox host worker is unavailable"),
        }
    }
}

impl std::error::Error for HostedError {}

impl From<RustBoxError> for HostedError {
    fn from(error: RustBoxError) -> Self {
        Self::Engine(error)
    }
}

/// A non-blocking lifecycle facade backed by a long-lived Tokio runtime.
pub struct HostedRustBox {
    commands: Sender<Command>,
    next_request: AtomicU64,
    requests: Arc<Mutex<HashMap<HostedRequestId, Option<Result<(), String>>>>>,
}

impl HostedRustBox {
    pub fn new(source: SourceConfig) -> Result<Self, HostedError> {
        Self::with_options(source, RustBoxOptions::default())
    }

    pub fn with_options(
        source: SourceConfig,
        options: RustBoxOptions,
    ) -> Result<Self, HostedError> {
        // Compose before spawning so invalid configuration is reported directly
        // and never leaves a partially initialized worker behind.
        let engine = RustBox::with_options(source, options)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("rustbox-runtime")
            .build()
            .map_err(|error| HostedError::Runtime(error.to_string()))?;
        let (commands, receiver) = mpsc::channel();
        let requests = Arc::new(Mutex::new(HashMap::new()));
        let worker_requests = requests.clone();
        thread::Builder::new()
            .name("rustbox-host".to_string())
            .spawn(move || run_worker(runtime, engine, receiver, worker_requests))
            .map_err(|error| HostedError::Runtime(error.to_string()))?;
        Ok(Self {
            commands,
            next_request: AtomicU64::new(1),
            requests,
        })
    }

    pub fn snapshot(&self) -> Result<EngineSnapshot, HostedError> {
        self.request(Command::Snapshot)
    }

    pub fn start(&self) -> Result<HostedRequestId, HostedError> {
        self.submit(Command::StartAsync)
    }

    pub fn stop(&self) -> Result<HostedRequestId, HostedError> {
        self.submit(Command::StopAsync)
    }

    pub fn reload(&self, source: SourceConfig) -> Result<HostedRequestId, HostedError> {
        self.submit(|request| Command::ReloadAsync(request, source))
    }

    /// Polls and consumes a completed request. Pending requests remain registered.
    pub fn poll_request(
        &self,
        request: HostedRequestId,
    ) -> Result<HostedRequestState, HostedError> {
        let mut requests = self.requests.lock().map_err(|_| HostedError::Unavailable)?;
        match requests.get(&request) {
            Some(None) => Ok(HostedRequestState::Pending),
            Some(Some(Ok(()))) => {
                requests.remove(&request);
                Ok(HostedRequestState::Succeeded)
            }
            Some(Some(Err(error))) => {
                let error = error.clone();
                requests.remove(&request);
                Ok(HostedRequestState::Failed(error))
            }
            None => Err(HostedError::UnknownRequest),
        }
    }

    fn submit(
        &self,
        command: impl FnOnce(HostedRequestId) -> Command,
    ) -> Result<HostedRequestId, HostedError> {
        let request = HostedRequestId(self.next_request.fetch_add(1, Ordering::Relaxed));
        self.requests
            .lock()
            .map_err(|_| HostedError::Unavailable)?
            .insert(request, None);
        if self.commands.send(command(request)).is_err() {
            if let Ok(mut requests) = self.requests.lock() {
                requests.remove(&request);
            }
            return Err(HostedError::Unavailable);
        }
        Ok(request)
    }

    fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, HostedError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(command(reply))
            .map_err(|_| HostedError::Unavailable)?;
        response.recv().map_err(|_| HostedError::Unavailable)?
    }
}

impl Drop for HostedRustBox {
    fn drop(&mut self) {
        // Shutdown stays on the worker so dropping an FFI handle never blocks
        // a Flutter/UI thread. Dropping JoinHandle detaches the worker safely.
        let _ = self.commands.send(Command::Shutdown);
    }
}

fn run_worker(
    runtime: tokio::runtime::Runtime,
    mut engine: RustBox,
    commands: Receiver<Command>,
    requests: Arc<Mutex<HashMap<HostedRequestId, Option<Result<(), String>>>>>,
) {
    while let Ok(command) = commands.recv() {
        match command {
            Command::StartAsync(request) => complete_request(
                &requests,
                request,
                runtime
                    .block_on(engine.start())
                    .map_err(|error| format!("{error:?}")),
            ),
            Command::StopAsync(request) => complete_request(
                &requests,
                request,
                runtime
                    .block_on(engine.stop())
                    .map_err(|error| format!("{error:?}")),
            ),
            Command::ReloadAsync(request, source) => complete_request(
                &requests,
                request,
                runtime
                    .block_on(engine.reload(source))
                    .map_err(|error| format!("{error:?}")),
            ),
            Command::Snapshot(reply) => {
                let _ = reply.send(Ok(engine.snapshot().clone()));
            }
            Command::Shutdown => {
                let _ = runtime.block_on(engine.stop());
                break;
            }
        }
    }
}

fn complete_request(
    requests: &Mutex<HashMap<HostedRequestId, Option<Result<(), String>>>>,
    request: HostedRequestId,
    result: Result<(), String>,
) {
    if let Ok(mut requests) = requests.lock()
        && let Some(entry) = requests.get_mut(&request)
    {
        *entry = Some(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_control::EngineState;
    use rustbox_types::Endpoint;

    #[test]
    fn submits_lifecycle_without_waiting_for_completion() {
        let host = HostedRustBox::new(SourceConfig::default_http_proxy(Endpoint::localhost_v4(0)))
            .expect("create host");
        let request = host.start().expect("submit start");
        loop {
            match host.poll_request(request).expect("poll start") {
                HostedRequestState::Pending => std::thread::yield_now(),
                HostedRequestState::Succeeded => break,
                HostedRequestState::Failed(error) => panic!("start failed: {error}"),
            }
        }
        assert_eq!(
            host.snapshot().expect("snapshot").state,
            EngineState::Running
        );
        let stop = host.stop().expect("submit stop");
        while host.poll_request(stop).expect("poll stop") == HostedRequestState::Pending {
            std::thread::yield_now();
        }
    }
}
