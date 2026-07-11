//! Transparent proxy inbound.
//!
//! The service is portable: it accepts already-captured streams from a host
//! `TransparentProxyProvider`, turns original-destination metadata into a
//! `Flow`, and leaves redirect/TPROXY/WFP mechanics to platform adapters.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NoopObservabilitySink, ObservabilitySink, TaskName,
    TaskSpawner, TransparentProxyProvider, TransparentRedirectMode, TransparentTcpBind,
};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{Endpoint, FlowId, FlowMeta, InboundId, Network};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentInboundConfig {
    pub mode: TransparentRedirectMode,
    pub mark: Option<u32>,
}

pub struct TransparentProxyInbound {
    id: InboundId,
    listen: Endpoint,
    provider: Arc<dyn TransparentProxyProvider>,
    spawner: Arc<dyn TaskSpawner>,
    sink: Arc<dyn FlowSink>,
    config: TransparentInboundConfig,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl TransparentProxyInbound {
    pub fn new(
        id: InboundId,
        listen: Endpoint,
        provider: Arc<dyn TransparentProxyProvider>,
        spawner: Arc<dyn TaskSpawner>,
        sink: Arc<dyn FlowSink>,
        config: TransparentInboundConfig,
    ) -> Self {
        Self {
            id,
            listen,
            provider,
            spawner,
            sink,
            config,
            observability: Arc::new(NoopObservabilitySink),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            local_endpoint: Arc::new(Mutex::new(None)),
            started: AtomicBool::new(false),
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("transparent inbound endpoint lock")
            .clone()
    }
}

impl Inbound for TransparentProxyInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for TransparentProxyInbound {
    fn start(&mut self, _ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("transparent inbound already started"));
            }

            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.transparent",
                    None,
                    EventKind::ServiceStarting {
                        service: format!("transparent/{}", self.id),
                    },
                ))
                .await;

            let listener = self
                .provider
                .bind_tcp(TransparentTcpBind {
                    listen: self.listen.clone(),
                    mode: self.config.mode,
                    mark: self.config.mark,
                })
                .await
                .map_err(|err| ServiceError::new(err.message))?;
            let local_endpoint = listener
                .local_endpoint()
                .unwrap_or_else(|| self.listen.clone());
            let local_endpoint_text = local_endpoint.to_string();
            *self
                .local_endpoint
                .lock()
                .expect("transparent inbound endpoint lock") = Some(local_endpoint);

            let id = self.id;
            let sink = Arc::clone(&self.sink);
            let observability = Arc::clone(&self.observability);
            let next_flow_id = Arc::clone(&self.next_flow_id);
            self.spawner
                .spawn(
                    TaskName("transparent-inbound-accept".to_string()),
                    Box::pin(async move {
                        accept_loop(id, listener, sink, observability, next_flow_id).await;
                    }),
                )
                .map_err(|err| ServiceError::new(err.message))?;

            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.transparent",
                    None,
                    EventKind::ServiceStarted {
                        service: format!("transparent/{id}@{local_endpoint_text}"),
                    },
                ))
                .await;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.started.store(false, Ordering::SeqCst);
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.transparent",
                    None,
                    EventKind::ServiceStopped {
                        service: format!("transparent/{}", self.id),
                    },
                ))
                .await;
            Ok(())
        })
    }
}

async fn accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn rustbox_host_api::TransparentStreamListener>,
    sink: Arc<dyn FlowSink>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
) {
    let listener_endpoint = listener
        .local_endpoint()
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    loop {
        let accepted = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                observability
                    .emit(Event::new(
                        EventLevel::Warn,
                        "rustbox.inbound.transparent",
                        None,
                        EventKind::Diagnostic(format!(
                            "transparent accept failed on {listener_endpoint}: {}",
                            err.message
                        )),
                    ))
                    .await;
                break;
            }
        };

        observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.inbound.transparent",
                None,
                EventKind::ConnectionAccepted {
                    listener: listener_endpoint.clone(),
                    peer: accepted.peer.to_string(),
                },
            ))
            .await;

        let flow_id_raw = next_flow_id.fetch_add(1, Ordering::Relaxed);
        let flow_id = FlowId::new(NonZeroU64::new(flow_id_raw.max(1)).expect("non-zero flow id"));
        let flow = Flow {
            meta: FlowMeta {
                id: flow_id,
                network: Network::Tcp,
                source: accepted.peer,
                destination: accepted.original_destination.clone(),
                inbound: inbound_id,
                domain: Some(accepted.original_destination.host.clone()),
                protocol_hint: None,
            },
            payload: FlowPayload::Stream(accepted.stream),
        };

        let _ = sink.submit(flow).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use rustbox_host_api::{AcceptedTransparentStream, TransparentProxyError};
    use rustbox_kernel::{FlowOutcome, FlowSink};
    use std::io;
    use std::sync::Mutex;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[test]
    fn starts_with_transparent_provider() {
        let provider = Arc::new(FakeTransparentProvider);
        let spawner = Arc::new(FakeSpawner);
        let sink = Arc::new(RecordingSink::default());
        let mut inbound = TransparentProxyInbound::new(
            InboundId::new(NonZeroU64::new(1).expect("id")),
            Endpoint::localhost_v4(12345),
            provider,
            spawner,
            sink,
            TransparentInboundConfig {
                mode: TransparentRedirectMode::Redirect,
                mark: None,
            },
        );

        block_on_ready(inbound.start(ServiceContext {
            engine_name: "test",
        }))
        .expect("start transparent inbound");

        assert_eq!(
            inbound.local_endpoint(),
            Some(Endpoint::localhost_v4(12345))
        );
    }

    #[derive(Default)]
    struct FakeTransparentProvider;

    impl TransparentProxyProvider for FakeTransparentProvider {
        fn bind_tcp(
            &self,
            request: TransparentTcpBind,
        ) -> BoxFuture<
            '_,
            Result<Box<dyn rustbox_host_api::TransparentStreamListener>, TransparentProxyError>,
        > {
            Box::pin(async move {
                Ok(Box::new(FakeTransparentListener {
                    listen: request.listen,
                })
                    as Box<dyn rustbox_host_api::TransparentStreamListener>)
            })
        }
    }

    struct FakeTransparentListener {
        listen: Endpoint,
    }

    impl rustbox_host_api::TransparentStreamListener for FakeTransparentListener {
        fn local_endpoint(&self) -> Option<Endpoint> {
            Some(self.listen.clone())
        }

        fn accept(
            &mut self,
        ) -> BoxFuture<'_, Result<AcceptedTransparentStream, TransparentProxyError>> {
            Box::pin(async { Err(TransparentProxyError::new("done")) })
        }
    }

    #[derive(Default)]
    struct FakeSpawner;

    impl rustbox_host_api::TaskSpawner for FakeSpawner {
        fn spawn(
            &self,
            _name: rustbox_host_api::TaskName,
            _task: BoxFuture<'static, ()>,
        ) -> Result<rustbox_host_api::TaskHandle, rustbox_host_api::SpawnError> {
            Ok(rustbox_host_api::TaskHandle { id: 1 })
        }

        fn cancel(
            &self,
            _handle: rustbox_host_api::TaskHandle,
        ) -> Result<(), rustbox_host_api::SpawnError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        flows: Mutex<Vec<FlowMeta>>,
    }

    impl FlowSink for RecordingSink {
        fn submit(
            &self,
            flow: Flow,
        ) -> BoxFuture<'_, Result<FlowOutcome, rustbox_kernel::FlowError>> {
            self.flows.lock().expect("flows").push(flow.meta);
            Box::pin(async { Ok(FlowOutcome::Rejected(rustbox_types::RejectReason::Policy)) })
        }
    }

    #[allow(dead_code)]
    struct EmptyStream;

    impl AsyncRead for EmptyStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for EmptyStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut future = core::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
