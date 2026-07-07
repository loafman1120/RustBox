use rustbox_control::{ControlState, EngineCommand, EngineSnapshot, EngineState};
use rustbox_control_api::rustbox_control_v1::{
    EngineState as ProtoEngineState, GetMetricsRequest, QueryEventsRequest, StopRequest,
    rust_box_control_client::RustBoxControlClient,
};
use rustbox_control_api::{AuthPolicy, ControlApiConfig, ControlApiState, serve_grpc};
use rustbox_host_api::{Event, EventKind, EventLevel, ObservabilitySink};
use rustbox_observability::ObservabilityStore;
use rustbox_types::FlowId;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep, timeout};
use tonic::{Code, Request};

#[tokio::test]
async fn serves_native_grpc_with_auth_and_stop_command() {
    let listen = free_loopback_addr();
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let state = sample_state().with_command_sender(command_tx);
    let config = ControlApiConfig {
        listen,
        auth: AuthPolicy::bearer_token("ci-secret"),
        max_events_per_query: 8,
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_grpc(config, state, async {
        let _ = shutdown_rx.await;
    }));

    let mut client = connect_client(listen).await;
    let error = client
        .get_metrics(Request::new(GetMetricsRequest {}))
        .await
        .expect_err("missing token should be rejected");
    assert_eq!(error.code(), Code::Unauthenticated);

    let metrics = client
        .get_metrics(bearer_request(GetMetricsRequest {}))
        .await
        .expect("authorized metrics")
        .into_inner();
    assert_eq!(metrics.flows_completed, 1);
    assert_eq!(metrics.inbound_to_outbound_bytes, 12);

    let events = client
        .query_events(bearer_request(QueryEventsRequest {
            min_level: "info".to_string(),
            target_prefix: "rustbox.kernel".to_string(),
            flow_id: 0,
            limit: 4,
        }))
        .await
        .expect("authorized event query")
        .into_inner();
    assert!(!events.events.is_empty());

    let stop = client
        .stop(bearer_request(StopRequest {}))
        .await
        .expect("authorized stop")
        .into_inner();
    assert_eq!(stop.state, ProtoEngineState::Stopping as i32);
    assert_eq!(
        timeout(Duration::from_secs(2), command_rx.recv())
            .await
            .expect("stop command timeout")
            .expect("stop command channel"),
        EngineCommand::Stop
    );

    let _ = shutdown_tx.send(());
    server.await.expect("server task").expect("server shutdown");
}

fn sample_state() -> ControlApiState {
    let store = Arc::new(ObservabilityStore::default());
    let flow_id = FlowId::new(NonZeroU64::new(42).expect("non-zero"));
    emit(
        &store,
        Event::new(
            EventLevel::Info,
            "rustbox.kernel.flow",
            Some(flow_id),
            EventKind::FlowAccepted {
                source: "127.0.0.1:53000".to_string(),
                destination: "example.test:443".to_string(),
                network: "Tcp".to_string(),
            },
        ),
    );
    emit(
        &store,
        Event::new(
            EventLevel::Info,
            "rustbox.kernel.traffic",
            Some(flow_id),
            EventKind::TrafficRecorded {
                inbound_to_outbound_bytes: 12,
                outbound_to_inbound_bytes: 34,
            },
        ),
    );
    emit(
        &store,
        Event::new(
            EventLevel::Info,
            "rustbox.kernel.flow",
            Some(flow_id),
            EventKind::FlowCompleted {
                outcome: "Forwarded".to_string(),
            },
        ),
    );

    ControlApiState::new(
        store,
        Arc::new(Mutex::new(ControlState::new(EngineSnapshot {
            state: EngineState::Running,
            generation: 3,
            inbound_count: 1,
            outbound_count: 1,
        }))),
    )
}

fn emit(store: &ObservabilityStore, event: Event) {
    block_on_ready(store.emit(event));
}

fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("future unexpectedly pending"),
    }
}

fn bearer_request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        "Bearer ci-secret".parse().expect("metadata"),
    );
    request
}

async fn connect_client(listen: SocketAddr) -> RustBoxControlClient<tonic::transport::Channel> {
    let endpoint = format!("http://{listen}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_error = None;

    while tokio::time::Instant::now() < deadline {
        match RustBoxControlClient::connect(endpoint.clone()).await {
            Ok(client) => return client,
            Err(err) => {
                last_error = Some(err);
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    panic!("timed out connecting to control API at {listen}: {last_error:?}");
}

fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind free port");
    listener.local_addr().expect("local addr")
}
