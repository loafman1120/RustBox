//! SOCKS5 inbound。
//!
//! 本模块把 `fast-socks5` 的协议状态机适配到 RustBox 的 Flow 边界：
//! 握手、命令解析、reply 和 UDP header 由第三方库负责，路由和出站仍交给内核。

use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command, new_udp_header, parse_udp_request};
use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, StreamListener, TaskName, TaskSpawner, TcpBind, UdpBind,
};
use rustbox_inbound_http::{HttpInboundCredentials, handle_http_proxy_connection};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind, stream_read};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{
    Endpoint, FlowId, FlowMeta, Host, InboundId, IpAddress, Network, ProtocolHint,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// SOCKS5 入口服务，当前支持无认证 CONNECT 隧道和 UDP ASSOCIATE。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5InboundCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedInboundCredentials {
    pub username: String,
    pub password: String,
}

pub struct Socks5Inbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    spawner: Arc<dyn TaskSpawner>,
    sink: Arc<dyn FlowSink>,
    credentials: Option<Socks5InboundCredentials>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl Socks5Inbound {
    pub fn new(
        id: InboundId,
        listen: Endpoint,
        network: Arc<dyn NetworkProvider>,
        spawner: Arc<dyn TaskSpawner>,
        sink: Arc<dyn FlowSink>,
    ) -> Self {
        Self {
            id,
            listen,
            network,
            spawner,
            sink,
            credentials: None,
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

    pub fn with_credentials(mut self, credentials: Socks5InboundCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("socks5 inbound endpoint lock")
            .clone()
    }
}

impl Inbound for Socks5Inbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

/// mixed 入口服务，在同一 TCP 端口上按首字节分流 HTTP proxy 与 SOCKS5。
pub struct MixedInbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    spawner: Arc<dyn TaskSpawner>,
    sink: Arc<dyn FlowSink>,
    credentials: Option<MixedInboundCredentials>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl MixedInbound {
    pub fn new(
        id: InboundId,
        listen: Endpoint,
        network: Arc<dyn NetworkProvider>,
        spawner: Arc<dyn TaskSpawner>,
        sink: Arc<dyn FlowSink>,
    ) -> Self {
        Self {
            id,
            listen,
            network,
            spawner,
            sink,
            credentials: None,
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

    pub fn with_credentials(mut self, credentials: MixedInboundCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("mixed inbound endpoint lock")
            .clone()
    }
}

impl Inbound for MixedInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for MixedInbound {
    fn start(&mut self, _ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("mixed inbound already started"));
            }

            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.mixed",
                    None,
                    EventKind::ServiceStarting {
                        service: format!("mixed/{}", self.id),
                    },
                ))
                .await;

            let listener = self
                .network
                .bind_tcp(TcpBind {
                    listen: self.listen.clone(),
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
                .expect("mixed inbound endpoint lock") = Some(local_endpoint);

            let id = self.id;
            let network = Arc::clone(&self.network);
            let sink = Arc::clone(&self.sink);
            let spawner = Arc::clone(&self.spawner);
            let observability = Arc::clone(&self.observability);
            let credentials = self.credentials.clone();
            let next_flow_id = Arc::clone(&self.next_flow_id);
            self.spawner
                .spawn(
                    TaskName("mixed-inbound-accept".to_string()),
                    Box::pin(async move {
                        mixed_accept_loop(
                            id,
                            listener,
                            network,
                            sink,
                            spawner,
                            observability,
                            credentials,
                            next_flow_id,
                        )
                        .await;
                    }),
                )
                .map_err(|err| ServiceError::new(err.message))?;
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.mixed",
                    None,
                    EventKind::ServiceStarted {
                        service: format!("mixed/{id}@{local_endpoint_text}"),
                    },
                ))
                .await;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.mixed",
                    None,
                    EventKind::ServiceStopping {
                        service: format!("mixed/{}", self.id),
                    },
                ))
                .await;
            self.started.store(false, Ordering::SeqCst);
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.mixed",
                    None,
                    EventKind::ServiceStopped {
                        service: format!("mixed/{}", self.id),
                    },
                ))
                .await;
            Ok(())
        })
    }
}

impl Service for Socks5Inbound {
    fn start(&mut self, _ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("socks5 inbound already started"));
            }

            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.socks5",
                    None,
                    EventKind::ServiceStarting {
                        service: format!("socks5/{}", self.id),
                    },
                ))
                .await;

            let listener = self
                .network
                .bind_tcp(TcpBind {
                    listen: self.listen.clone(),
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
                .expect("socks5 inbound endpoint lock") = Some(local_endpoint);

            let id = self.id;
            let network = Arc::clone(&self.network);
            let sink = Arc::clone(&self.sink);
            let spawner = Arc::clone(&self.spawner);
            let observability = Arc::clone(&self.observability);
            let credentials = self.credentials.clone();
            let next_flow_id = Arc::clone(&self.next_flow_id);
            self.spawner
                .spawn(
                    TaskName("socks5-inbound-accept".to_string()),
                    Box::pin(async move {
                        accept_loop(
                            id,
                            listener,
                            network,
                            sink,
                            spawner,
                            observability,
                            credentials,
                            next_flow_id,
                        )
                        .await;
                    }),
                )
                .map_err(|err| ServiceError::new(err.message))?;
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.socks5",
                    None,
                    EventKind::ServiceStarted {
                        service: format!("socks5/{id}@{local_endpoint_text}"),
                    },
                ))
                .await;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.socks5",
                    None,
                    EventKind::ServiceStopping {
                        service: format!("socks5/{}", self.id),
                    },
                ))
                .await;
            self.started.store(false, Ordering::SeqCst);
            self.observability
                .emit(Event::new(
                    EventLevel::Info,
                    "rustbox.inbound.socks5",
                    None,
                    EventKind::ServiceStopped {
                        service: format!("socks5/{}", self.id),
                    },
                ))
                .await;
            Ok(())
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn StreamListener>,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<Socks5InboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
) {
    let listener_endpoint = listener
        .local_endpoint()
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            break;
        };

        observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.inbound.socks5",
                None,
                EventKind::ConnectionAccepted {
                    listener: listener_endpoint.clone(),
                    peer: peer.to_string(),
                },
            ))
            .await;

        let network = Arc::clone(&network);
        let sink = Arc::clone(&sink);
        let spawner = Arc::clone(&spawner);
        let ctx = ConnectionContext {
            inbound_id,
            network,
            sink,
            spawner: Arc::clone(&spawner),
            observability: Arc::clone(&observability),
            credentials: credentials.clone(),
            next_flow_id: Arc::clone(&next_flow_id),
        };
        let _ = spawner.spawn(
            TaskName("socks5-inbound-connection".to_string()),
            Box::pin(async move {
                let _ = handle_connection(ctx, peer, stream).await;
            }),
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn mixed_accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn StreamListener>,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<MixedInboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
) {
    let listener_endpoint = listener
        .local_endpoint()
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            break;
        };

        observability
            .emit(Event::new(
                EventLevel::Debug,
                "rustbox.inbound.mixed",
                None,
                EventKind::ConnectionAccepted {
                    listener: listener_endpoint.clone(),
                    peer: peer.to_string(),
                },
            ))
            .await;

        let network = Arc::clone(&network);
        let sink = Arc::clone(&sink);
        let spawner = Arc::clone(&spawner);
        let task_spawner = Arc::clone(&spawner);
        let observability = Arc::clone(&observability);
        let credentials = credentials.clone();
        let next_flow_id = Arc::clone(&next_flow_id);
        let _ = spawner.spawn(
            TaskName("mixed-inbound-connection".to_string()),
            Box::pin(async move {
                let _ = handle_mixed_connection(
                    inbound_id,
                    peer,
                    stream,
                    network,
                    sink,
                    task_spawner,
                    observability,
                    credentials,
                    next_flow_id,
                )
                .await;
            }),
        );
    }
}

type CommandProtocol = fast_socks5::server::Socks5ServerProtocol<
    RustBoxAsyncStream,
    fast_socks5::server::states::CommandRead,
>;

#[derive(Clone)]
struct ConnectionContext {
    inbound_id: InboundId,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<Socks5InboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
}

#[allow(clippy::too_many_arguments)]
async fn handle_mixed_connection(
    inbound_id: InboundId,
    peer: Endpoint,
    mut stream: Box<dyn ByteStream>,
    network: Arc<dyn NetworkProvider>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    observability: Arc<dyn ObservabilitySink>,
    credentials: Option<MixedInboundCredentials>,
    next_flow_id: Arc<AtomicU64>,
) -> Result<(), ServiceError> {
    let mut first = [0_u8; 1];
    let read = stream_read(&mut *stream, &mut first)
        .await
        .map_err(|err| ServiceError::new(err.message))?;
    if read == 0 {
        return Err(ServiceError::new(
            "mixed inbound connection closed before protocol byte",
        ));
    }

    let stream = Box::new(PrefixedByteStream::new(stream, first.to_vec())) as Box<dyn ByteStream>;
    if first[0] == 0x05 {
        let socks_credentials = credentials
            .as_ref()
            .map(|credentials| Socks5InboundCredentials {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            });
        let ctx = ConnectionContext {
            inbound_id,
            network,
            sink,
            spawner,
            observability,
            credentials: socks_credentials,
            next_flow_id,
        };
        handle_connection(ctx, peer, stream).await
    } else {
        let http_credentials = credentials.map(|credentials| HttpInboundCredentials {
            username: credentials.username,
            password: credentials.password,
        });
        handle_http_proxy_connection(
            inbound_id,
            peer,
            stream,
            sink,
            observability,
            http_credentials,
            next_flow_id,
        )
        .await
    }
}

async fn handle_connection(
    ctx: ConnectionContext,
    peer: Endpoint,
    stream: Box<dyn ByteStream>,
) -> Result<(), ServiceError> {
    let async_stream = RustBoxAsyncStream::new(stream);
    let proto = match &ctx.credentials {
        Some(credentials) => {
            match Socks5ServerProtocol::accept_password_auth(async_stream, |username, password| {
                username == credentials.username && password == credentials.password
            })
            .await
            {
                Ok((proto, _)) => proto,
                Err(err) => {
                    ctx.observability
                        .emit(Event::new(
                            EventLevel::Warn,
                            "rustbox.inbound.socks5",
                            None,
                            EventKind::Diagnostic(format!(
                                "invalid SOCKS5 request from {peer}: {err}"
                            )),
                        ))
                        .await;
                    return Err(ServiceError::new(err.to_string()));
                }
            }
        }
        None => match Socks5ServerProtocol::accept_no_auth(async_stream).await {
            Ok(proto) => proto,
            Err(err) => {
                ctx.observability
                    .emit(Event::new(
                        EventLevel::Warn,
                        "rustbox.inbound.socks5",
                        None,
                        EventKind::Diagnostic(format!("invalid SOCKS5 request from {peer}: {err}")),
                    ))
                    .await;
                return Err(ServiceError::new(err.to_string()));
            }
        },
    };
    let (proto, command, target) = proto
        .read_command()
        .await
        .map_err(|err| ServiceError::new(err.to_string()))?;
    let target = target_addr_to_endpoint(target);

    match command {
        Socks5Command::TCPConnect => handle_connect(ctx, peer, proto, target).await,
        Socks5Command::UDPAssociate => handle_udp_associate(ctx, peer, proto, target).await,
        Socks5Command::TCPBind => {
            proto
                .reply_error(&ReplyError::CommandNotSupported)
                .await
                .map_err(|err| ServiceError::new(err.to_string()))?;
            Err(ServiceError::new("SOCKS5 BIND is not supported"))
        }
    }
}

async fn handle_connect(
    ctx: ConnectionContext,
    peer: Endpoint,
    proto: CommandProtocol,
    target: Endpoint,
) -> Result<(), ServiceError> {
    let stream = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .map_err(|err| ServiceError::new(err.to_string()))?
        .into_inner();

    let flow = Flow {
        meta: flow_meta(ctx.inbound_id, peer, target, ctx.next_flow_id, Network::Tcp),
        payload: FlowPayload::Stream(stream),
    };

    ctx.sink
        .submit(flow)
        .await
        .map(|_| ())
        .map_err(|err| ServiceError::new(format!("{err:?}")))
}

async fn handle_udp_associate(
    ctx: ConnectionContext,
    peer: Endpoint,
    proto: CommandProtocol,
    association_target: Endpoint,
) -> Result<(), ServiceError> {
    let bind_endpoint = udp_relay_bind_endpoint(&association_target, &peer);
    let relay_socket = ctx
        .network
        .bind_udp(UdpBind {
            listen: bind_endpoint,
        })
        .await
        .map_err(|err| ServiceError::new(err.message))?;
    let relay_endpoint = relay_socket
        .local_endpoint()
        .ok_or_else(|| ServiceError::new("UDP relay socket did not report local endpoint"))?;
    let relay_addr = endpoint_to_socket_addr(&relay_endpoint)?;

    let stream = proto
        .reply_success(relay_addr)
        .await
        .map_err(|err| ServiceError::new(err.to_string()))?
        .into_inner();

    let state = Arc::new(UdpAssociationState::new());
    spawn_udp_control_watcher(Arc::clone(&ctx.spawner), stream, Arc::clone(&state))?;

    let socket = Socks5UdpRelaySocket::new(relay_socket, peer.host.clone(), state);
    let flow = Flow {
        meta: flow_meta(
            ctx.inbound_id,
            peer,
            association_target,
            ctx.next_flow_id,
            Network::Udp,
        ),
        payload: FlowPayload::Datagram(Box::new(socket)),
    };

    ctx.sink
        .submit(flow)
        .await
        .map(|_| ())
        .map_err(|err| ServiceError::new(format!("{err:?}")))
}

fn flow_meta(
    inbound_id: InboundId,
    source: Endpoint,
    destination: Endpoint,
    next_flow_id: Arc<AtomicU64>,
    network: Network,
) -> FlowMeta {
    let flow_id_raw = next_flow_id.fetch_add(1, Ordering::Relaxed);
    let flow_id = FlowId::new(NonZeroU64::new(flow_id_raw.max(1)).expect("non-zero flow id"));
    FlowMeta {
        id: flow_id,
        network,
        source,
        destination: destination.clone(),
        inbound: inbound_id,
        domain: Some(destination.host.clone()),
        protocol_hint: Some(ProtocolHint::Socks5),
    }
}

fn udp_relay_bind_endpoint(association_target: &Endpoint, peer: &Endpoint) -> Endpoint {
    match &association_target.host {
        Host::Ip(IpAddress::V4([0, 0, 0, 0])) => Endpoint::new(peer.host.clone(), 0),
        Host::Ip(IpAddress::V6(octets)) if octets.iter().all(|byte| *byte == 0) => {
            Endpoint::new(peer.host.clone(), 0)
        }
        Host::Ip(_) => Endpoint::new(association_target.host.clone(), 0),
        Host::Domain(_) => Endpoint::new(peer.host.clone(), 0),
    }
}

fn spawn_udp_control_watcher(
    spawner: Arc<dyn TaskSpawner>,
    mut stream: Box<dyn ByteStream>,
    state: Arc<UdpAssociationState>,
) -> Result<(), ServiceError> {
    spawner
        .spawn(
            TaskName("socks5-udp-control".to_string()),
            Box::pin(async move {
                let mut buf = [0_u8; 1];
                loop {
                    match stream_read(&mut *stream, &mut buf).await {
                        Ok(0) | Err(_) => {
                            state.close();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
            }),
        )
        .map(|_| ())
        .map_err(|err| ServiceError::new(err.message))
}

struct UdpAssociationState {
    closed: AtomicBool,
    recv_waker: Mutex<Option<Waker>>,
}

impl UdpAssociationState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            recv_waker: Mutex::new(None),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(waker) = self
            .recv_waker
            .lock()
            .expect("udp association waker lock")
            .take()
        {
            waker.wake();
        }
    }

    fn remember_waker(&self, waker: &Waker) {
        *self.recv_waker.lock().expect("udp association waker lock") = Some(waker.clone());
    }
}

struct Socks5UdpRelaySocket {
    inner: Box<dyn DatagramSocket>,
    expected_client_host: Host,
    client_endpoint: Arc<Mutex<Option<Endpoint>>>,
    state: Arc<UdpAssociationState>,
    recv_buf: Vec<u8>,
}

impl Socks5UdpRelaySocket {
    fn new(
        inner: Box<dyn DatagramSocket>,
        expected_client_host: Host,
        state: Arc<UdpAssociationState>,
    ) -> Self {
        Self {
            inner,
            expected_client_host,
            client_endpoint: Arc::new(Mutex::new(None)),
            state,
            recv_buf: vec![0; 65_535],
        }
    }
}

impl DatagramSocket for Socks5UdpRelaySocket {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_endpoint()
    }

    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        if self.state.is_closed() {
            return Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "SOCKS5 UDP association is closed",
            )));
        }

        loop {
            let this = &mut *self;
            match Pin::new(&mut *this.inner).poll_recv_from(cx, &mut this.recv_buf) {
                Poll::Ready(Ok((len, client))) => {
                    if client.host != this.expected_client_host {
                        continue;
                    }
                    let mut parsed = Box::pin(parse_udp_request(&this.recv_buf[..len]));
                    let Ok((frag, target, data)) = ready_or_error(parsed.as_mut().poll(cx)) else {
                        continue;
                    };
                    if frag != 0 {
                        continue;
                    }
                    if data.len() > buf.len() {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::InvalidInput,
                            "SOCKS5 UDP payload exceeds relay buffer",
                        )));
                    }

                    *this
                        .client_endpoint
                        .lock()
                        .expect("socks5 udp client endpoint lock") = Some(client);
                    buf[..data.len()].copy_from_slice(data);
                    return Poll::Ready(Ok((data.len(), target_addr_to_endpoint(target))));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    if this.state.is_closed() {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::Closed,
                            "SOCKS5 UDP association is closed",
                        )));
                    }
                    this.state.remember_waker(cx.waker());
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        if self.state.is_closed() {
            return Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "SOCKS5 UDP association is closed",
            )));
        }

        let client = match self
            .client_endpoint
            .lock()
            .expect("socks5 udp client endpoint lock")
            .clone()
        {
            Some(client) => client,
            None => {
                return Poll::Ready(Err(IoError::new(
                    IoErrorKind::Closed,
                    "SOCKS5 UDP client endpoint is not known yet",
                )));
            }
        };
        let mut encoded = match new_udp_header(endpoint_to_target_addr(target)) {
            Ok(encoded) => encoded,
            Err(err) => return Poll::Ready(Err(io_error(io::Error::other(err.to_string())))),
        };
        encoded.extend_from_slice(buf);

        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_send_to(cx, &encoded, &client) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn ready_or_error<T, E>(poll: Poll<Result<T, E>>) -> Result<T, E> {
    match poll {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fast-socks5 slice UDP parser unexpectedly returned Pending"),
    }
}

struct PrefixedByteStream {
    inner: Box<dyn ByteStream>,
    prefix: Vec<u8>,
    offset: usize,
}

impl PrefixedByteStream {
    fn new(inner: Box<dyn ByteStream>, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

impl ByteStream for PrefixedByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        if self.offset < self.prefix.len() {
            let len = (self.prefix.len() - self.offset).min(buf.len());
            buf[..len].copy_from_slice(&self.prefix[self.offset..self.offset + len]);
            self.offset += len;
            return Poll::Ready(Ok(len));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut *self.inner).poll_close(cx)
    }
}

struct RustBoxAsyncStream {
    inner: Box<dyn ByteStream>,
}

impl RustBoxAsyncStream {
    fn new(inner: Box<dyn ByteStream>) -> Self {
        Self { inner }
    }

    fn into_inner(self) -> Box<dyn ByteStream> {
        self.inner
    }
}

impl AsyncRead for RustBoxAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let dst = buf.initialize_unfilled();
        match Pin::new(&mut *self.inner).poll_read(cx, dst) {
            Poll::Ready(Ok(read)) => {
                buf.set_filled(before + read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error_to_std(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for RustBoxAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner)
            .poll_write(cx, buf)
            .map_err(io_error_to_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner)
            .poll_flush(cx)
            .map_err(io_error_to_std)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner)
            .poll_close(cx)
            .map_err(io_error_to_std)
    }
}

fn endpoint_to_target_addr(endpoint: &Endpoint) -> TargetAddr {
    match &endpoint.host {
        Host::Domain(domain) => TargetAddr::Domain(domain.clone(), endpoint.port),
        Host::Ip(ip) => TargetAddr::Ip(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
    }
}

fn target_addr_to_endpoint(target: TargetAddr) -> Endpoint {
    match target {
        TargetAddr::Domain(domain, port) => Endpoint::new(Host::Domain(domain), port),
        TargetAddr::Ip(addr) => socket_addr_to_endpoint(addr),
    }
}

fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Result<SocketAddr, ServiceError> {
    match &endpoint.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
        Host::Domain(domain) => Err(ServiceError::new(format!(
            "cannot use domain endpoint {domain} as SOCKS reply bind address"
        ))),
    }
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> Endpoint {
    let host = match addr.ip() {
        IpAddr::V4(ip) => Host::Ip(IpAddress::V4(ip.octets())),
        IpAddr::V6(ip) => Host::Ip(IpAddress::V6(ip.octets())),
    };
    Endpoint::new(host, addr.port())
}

fn ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

fn io_error(err: io::Error) -> IoError {
    IoError::new(IoErrorKind::Other, err.to_string())
}

fn io_error_to_std(err: IoError) -> io::Error {
    let kind = match err.kind {
        IoErrorKind::Closed => io::ErrorKind::UnexpectedEof,
        IoErrorKind::Interrupted => io::ErrorKind::Interrupted,
        IoErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        IoErrorKind::Unsupported => io::ErrorKind::Unsupported,
        IoErrorKind::Other => io::ErrorKind::Other,
    };
    io::Error::new(kind, err.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use fast_socks5::{new_udp_header, parse_udp_request};
    use rustbox_host_api::TokioHost;
    use rustbox_kernel::{Engine, Service};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_types::OutboundId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    #[tokio::test]
    async fn socks5_connect_tunnels_bytes_to_direct_outbound() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_listener.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.expect("echo accept");
            let mut buf = [0_u8; 4];
            socket.read_exact(&mut buf).await.expect("echo read");
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.expect("echo write");
        });

        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = Socks5Inbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            host,
            sink,
        );
        inbound
            .start(ServiceContext {
                engine_name: "test",
            })
            .await
            .expect("start socks5 inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = endpoint_to_socket_addr(&proxy).expect("proxy socket addr");

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("write greeting");
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.expect("read method");
        assert_eq!(method, [0x05, 0x00]);

        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (echo_addr.port() >> 8) as u8,
                echo_addr.port() as u8,
            ])
            .await
            .expect("write connect");
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.expect("read reply");
        assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);

        client
            .write_all(b"ping")
            .await
            .expect("write tunneled data");
        let mut tunnel_response = [0_u8; 4];
        client
            .read_exact(&mut tunnel_response)
            .await
            .expect("read tunneled data");
        assert_eq!(&tunnel_response, b"pong");
    }

    #[tokio::test]
    async fn socks5_connect_accepts_username_password_auth() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_listener.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.expect("echo accept");
            let mut buf = [0_u8; 4];
            socket.read_exact(&mut buf).await.expect("echo read");
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.expect("echo write");
        });

        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = Socks5Inbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            host,
            sink,
        )
        .with_credentials(Socks5InboundCredentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        });
        inbound
            .start(ServiceContext {
                engine_name: "test",
            })
            .await
            .expect("start socks5 inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = endpoint_to_socket_addr(&proxy).expect("proxy socket addr");

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(&[0x05, 0x01, 0x02])
            .await
            .expect("write greeting");
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.expect("read method");
        assert_eq!(method, [0x05, 0x02]);

        client
            .write_all(&[
                0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x06, b's', b'e', b'c', b'r', b'e', b't',
            ])
            .await
            .expect("write auth");
        let mut auth_reply = [0_u8; 2];
        client
            .read_exact(&mut auth_reply)
            .await
            .expect("read auth reply");
        assert_eq!(auth_reply, [0x01, 0x00]);

        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (echo_addr.port() >> 8) as u8,
                echo_addr.port() as u8,
            ])
            .await
            .expect("write connect");
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.expect("read reply");
        assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);

        client
            .write_all(b"ping")
            .await
            .expect("write tunneled data");
        let mut tunnel_response = [0_u8; 4];
        client
            .read_exact(&mut tunnel_response)
            .await
            .expect("read tunneled data");
        assert_eq!(&tunnel_response, b"pong");
    }

    #[tokio::test]
    async fn socks5_udp_associate_relays_datagrams_to_direct_outbound() {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = echo_socket.local_addr().expect("echo local addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (len, peer) = echo_socket.recv_from(&mut buf).await.expect("echo recv");
            assert_eq!(&buf[..len], b"ping");
            echo_socket.send_to(b"pong", peer).await.expect("echo send");
        });

        let host = Arc::new(TokioHost::new());
        let outbound_id = OutboundId::new(NonZeroU64::new(1).expect("non-zero outbound id"));
        let engine = Arc::new(
            Engine::builder(Box::new(StaticRouter::new(outbound_id)))
                .register_outbound(Box::new(DirectOutbound::new(outbound_id, host.clone())))
                .expect("register direct outbound")
                .build()
                .expect("build engine"),
        );
        let sink: Arc<dyn FlowSink> = engine;
        let mut inbound = Socks5Inbound::new(
            InboundId::new(NonZeroU64::new(1).expect("non-zero inbound id")),
            Endpoint::localhost_v4(0),
            host.clone(),
            host,
            sink,
        );
        inbound
            .start(ServiceContext {
                engine_name: "test",
            })
            .await
            .expect("start socks5 inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = endpoint_to_socket_addr(&proxy).expect("proxy socket addr");

        let mut control = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        control
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("write greeting");
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).await.expect("read method");
        assert_eq!(method, [0x05, 0x00]);

        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("write udp associate");
        let mut reply = [0_u8; 10];
        control.read_exact(&mut reply).await.expect("read reply");
        assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
        let relay_addr = SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ));

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
        let mut packet = new_udp_header(TargetAddr::Ip(echo_addr)).expect("encode udp header");
        packet.extend_from_slice(b"ping");
        udp_client
            .send_to(&packet, relay_addr)
            .await
            .expect("send udp packet");

        let mut response = [0_u8; 64];
        let (len, _) = udp_client
            .recv_from(&mut response)
            .await
            .expect("recv udp response");
        let (frag, target, data) = parse_udp_request(&response[..len])
            .await
            .expect("parse udp response");
        assert_eq!(frag, 0);
        assert_eq!(target, TargetAddr::Ip(echo_addr));
        assert_eq!(data, b"pong");
    }
}
