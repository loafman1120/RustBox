//! SOCKS5 CONNECT inbound。
//!
//! 本模块复用 runtime-neutral SOCKS5 codec 完成握手，并把 CONNECT 请求转换为
//! 内核 `Flow`。BIND、UDP ASSOCIATE 和认证扩展仍保留为后续边界。

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rustbox_codec_socks5::{
    AuthMethod, Command, ReplyCode, encode_method_selection, encode_reply, parse_connect_request,
    parse_greeting,
};
use rustbox_host_api::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, StreamListener, TaskName, TaskSpawner, TcpBind,
};
use rustbox_io::{ByteStream, stream_close, stream_read, stream_write_all};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{Endpoint, FlowId, FlowMeta, InboundId, Network, ProtocolHint};
use std::sync::{Arc, Mutex};

/// SOCKS5 入口服务，当前支持无认证 CONNECT 隧道。
pub struct Socks5Inbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    spawner: Arc<dyn TaskSpawner>,
    sink: Arc<dyn FlowSink>,
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
            .expect("socks5 inbound endpoint lock")
            .clone()
    }
}

impl Inbound for Socks5Inbound {
    fn id(&self) -> InboundId {
        self.id
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
            let sink = Arc::clone(&self.sink);
            let spawner = Arc::clone(&self.spawner);
            let observability = Arc::clone(&self.observability);
            let next_flow_id = Arc::clone(&self.next_flow_id);
            self.spawner
                .spawn(
                    TaskName("socks5-inbound-accept".to_string()),
                    Box::pin(async move {
                        accept_loop(id, listener, sink, spawner, observability, next_flow_id).await;
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

async fn accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn StreamListener>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
) {
    // accept loop 不解析协议，只把每个连接交给独立连接任务处理。
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

        let sink = Arc::clone(&sink);
        let observability = Arc::clone(&observability);
        let next_flow_id = Arc::clone(&next_flow_id);
        let _ = spawner.spawn(
            TaskName("socks5-inbound-connection".to_string()),
            Box::pin(async move {
                let _ =
                    handle_connection(inbound_id, peer, stream, sink, observability, next_flow_id)
                        .await;
            }),
        );
    }
}

async fn handle_connection(
    inbound_id: InboundId,
    peer: Endpoint,
    mut stream: Box<dyn ByteStream>,
    sink: Arc<dyn FlowSink>,
    observability: Arc<dyn ObservabilitySink>,
    next_flow_id: Arc<AtomicU64>,
) -> Result<(), ServiceError> {
    // 关键转换点：SOCKS5 CONNECT target -> FlowMeta.destination + FlowPayload::Stream。
    let target = match read_connect_target(&mut *stream).await {
        Ok(target) => target,
        Err(err) => {
            observability
                .emit(Event::new(
                    EventLevel::Warn,
                    "rustbox.inbound.socks5",
                    None,
                    EventKind::Diagnostic(format!(
                        "invalid SOCKS5 request from {peer}: {}",
                        err.message
                    )),
                ))
                .await;
            let _ = stream_close(&mut *stream).await;
            return Err(err);
        }
    };

    let reply = encode_reply(ReplyCode::Succeeded, &Endpoint::localhost_v4(0))
        .map_err(|err| ServiceError::new(err.message))?;
    stream_write_all(&mut *stream, &reply)
        .await
        .map_err(|err| ServiceError::new(err.message))?;

    let flow_id_raw = next_flow_id.fetch_add(1, Ordering::Relaxed);
    let flow_id = FlowId::new(NonZeroU64::new(flow_id_raw.max(1)).expect("non-zero flow id"));
    let meta = FlowMeta {
        id: flow_id,
        network: Network::Tcp,
        source: peer,
        destination: target.clone(),
        inbound: inbound_id,
        domain: Some(target.host.clone()),
        protocol_hint: Some(ProtocolHint::Socks5),
    };
    let flow = Flow {
        meta,
        payload: FlowPayload::Stream(stream),
    };

    sink.submit(flow)
        .await
        .map(|_| ())
        .map_err(|err| ServiceError::new(format!("{err:?}")))
}

async fn read_connect_target(stream: &mut dyn ByteStream) -> Result<Endpoint, ServiceError> {
    // SOCKS5 协议字节由 codec 解析，inbound 只负责按流式 I/O 收集完整握手。
    let mut greeting_header = [0_u8; 2];
    stream_read_exact(stream, &mut greeting_header).await?;
    let mut greeting = Vec::with_capacity(greeting_header[1] as usize + 2);
    greeting.extend_from_slice(&greeting_header);
    let mut methods = vec![0_u8; greeting_header[1] as usize];
    stream_read_exact(stream, &mut methods).await?;
    greeting.extend_from_slice(&methods);

    let parsed_greeting =
        parse_greeting(&greeting).map_err(|err| ServiceError::new(err.message))?;
    if !parsed_greeting
        .methods
        .contains(&AuthMethod::NoAuthentication)
    {
        stream_write_all(
            stream,
            &encode_method_selection(AuthMethod::NoAcceptableMethods),
        )
        .await
        .map_err(|err| ServiceError::new(err.message))?;
        return Err(ServiceError::new(
            "SOCKS5 client did not offer no-authentication method",
        ));
    }
    stream_write_all(
        stream,
        &encode_method_selection(AuthMethod::NoAuthentication),
    )
    .await
    .map_err(|err| ServiceError::new(err.message))?;

    let mut request_header = [0_u8; 4];
    stream_read_exact(stream, &mut request_header).await?;
    let mut request = Vec::from(request_header);
    match request_header[3] {
        0x01 => read_request_tail(stream, &mut request, 6).await?,
        0x03 => {
            let mut len = [0_u8; 1];
            stream_read_exact(stream, &mut len).await?;
            request.push(len[0]);
            read_request_tail(stream, &mut request, len[0] as usize + 2).await?;
        }
        0x04 => read_request_tail(stream, &mut request, 18).await?,
        _ => {
            write_failure_reply(stream, ReplyCode::AddressTypeNotSupported).await?;
            return Err(ServiceError::new("unsupported SOCKS5 address type"));
        }
    }

    let parsed = parse_connect_request(&request).map_err(|err| ServiceError::new(err.message))?;
    if parsed.command != Command::Connect {
        write_failure_reply(stream, ReplyCode::CommandNotSupported).await?;
        return Err(ServiceError::new("only SOCKS5 CONNECT is supported"));
    }

    Ok(parsed.target)
}

async fn read_request_tail(
    stream: &mut dyn ByteStream,
    request: &mut Vec<u8>,
    len: usize,
) -> Result<(), ServiceError> {
    let mut tail = vec![0_u8; len];
    stream_read_exact(stream, &mut tail).await?;
    request.extend_from_slice(&tail);
    Ok(())
}

async fn write_failure_reply(
    stream: &mut dyn ByteStream,
    code: ReplyCode,
) -> Result<(), ServiceError> {
    let reply = encode_reply(code, &Endpoint::localhost_v4(0))
        .map_err(|err| ServiceError::new(err.message))?;
    stream_write_all(stream, &reply)
        .await
        .map_err(|err| ServiceError::new(err.message))
}

async fn stream_read_exact(
    stream: &mut dyn ByteStream,
    mut buf: &mut [u8],
) -> Result<(), ServiceError> {
    while !buf.is_empty() {
        let read = stream_read(stream, buf)
            .await
            .map_err(|err| ServiceError::new(err.message))?;
        if read == 0 {
            return Err(ServiceError::new(
                "connection closed during SOCKS5 handshake",
            ));
        }
        buf = &mut buf[read..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_kernel::{Engine, Service};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_runtime_tokio::TokioHost;
    use rustbox_types::{Host, IpAddress, OutboundId};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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
        let proxy_addr = match proxy.host {
            Host::Ip(IpAddress::V4(octets)) => std::net::SocketAddr::from((octets, proxy.port)),
            _ => panic!("expected IPv4 proxy endpoint"),
        };

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
}
