//! Minimal HTTP CONNECT inbound.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rustbox_host_api::{
    BoxFuture, NetworkProvider, StreamListener, TaskName, TaskSpawner, TcpBind,
};
use rustbox_io::{ByteStream, stream_close, stream_read, stream_write_all};
use rustbox_kernel::{Flow, FlowPayload, FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_types::{
    Endpoint, FlowId, FlowMeta, Host, InboundId, IpAddress, Network, ProtocolHint,
};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

const MAX_HEADER_BYTES: usize = 8192;

pub struct HttpProxyInbound {
    id: InboundId,
    listen: Endpoint,
    network: Arc<dyn NetworkProvider>,
    spawner: Arc<dyn TaskSpawner>,
    sink: Arc<dyn FlowSink>,
    next_flow_id: Arc<AtomicU64>,
    local_endpoint: Arc<Mutex<Option<Endpoint>>>,
    started: AtomicBool,
}

impl HttpProxyInbound {
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
            next_flow_id: Arc::new(AtomicU64::new(1)),
            local_endpoint: Arc::new(Mutex::new(None)),
            started: AtomicBool::new(false),
        }
    }

    pub fn local_endpoint(&self) -> Option<Endpoint> {
        self.local_endpoint
            .lock()
            .expect("http inbound endpoint lock")
            .clone()
    }
}

impl Inbound for HttpProxyInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for HttpProxyInbound {
    fn start(&mut self, _ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("http inbound already started"));
            }

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
            *self
                .local_endpoint
                .lock()
                .expect("http inbound endpoint lock") = Some(local_endpoint);

            let id = self.id;
            let sink = Arc::clone(&self.sink);
            let spawner = Arc::clone(&self.spawner);
            let next_flow_id = Arc::clone(&self.next_flow_id);
            self.spawner
                .spawn(
                    TaskName("http-inbound-accept".to_string()),
                    Box::pin(async move {
                        accept_loop(id, listener, sink, spawner, next_flow_id).await;
                    }),
                )
                .map_err(|err| ServiceError::new(err.message))?;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.started.store(false, Ordering::SeqCst);
            Ok(())
        })
    }
}

async fn accept_loop(
    inbound_id: InboundId,
    mut listener: Box<dyn StreamListener>,
    sink: Arc<dyn FlowSink>,
    spawner: Arc<dyn TaskSpawner>,
    next_flow_id: Arc<AtomicU64>,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            break;
        };

        let sink = Arc::clone(&sink);
        let next_flow_id = Arc::clone(&next_flow_id);
        let _ = spawner.spawn(
            TaskName("http-inbound-connection".to_string()),
            Box::pin(async move {
                let _ = handle_connection(inbound_id, peer, stream, sink, next_flow_id).await;
            }),
        );
    }
}

async fn handle_connection(
    inbound_id: InboundId,
    peer: Endpoint,
    mut stream: Box<dyn ByteStream>,
    sink: Arc<dyn FlowSink>,
    next_flow_id: Arc<AtomicU64>,
) -> Result<(), ServiceError> {
    let target = match read_connect_target(&mut *stream).await {
        Ok(target) => target,
        Err(err) => {
            let _ = stream_write_all(&mut *stream, b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = stream_close(&mut *stream).await;
            return Err(err);
        }
    };

    stream_write_all(&mut *stream, b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
        protocol_hint: Some(ProtocolHint::Http),
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
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 512];
    while bytes.len() < MAX_HEADER_BYTES {
        let read = stream_read(stream, &mut scratch)
            .await
            .map_err(|err| ServiceError::new(err.message))?;
        if read == 0 {
            return Err(ServiceError::new("connection closed before HTTP headers"));
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return parse_connect_request(&bytes);
        }
    }

    Err(ServiceError::new("HTTP CONNECT headers exceeded limit"))
}

fn parse_connect_request(bytes: &[u8]) -> Result<Endpoint, ServiceError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ServiceError::new("HTTP CONNECT request is not valid UTF-8"))?;
    let first_line = text
        .lines()
        .next()
        .ok_or_else(|| ServiceError::new("HTTP CONNECT request is empty"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if method != "CONNECT" || !version.starts_with("HTTP/") {
        return Err(ServiceError::new("only HTTP CONNECT is supported"));
    }

    parse_authority(authority)
}

fn parse_authority(authority: &str) -> Result<Endpoint, ServiceError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(ServiceError::new("invalid bracketed IPv6 authority"));
        };
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return Err(ServiceError::new(
                "HTTP CONNECT authority must include a port",
            ));
        };
        (host, port)
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| ServiceError::new("HTTP CONNECT port is invalid"))?;
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Host::Ip(IpAddress::V4(ip.octets())),
        Ok(IpAddr::V6(ip)) => Host::Ip(IpAddress::V6(ip.octets())),
        Err(_) => Host::Domain(host.to_string()),
    };
    Ok(Endpoint::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_kernel::{Engine, Service};
    use rustbox_outbound_direct::DirectOutbound;
    use rustbox_route::StaticRouter;
    use rustbox_runtime_tokio::TokioHost;
    use rustbox_types::OutboundId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn http_connect_tunnels_bytes_to_direct_outbound() {
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
        let mut inbound = HttpProxyInbound::new(
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
            .expect("start http inbound");

        let proxy = inbound.local_endpoint().expect("proxy local endpoint");
        let proxy_addr = match proxy.host {
            Host::Ip(IpAddress::V4(octets)) => std::net::SocketAddr::from((octets, proxy.port)),
            _ => panic!("expected IPv4 proxy endpoint"),
        };

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connect");
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    echo_addr.port(),
                    echo_addr.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write connect");

        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.expect("read response");
            response.push(byte[0]);
        }
        assert!(
            std::str::from_utf8(&response)
                .expect("utf8 response")
                .starts_with("HTTP/1.1 200")
        );

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
