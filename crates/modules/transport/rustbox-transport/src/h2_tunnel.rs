use crate::{StreamTransport, TransportContext, TransportError};
use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use rand::Rng;
use rustbox_io::ByteStream;
use rustbox_kernel::{TaskScope, TokioNetworkProvider};
use rustbox_types::Endpoint;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const FIRST_PADDINGS: usize = 8;
const TUNNEL_BUFFER: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct H2TunnelOptions {
    pub headers: Vec<(String, String)>,
    pub negotiate_naive_padding: bool,
}

/// A reusable HTTP/2 connection pool with one multiplexed session per proxy.
/// The only shared mutation is the h2 sender handle guarded by Tokio's mutex;
/// individual tunnel streams use bounded `duplex` buffers and scoped tasks.
#[derive(Clone)]
pub struct H2TunnelPool {
    proxy: Endpoint,
    transport: Arc<dyn StreamTransport>,
    tasks: TaskScope,
    sender: Arc<Mutex<Option<SendRequest<Bytes>>>>,
}

impl H2TunnelPool {
    pub fn new(proxy: Endpoint, transport: Arc<dyn StreamTransport>, tasks: TaskScope) -> Self {
        Self {
            proxy,
            transport,
            tasks,
            sender: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn connect(
        &self,
        target: Endpoint,
        options: H2TunnelOptions,
    ) -> Result<Box<dyn ByteStream>, TransportError> {
        let mut retry = true;
        loop {
            let sender = self.sender().await?;
            match open_tunnel(sender, &target, &options, &self.tasks).await {
                Ok(stream) => return Ok(stream),
                Err(error) if retry => {
                    retry = false;
                    self.sender.lock().await.take();
                    if !error.message.contains("HTTP/2") {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn sender(&self) -> Result<SendRequest<Bytes>, TransportError> {
        let mut shared = self.sender.lock().await;
        if let Some(sender) = shared.as_ref() {
            return Ok(sender.clone());
        }
        // The transport already owns the configured NetworkProvider. The
        // context is retained for the generic interface and not used here.
        let unused = TokioNetworkProvider::new();
        let stream = self
            .transport
            .connect(TransportContext { network: &unused }, self.proxy.clone())
            .await?;
        let (sender, connection) = h2::client::handshake(stream)
            .await
            .map_err(|error| TransportError::new(format!("HTTP/2 handshake: {error}")))?;
        self.tasks.spawn(async move {
            let _ = connection.await;
        });
        *shared = Some(sender.clone());
        Ok(sender)
    }
}

async fn open_tunnel(
    sender: SendRequest<Bytes>,
    target: &Endpoint,
    options: &H2TunnelOptions,
    tasks: &TaskScope,
) -> Result<Box<dyn ByteStream>, TransportError> {
    let mut sender = sender
        .ready()
        .await
        .map_err(|error| TransportError::new(format!("HTTP/2 session readiness: {error}")))?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .body(())
        .map_err(|error| TransportError::new(format!("HTTP/2 CONNECT request: {error}")))?;
    append_headers(request.headers_mut(), &options.headers)?;
    if options.negotiate_naive_padding {
        request
            .headers_mut()
            .insert("padding", random_padding_header(16, 32));
    }
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|error| TransportError::new(format!("HTTP/2 CONNECT send: {error}")))?;
    let response = response
        .await
        .map_err(|error| TransportError::new(format!("HTTP/2 CONNECT response: {error}")))?;
    if response.status() != StatusCode::OK {
        return Err(TransportError::new(format!(
            "HTTP/2 CONNECT returned {}",
            response.status()
        )));
    }
    let padded = options.negotiate_naive_padding && response.headers().contains_key("padding");
    let receive = response.into_body();
    let (application, relay) = tokio::io::duplex(TUNNEL_BUFFER);
    tasks.spawn(relay_h2_tunnel(relay, send, receive, padded));
    Ok(Box::new(application))
}

fn append_headers(
    headers: &mut HeaderMap,
    configured: &[(String, String)],
) -> Result<(), TransportError> {
    for (name, value) in configured {
        let name = HeaderName::try_from(name.as_str())
            .map_err(|error| TransportError::new(format!("HTTP/2 header name: {error}")))?;
        let value = HeaderValue::try_from(value.as_str())
            .map_err(|error| TransportError::new(format!("HTTP/2 header value: {error}")))?;
        headers.append(name, value);
    }
    Ok(())
}

fn random_padding_header(minimum: usize, maximum: usize) -> HeaderValue {
    const SYMBOLS: &[u8] = b"~!@#$%^&*()_+{}|:<>?`-=[]\\;',./";
    let mut rng = rand::rng();
    let length = rng.random_range(minimum..=maximum);
    let bytes = (0..length)
        .map(|_| SYMBOLS[rng.random_range(0..SYMBOLS.len())])
        .collect::<Vec<_>>();
    HeaderValue::from_bytes(&bytes).expect("padding symbols are valid HTTP header bytes")
}

async fn relay_h2_tunnel(
    stream: tokio::io::DuplexStream,
    mut send: h2::SendStream<Bytes>,
    mut receive: h2::RecvStream,
    padded: bool,
) {
    let (mut application_read, mut application_write) = tokio::io::split(stream);
    let upload = async {
        let mut buffer = vec![0_u8; u16::MAX as usize];
        let mut count = 0;
        loop {
            let read = application_read.read(&mut buffer).await?;
            if read == 0 {
                send.send_data(Bytes::new(), true).map_err(h2_io)?;
                return Ok::<_, std::io::Error>(());
            }
            let data = if padded && count < FIRST_PADDINGS {
                count += 1;
                encode_padded(&buffer[..read])
            } else {
                Bytes::copy_from_slice(&buffer[..read])
            };
            send.reserve_capacity(data.len());
            let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .transpose()
                .map_err(h2_io)?
                .unwrap_or(0);
            if capacity < data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "HTTP/2 stream closed before providing send capacity",
                ));
            }
            send.send_data(data, false).map_err(h2_io)?;
        }
    };
    let download = async {
        let mut decoder = PaddingDecoder::new(padded);
        while let Some(chunk) = receive.data().await {
            let chunk = chunk.map_err(h2_io)?;
            let consumed = chunk.len();
            decoder.push(chunk, &mut application_write).await?;
            receive
                .flow_control()
                .release_capacity(consumed)
                .map_err(h2_io)?;
        }
        decoder.finish()?;
        application_write.shutdown().await
    };
    let _ = tokio::try_join!(upload, download);
}

fn encode_padded(payload: &[u8]) -> Bytes {
    let padding = rand::rng().random_range(0..=u8::MAX);
    let mut output = BytesMut::with_capacity(3 + payload.len() + usize::from(padding));
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(&[padding]);
    output.extend_from_slice(payload);
    output.resize(output.len() + usize::from(padding), 0);
    output.freeze()
}

struct PaddingDecoder {
    enabled: bool,
    decoded: usize,
    buffered: BytesMut,
}

impl PaddingDecoder {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            decoded: 0,
            buffered: BytesMut::new(),
        }
    }

    async fn push(
        &mut self,
        chunk: Bytes,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> std::io::Result<()> {
        if !self.enabled || self.decoded >= FIRST_PADDINGS {
            output.write_all(&chunk).await?;
            return Ok(());
        }
        self.buffered.extend_from_slice(&chunk);
        loop {
            if self.decoded >= FIRST_PADDINGS {
                output.write_all(&self.buffered.split().freeze()).await?;
                return Ok(());
            }
            if self.buffered.len() < 3 {
                return Ok(());
            }
            let payload = usize::from(u16::from_be_bytes([self.buffered[0], self.buffered[1]]));
            let padding = usize::from(self.buffered[2]);
            let frame = 3 + payload + padding;
            if self.buffered.len() < frame {
                return Ok(());
            }
            self.buffered.advance(3);
            output.write_all(&self.buffered[..payload]).await?;
            self.buffered.advance(payload + padding);
            self.decoded += 1;
        }
    }

    fn finish(&self) -> std::io::Result<()> {
        if self.enabled && self.decoded < FIRST_PADDINGS && !self.buffered.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated Naive padding frame",
            ))
        } else {
            Ok(())
        }
    }
}

fn h2_io(error: h2::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_kernel::BoxFuture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct OneStreamTransport {
        stream: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
        connections: AtomicUsize,
    }

    impl StreamTransport for OneStreamTransport {
        fn connect(
            &self,
            _ctx: TransportContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
            Box::pin(async move {
                self.connections.fetch_add(1, Ordering::Relaxed);
                self.stream
                    .lock()
                    .unwrap()
                    .take()
                    .map(|stream| Box::new(stream) as Box<dyn ByteStream>)
                    .ok_or_else(|| TransportError::new("unexpected second physical connection"))
            })
        }
    }

    #[tokio::test]
    async fn padding_decoder_handles_split_and_coalesced_frames() {
        let (mut read, mut write) = tokio::io::duplex(4096);
        let mut decoder = PaddingDecoder::new(true);
        let mut encoded = BytesMut::new();
        for index in 0..FIRST_PADDINGS {
            encoded.extend_from_slice(&encode_padded(&[index as u8]));
        }
        encoded.extend_from_slice(b"plain");
        let split = encoded.len() / 2;
        decoder
            .push(encoded.split_to(split).freeze(), &mut write)
            .await
            .unwrap();
        decoder.push(encoded.freeze(), &mut write).await.unwrap();
        decoder.finish().unwrap();
        drop(write);
        let mut output = Vec::new();
        read.read_to_end(&mut output).await.unwrap();
        assert_eq!(
            output,
            [0, 1, 2, 3, 4, 5, 6, 7]
                .into_iter()
                .chain(*b"plain")
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn pool_multiplexes_connect_streams_on_one_transport() {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let transport = Arc::new(OneStreamTransport {
            stream: std::sync::Mutex::new(Some(client)),
            connections: AtomicUsize::new(0),
        });
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (request, mut respond) = result.unwrap();
                tokio::spawn(async move {
                    let mut receive = request.into_body();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    while let Some(data) = receive.data().await {
                        let data = data.unwrap();
                        let length = data.len();
                        send.send_data(data, false).unwrap();
                        receive.flow_control().release_capacity(length).unwrap();
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        });
        let tasks = TaskScope::new();
        let pool = H2TunnelPool::new(
            Endpoint::localhost_v4(443),
            transport.clone(),
            tasks.clone(),
        );
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let mut stream = pool
                .connect(Endpoint::localhost_v4(80), H2TunnelOptions::default())
                .await
                .unwrap();
            stream.write_all(payload).await.unwrap();
            let mut echoed = vec![0_u8; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        }
        assert_eq!(transport.connections.load(Ordering::Relaxed), 1);
        tasks.cancel();
        tasks.close();
        tasks.wait().await;
        server_task.abort();
    }
}
