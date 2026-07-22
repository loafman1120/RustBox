//! TUIC v5 client over Quinn/Tokio.
//!
//! This is an independent implementation of the published TUIC v5 wire
//! specification. One authenticated QUIC connection is shared by TCP streams
//! and UDP associations; bounded Tokio channels isolate datagram backpressure.

use bytes::{BufMut, Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use quinn::crypto::rustls::QuicClientConfig;
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError, TaskScope};
use rustbox_transport::{TlsLayerConfig, rustls_client_config};
use rustbox_types::{Endpoint, Host, OutboundId};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::PollSender;

const VERSION: u8 = 5;
const AUTHENTICATE: u8 = 0;
const CONNECT: u8 = 1;
const PACKET: u8 = 2;
const DISSOCIATE: u8 = 3;
const HEARTBEAT: u8 = 4;
const UDP_FRAGMENT_PAYLOAD: usize = 1000;

type DatagramPacket = Result<(Vec<u8>, Endpoint), IoError>;
type AssociationMap = Arc<StdMutex<HashMap<u16, mpsc::Sender<DatagramPacket>>>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicConfig {
    pub server: Endpoint,
    pub uuid: uuid::Uuid,
    pub password: String,
    pub tls: TlsLayerConfig,
    pub heartbeat: Duration,
}

struct ClientState {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

pub struct TuicOutbound {
    id: OutboundId,
    server: Endpoint,
    server_name: String,
    uuid: [u8; 16],
    password: Vec<u8>,
    client_config: quinn::ClientConfig,
    heartbeat: Duration,
    state: Mutex<Option<ClientState>>,
    associations: AssociationMap,
    next_association: AtomicU16,
    tasks: TaskScope,
}

impl TuicOutbound {
    pub fn new(
        id: OutboundId,
        mut config: TuicConfig,
        tasks: TaskScope,
    ) -> Result<Self, OutboundError> {
        if config.password.is_empty() {
            return Err(OutboundError::new("TUIC password must not be empty"));
        }
        let server_name = config
            .tls
            .server_name
            .clone()
            .unwrap_or_else(|| config.server.host.to_string());
        if config.tls.alpn.is_empty() {
            config.tls.alpn.push("h3".into());
        }
        let rustls =
            rustls_client_config(&config.tls).map_err(|error| OutboundError::new(error.message))?;
        let quic = QuicClientConfig::try_from(rustls)
            .map_err(|error| OutboundError::new(format!("TUIC QUIC TLS: {error}")))?;
        Ok(Self {
            id,
            server: config.server,
            server_name,
            uuid: *config.uuid.as_bytes(),
            password: config.password.into_bytes(),
            client_config: quinn::ClientConfig::new(Arc::new(quic)),
            heartbeat: config.heartbeat.max(Duration::from_secs(1)),
            state: Mutex::new(None),
            associations: Arc::new(StdMutex::new(HashMap::new())),
            next_association: AtomicU16::new(1),
            tasks,
        })
    }

    async fn connection(&self) -> Result<quinn::Connection, OutboundError> {
        let mut state = self.state.lock().await;
        if let Some(current) = state.as_ref()
            && current.connection.close_reason().is_none()
        {
            return Ok(current.connection.clone());
        }
        self.associations.lock().unwrap().clear();
        let address = resolve_server(&self.server).await?;
        let bind = if address.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|error| OutboundError::new(format!("TUIC UDP endpoint: {error}")))?;
        endpoint.set_default_client_config(self.client_config.clone());
        let connection = endpoint
            .connect(address, &self.server_name)
            .map_err(|error| OutboundError::new(format!("TUIC connect setup: {error}")))?
            .await
            .map_err(|error| OutboundError::new(format!("TUIC QUIC connect: {error}")))?;
        authenticate(&connection, self.uuid, &self.password).await?;
        self.tasks.spawn(dispatch_datagrams(
            connection.clone(),
            self.associations.clone(),
        ));
        self.tasks
            .spawn(send_heartbeats(connection.clone(), self.heartbeat));
        *state = Some(ClientState {
            _endpoint: endpoint,
            connection: connection.clone(),
        });
        Ok(connection)
    }

    fn allocate_association(&self) -> u16 {
        loop {
            let id = self.next_association.fetch_add(1, Ordering::Relaxed).max(1);
            if !self.associations.lock().unwrap().contains_key(&id) {
                return id;
            }
        }
    }
}

impl Outbound for TuicOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            let connection = self.connection().await?;
            let (mut send, receive) = connection
                .open_bi()
                .await
                .map_err(|error| OutboundError::new(format!("TUIC open TCP stream: {error}")))?;
            let mut header = vec![VERSION, CONNECT];
            encode_address(&target, &mut header)?;
            send.write_all(&header)
                .await
                .map_err(|error| OutboundError::new(format!("TUIC CONNECT header: {error}")))?;
            Ok(Box::new(TuicStream { send, receive }) as Box<dyn ByteStream>)
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            let connection = self.connection().await?;
            if connection.max_datagram_size().is_none() {
                return Err(OutboundError::new(
                    "TUIC server did not enable QUIC datagrams",
                ));
            }
            let association = self.allocate_association();
            let (packet_tx, packet_rx) = mpsc::channel(256);
            self.associations
                .lock()
                .unwrap()
                .insert(association, packet_tx);
            let (command_tx, command_rx) = mpsc::channel(256);
            self.tasks.spawn(send_udp_packets(
                connection.clone(),
                association,
                command_rx,
            ));
            Ok(Box::new(TuicDatagram {
                connection,
                association,
                associations: self.associations.clone(),
                commands: PollSender::new(command_tx),
                packets: packet_rx,
                tasks: self.tasks.clone(),
            }) as Box<dyn DatagramSocket>)
        })
    }
}

struct TuicStream {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.receive).poll_read(cx, output)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, input) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

enum UdpCommand {
    Send(Vec<u8>, Endpoint),
}

struct TuicDatagram {
    connection: quinn::Connection,
    association: u16,
    associations: AssociationMap,
    commands: PollSender<UdpCommand>,
    packets: mpsc::Receiver<DatagramPacket>,
    tasks: TaskScope,
}

impl Drop for TuicDatagram {
    fn drop(&mut self) {
        self.associations.lock().unwrap().remove(&self.association);
        self.commands.close();
        let connection = self.connection.clone();
        let association = self.association;
        self.tasks.spawn(async move {
            if let Ok(mut stream) = connection.open_uni().await {
                let _ = stream
                    .write_all(&[
                        VERSION,
                        DISSOCIATE,
                        (association >> 8) as u8,
                        association as u8,
                    ])
                    .await;
                let _ = stream.finish();
            }
        });
    }
}

impl DatagramSocket for TuicDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        match self.packets.poll_recv(cx) {
            Poll::Ready(Some(Ok((packet, source)))) => {
                if packet.len() > output.len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "TUIC UDP packet exceeds receive buffer",
                    )));
                }
                output[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "TUIC UDP association closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        let length = packet.len();
        match self.commands.poll_reserve(cx) {
            Poll::Ready(Ok(())) => self
                .commands
                .send_item(UdpCommand::Send(packet.to_vec(), target.clone()))
                .map(|()| Poll::Ready(Ok(length)))
                .unwrap_or_else(|_| {
                    Poll::Ready(Err(IoError::new(
                        IoErrorKind::Closed,
                        "TUIC UDP sender closed",
                    )))
                }),
            Poll::Ready(Err(_)) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "TUIC UDP sender closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn resolve_server(server: &Endpoint) -> Result<SocketAddr, OutboundError> {
    match server.host {
        Host::Ip(value) => Ok(SocketAddr::new(value, server.port)),
        Host::Domain(ref domain) => tokio::net::lookup_host((domain.as_str(), server.port))
            .await
            .map_err(|error| OutboundError::new(format!("TUIC server DNS: {error}")))?
            .next()
            .ok_or_else(|| OutboundError::new("TUIC server DNS returned no address")),
    }
}

async fn authenticate(
    connection: &quinn::Connection,
    uuid: [u8; 16],
    password: &[u8],
) -> Result<(), OutboundError> {
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, password)
        .map_err(|error| OutboundError::new(format!("TUIC TLS exporter: {error:?}")))?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| OutboundError::new(format!("TUIC authentication stream: {error}")))?;
    let mut command = Vec::with_capacity(50);
    command.extend_from_slice(&[VERSION, AUTHENTICATE]);
    command.extend_from_slice(&uuid);
    command.extend_from_slice(&token);
    stream
        .write_all(&command)
        .await
        .map_err(|error| OutboundError::new(format!("TUIC authenticate: {error}")))?;
    stream
        .finish()
        .map_err(|error| OutboundError::new(format!("TUIC authenticate finish: {error}")))
}

async fn send_heartbeats(connection: quinn::Connection, interval: Duration) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if connection.close_reason().is_some() {
            return;
        }
        if connection
            .send_datagram(Bytes::from_static(&[VERSION, HEARTBEAT]))
            .is_err()
        {
            return;
        }
    }
}

async fn send_udp_packets(
    connection: quinn::Connection,
    association: u16,
    mut commands: mpsc::Receiver<UdpCommand>,
) {
    let mut packet_id = 0_u16;
    while let Some(UdpCommand::Send(packet, target)) = commands.recv().await {
        packet_id = packet_id.wrapping_add(1);
        let total = packet.len().div_ceil(UDP_FRAGMENT_PAYLOAD).max(1);
        let Ok(total) = u8::try_from(total) else {
            continue;
        };
        for (fragment, chunk) in packet.chunks(UDP_FRAGMENT_PAYLOAD).enumerate() {
            let Ok(fragment) = u8::try_from(fragment) else {
                break;
            };
            let mut command = BytesMut::with_capacity(32 + chunk.len());
            command.extend_from_slice(&[VERSION, PACKET]);
            command.put_u16(association);
            command.put_u16(packet_id);
            command.put_u8(total);
            command.put_u8(fragment);
            command.put_u16(chunk.len() as u16);
            if fragment == 0 {
                if encode_address(&target, &mut command).is_err() {
                    break;
                }
            } else {
                command.put_u8(0xff);
            }
            command.extend_from_slice(chunk);
            if connection
                .send_datagram_wait(command.freeze())
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

struct Fragments {
    source: Option<Endpoint>,
    parts: Vec<Option<Vec<u8>>>,
}

async fn dispatch_datagrams(connection: quinn::Connection, associations: AssociationMap) {
    let mut fragments: HashMap<(u16, u16), Fragments> = HashMap::new();
    loop {
        let packet = match connection.read_datagram().await {
            Ok(packet) => packet,
            Err(_) => return,
        };
        let Ok(decoded) = decode_packet(&packet) else {
            continue;
        };
        let key = (decoded.association, decoded.packet_id);
        let entry = fragments.entry(key).or_insert_with(|| Fragments {
            source: None,
            parts: vec![None; usize::from(decoded.total)],
        });
        if entry.parts.len() != usize::from(decoded.total)
            || usize::from(decoded.fragment) >= entry.parts.len()
        {
            fragments.remove(&key);
            continue;
        }
        if decoded.source.is_some() {
            entry.source = decoded.source;
        }
        entry.parts[usize::from(decoded.fragment)] = Some(decoded.payload);
        if entry.source.is_some() && entry.parts.iter().all(Option::is_some) {
            let completed = fragments.remove(&key).expect("fragment entry exists");
            let mut payload = Vec::new();
            for part in completed.parts.into_iter().flatten() {
                payload.extend_from_slice(&part);
            }
            let sender = associations
                .lock()
                .unwrap()
                .get(&decoded.association)
                .cloned();
            if let Some(sender) = sender {
                let _ = sender.send(Ok((payload, completed.source.unwrap()))).await;
            }
        }
    }
}

struct DecodedPacket {
    association: u16,
    packet_id: u16,
    total: u8,
    fragment: u8,
    source: Option<Endpoint>,
    payload: Vec<u8>,
}

fn decode_packet(packet: &[u8]) -> Result<DecodedPacket, IoError> {
    if packet.len() < 11 || packet[0] != VERSION || packet[1] != PACKET {
        return Err(protocol_error("invalid TUIC datagram header"));
    }
    let association = u16::from_be_bytes([packet[2], packet[3]]);
    let packet_id = u16::from_be_bytes([packet[4], packet[5]]);
    let total = packet[6];
    let fragment = packet[7];
    let size = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
    if total == 0 || fragment >= total {
        return Err(protocol_error("invalid TUIC fragment counters"));
    }
    let (source, offset) = decode_address(packet, 10)?;
    if packet.len() != offset + size {
        return Err(protocol_error("TUIC datagram payload size mismatch"));
    }
    Ok(DecodedPacket {
        association,
        packet_id,
        total,
        fragment,
        source,
        payload: packet[offset..].to_vec(),
    })
}

fn encode_address(target: &Endpoint, output: &mut impl BufMut) -> Result<(), OutboundError> {
    match &target.host {
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| OutboundError::new("TUIC domain exceeds 255 bytes"))?;
            output.put_u8(0);
            output.put_u8(length);
            output.put_slice(domain.as_bytes());
        }
        Host::Ip(IpAddr::V4(address)) => {
            output.put_u8(1);
            output.put_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            output.put_u8(2);
            output.put_slice(&address.octets());
        }
    }
    output.put_u16(target.port);
    Ok(())
}

fn decode_address(packet: &[u8], offset: usize) -> Result<(Option<Endpoint>, usize), IoError> {
    let kind = *packet
        .get(offset)
        .ok_or_else(|| protocol_error("missing TUIC address"))?;
    match kind {
        0xff => Ok((None, offset + 1)),
        0 => {
            let length = usize::from(
                *packet
                    .get(offset + 1)
                    .ok_or_else(|| protocol_error("missing TUIC domain length"))?,
            );
            let end = offset + 2 + length;
            let domain = std::str::from_utf8(
                packet
                    .get(offset + 2..end)
                    .ok_or_else(|| protocol_error("truncated TUIC domain"))?,
            )
            .map_err(|_| protocol_error("invalid TUIC domain UTF-8"))?;
            let port = read_port(packet, end)?;
            Ok((Some(Endpoint::new(Host::domain(domain), port)), end + 2))
        }
        1 => {
            let end = offset + 5;
            let bytes: [u8; 4] = packet
                .get(offset + 1..end)
                .ok_or_else(|| protocol_error("truncated TUIC IPv4"))?
                .try_into()
                .unwrap();
            Ok((
                Some(Endpoint::new(
                    Host::Ip(IpAddr::V4(bytes.into())),
                    read_port(packet, end)?,
                )),
                end + 2,
            ))
        }
        2 => {
            let end = offset + 17;
            let bytes: [u8; 16] = packet
                .get(offset + 1..end)
                .ok_or_else(|| protocol_error("truncated TUIC IPv6"))?
                .try_into()
                .unwrap();
            Ok((
                Some(Endpoint::new(
                    Host::Ip(IpAddr::V6(bytes.into())),
                    read_port(packet, end)?,
                )),
                end + 2,
            ))
        }
        _ => Err(protocol_error("unknown TUIC address type")),
    }
}

fn read_port(packet: &[u8], offset: usize) -> Result<u16, IoError> {
    let bytes: [u8; 2] = packet
        .get(offset..offset + 2)
        .ok_or_else(|| protocol_error("missing TUIC port"))?
        .try_into()
        .unwrap();
    Ok(u16::from_be_bytes(bytes))
}

fn protocol_error(message: &str) -> IoError {
    IoError::new(IoErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_codec_round_trips_each_address_family() {
        for endpoint in [
            Endpoint::new(Host::domain("example.test"), 53),
            Endpoint::new(Host::Ip(IpAddr::from([192, 0, 2, 1])), 443),
            Endpoint::new(
                Host::Ip(IpAddr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
                80,
            ),
        ] {
            let mut bytes = BytesMut::new();
            encode_address(&endpoint, &mut bytes).unwrap();
            let (decoded, end) = decode_address(&bytes, 0).unwrap();
            assert_eq!(decoded, Some(endpoint));
            assert_eq!(end, bytes.len());
        }
    }
}
