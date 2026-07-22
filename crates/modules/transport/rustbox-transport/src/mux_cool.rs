//! Mux.Cool v1 client session shared by target-oriented proxy outbounds.

use crate::TransportError;
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{Outbound, OutboundContext, TaskScope};
use rustbox_types::{Endpoint, Host};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::PollSender;

const NEW: u8 = 1;
const KEEP: u8 = 2;
const END: u8 = 3;
const DATA: u8 = 1;
const MAX_PAYLOAD: usize = 60 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxCoolConfig {
    pub max_streams: usize,
    pub max_connections: usize,
    pub buffer_size: usize,
}

impl Default for MuxCoolConfig {
    fn default() -> Self {
        Self {
            max_streams: 32,
            max_connections: 4,
            buffer_size: 64 * 1024,
        }
    }
}

struct SessionHandle {
    commands: mpsc::Sender<Command>,
    active: Arc<AtomicUsize>,
}

impl Clone for SessionHandle {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            active: self.active.clone(),
        }
    }
}

pub struct MuxCoolPool {
    outbound: Arc<dyn Outbound>,
    config: MuxCoolConfig,
    sessions: Mutex<Vec<SessionHandle>>,
    next_id: AtomicU16,
    next_global_id: AtomicU64,
    tasks: TaskScope,
}

impl MuxCoolPool {
    pub fn new(outbound: Arc<dyn Outbound>, config: MuxCoolConfig, tasks: TaskScope) -> Self {
        Self {
            outbound,
            config,
            sessions: Mutex::new(Vec::new()),
            next_id: AtomicU16::new(1),
            next_global_id: AtomicU64::new(1),
            tasks,
        }
    }

    pub async fn open(&self, target: Endpoint) -> Result<Box<dyn ByteStream>, TransportError> {
        let session = self.acquire_session().await?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
        let (application, relay) = tokio::io::duplex(self.config.buffer_size.max(4096));
        let (accepted_tx, accepted_rx) = oneshot::channel();
        if session
            .commands
            .send(Command::Open {
                id,
                target,
                relay,
                accepted: accepted_tx,
            })
            .await
            .is_err()
        {
            session.active.fetch_sub(1, Ordering::Release);
            return Err(TransportError::new("Mux.Cool session closed"));
        }
        match accepted_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                session.active.fetch_sub(1, Ordering::Release);
                return Err(error);
            }
            Err(_) => {
                session.active.fetch_sub(1, Ordering::Release);
                return Err(TransportError::new("Mux.Cool session closed during open"));
            }
        }
        Ok(Box::new(application) as Box<dyn ByteStream>)
    }

    pub async fn open_datagram(
        &self,
        target: Endpoint,
    ) -> Result<Box<dyn DatagramSocket>, TransportError> {
        let session = self.acquire_session().await?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
        let global_id = self.next_global_id.fetch_add(1, Ordering::Relaxed).max(1);
        let (packets_tx, packets_rx) = mpsc::channel(256);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        if session
            .commands
            .send(Command::OpenDatagram {
                id,
                target,
                global_id,
                packets: packets_tx,
                accepted: accepted_tx,
            })
            .await
            .is_err()
        {
            session.active.fetch_sub(1, Ordering::Release);
            return Err(TransportError::new("Mux.Cool session closed"));
        }
        match accepted_rx.await {
            Ok(Ok(())) => Ok(Box::new(MuxCoolDatagram {
                id,
                commands: PollSender::new(session.commands),
                packets: packets_rx,
            })),
            Ok(Err(error)) => {
                session.active.fetch_sub(1, Ordering::Release);
                Err(error)
            }
            Err(_) => {
                session.active.fetch_sub(1, Ordering::Release);
                Err(TransportError::new(
                    "Mux.Cool session closed during UDP open",
                ))
            }
        }
    }

    async fn acquire_session(&self) -> Result<SessionHandle, TransportError> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| !session.commands.is_closed());
        if let Some(session) = sessions
            .iter()
            .min_by_key(|session| session.active.load(Ordering::Acquire))
            && session.active.load(Ordering::Acquire) < self.config.max_streams.max(1)
        {
            session.active.fetch_add(1, Ordering::AcqRel);
            return Ok(session.clone());
        }
        if sessions.len() >= self.config.max_connections.max(1) {
            return Err(TransportError::new("Mux.Cool pool capacity reached"));
        }
        let marker = Endpoint::new(Host::domain("v1.mux.cool"), 0);
        let stream = self
            .outbound
            .open_stream(OutboundContext::background(), marker)
            .await
            .map_err(|error| TransportError::new(format!("Mux.Cool carrier: {}", error.message)))?;
        let (commands, receiver) = mpsc::channel(self.config.max_streams.max(1) * 4);
        let active = Arc::new(AtomicUsize::new(1));
        self.tasks.spawn(run_session(
            stream,
            receiver,
            commands.clone(),
            self.tasks.clone(),
            self.config.max_streams.max(1),
            active.clone(),
        ));
        let session = SessionHandle { commands, active };
        sessions.push(session.clone());
        Ok(session)
    }
}

enum Command {
    Open {
        id: u16,
        target: Endpoint,
        relay: tokio::io::DuplexStream,
        accepted: oneshot::Sender<Result<(), TransportError>>,
    },
    OpenDatagram {
        id: u16,
        target: Endpoint,
        global_id: u64,
        packets: mpsc::Sender<Result<(Vec<u8>, Endpoint), IoError>>,
        accepted: oneshot::Sender<Result<(), TransportError>>,
    },
    Data {
        id: u16,
        payload: Vec<u8>,
    },
    Datagram {
        id: u16,
        target: Endpoint,
        payload: Vec<u8>,
    },
    End {
        id: u16,
    },
}

enum Substream {
    Stream(tokio::io::WriteHalf<tokio::io::DuplexStream>),
    Datagram(mpsc::Sender<Result<(Vec<u8>, Endpoint), IoError>>),
}

async fn run_session(
    stream: Box<dyn ByteStream>,
    mut commands: mpsc::Receiver<Command>,
    sender: mpsc::Sender<Command>,
    tasks: TaskScope,
    max_streams: usize,
    active: Arc<AtomicUsize>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut streams: HashMap<u16, Substream> = HashMap::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Open { id, target, relay, accepted }) => {
                    if streams.len() >= max_streams {
                        let _ = accepted.send(Err(TransportError::new("Mux.Cool session stream limit reached")));
                        continue;
                    }
                    let (read, write) = tokio::io::split(relay);
                    let frame = match new_frame(id, &target) {
                        Ok(frame) => frame,
                        Err(error) => { let _ = accepted.send(Err(error)); continue; }
                    };
                    if writer.write_all(&frame).await.is_err() { let _ = accepted.send(Err(TransportError::new("Mux.Cool carrier write failed"))); return; }
                    streams.insert(id, Substream::Stream(write));
                    spawn_upload(read, id, sender.clone(), &tasks);
                    let _ = accepted.send(Ok(()));
                }
                Some(Command::OpenDatagram { id, target, global_id, packets, accepted }) => {
                    if streams.len() >= max_streams {
                        let _ = accepted.send(Err(TransportError::new("Mux.Cool session stream limit reached")));
                        continue;
                    }
                    let frame = match new_datagram_frame(id, &target, global_id) {
                        Ok(frame) => frame,
                        Err(error) => { let _ = accepted.send(Err(error)); continue; }
                    };
                    if writer.write_all(&frame).await.is_err() { let _ = accepted.send(Err(TransportError::new("Mux.Cool carrier write failed"))); return; }
                    streams.insert(id, Substream::Datagram(packets));
                    let _ = accepted.send(Ok(()));
                }
                Some(Command::Data { id, payload }) => {
                    if writer.write_all(&data_frame(id, &payload)).await.is_err() { return; }
                }
                Some(Command::Datagram { id, target, payload }) => {
                    let frame = match datagram_frame(id, &target, &payload) {
                        Ok(frame) => frame,
                        Err(_) => continue,
                    };
                    if writer.write_all(&frame).await.is_err() { return; }
                }
                Some(Command::End { id }) => {
                    let _ = writer.write_all(&simple_frame(id, END)).await;
                    if streams.remove(&id).is_some() {
                        active.fetch_sub(1, Ordering::Release);
                    }
                }
                None => return,
            },
            frame = read_frame(&mut reader) => match frame {
                Ok(frame) => {
                    let failed = match streams.get_mut(&frame.id) {
                        Some(Substream::Stream(stream)) => {
                            !frame.payload.is_empty() && stream.write_all(&frame.payload).await.is_err()
                        }
                        Some(Substream::Datagram(packets)) => {
                            if let Some(target) = frame.target.clone() {
                                packets.send(Ok((frame.payload.clone(), target))).await.is_err()
                            } else { false }
                        }
                        None => false,
                    };
                    if failed || frame.status == END {
                        if let Some(Substream::Stream(stream)) = streams.get_mut(&frame.id) {
                            let _ = stream.shutdown().await;
                        }
                        if streams.remove(&frame.id).is_some() { active.fetch_sub(1, Ordering::Release); }
                    }
                }
                Err(_) => return,
            }
        }
    }
}

fn spawn_upload(
    mut read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    id: u16,
    sender: mpsc::Sender<Command>,
    tasks: &TaskScope,
) {
    tasks.spawn(async move {
        let mut buffer = vec![0_u8; MAX_PAYLOAD];
        loop {
            match read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = sender.send(Command::End { id }).await;
                    return;
                }
                Ok(length) => {
                    if sender
                        .send(Command::Data {
                            id,
                            payload: buffer[..length].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
}

struct MuxCoolDatagram {
    id: u16,
    commands: PollSender<Command>,
    packets: mpsc::Receiver<Result<(Vec<u8>, Endpoint), IoError>>,
}

impl DatagramSocket for MuxCoolDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        match self.packets.poll_recv(cx) {
            Poll::Ready(Some(Ok((packet, source)))) => {
                if packet.len() > buffer.len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "Mux.Cool receive buffer is too small",
                    )));
                }
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "Mux.Cool UDP association closed",
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
        match self.commands.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let length = packet.len();
                let id = self.id;
                self.commands
                    .send_item(Command::Datagram {
                        id,
                        target: target.clone(),
                        payload: packet.to_vec(),
                    })
                    .map(|()| Poll::Ready(Ok(length)))
                    .unwrap_or_else(|_| {
                        Poll::Ready(Err(IoError::new(
                            IoErrorKind::Closed,
                            "Mux.Cool UDP sender closed",
                        )))
                    })
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "Mux.Cool UDP sender closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for MuxCoolDatagram {
    fn drop(&mut self) {
        if let Some(sender) = self.commands.get_ref() {
            let _ = sender.try_send(Command::End { id: self.id });
        }
        self.commands.close();
    }
}

struct Frame {
    id: u16,
    status: u8,
    payload: Vec<u8>,
    target: Option<Endpoint>,
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Frame> {
    let metadata_length = reader.read_u16().await? as usize;
    if !(4..=1024).contains(&metadata_length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid Mux.Cool metadata length",
        ));
    }
    let mut metadata = vec![0_u8; metadata_length];
    reader.read_exact(&mut metadata).await?;
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let target = if metadata.len() > 7 && metadata[4] == 2 {
        Some(decode_endpoint(&metadata[5..])?)
    } else {
        None
    };
    let payload = if metadata[3] & DATA != 0 {
        let length = reader.read_u16().await? as usize;
        let mut payload = vec![0_u8; length];
        reader.read_exact(&mut payload).await?;
        payload
    } else {
        Vec::new()
    };
    Ok(Frame {
        id,
        status,
        payload,
        target,
    })
}

fn new_datagram_frame(
    id: u16,
    target: &Endpoint,
    global_id: u64,
) -> Result<Vec<u8>, TransportError> {
    let mut metadata = Vec::with_capacity(40);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[NEW, 0, 2]);
    metadata.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&mut metadata, &target.host)?;
    metadata.extend_from_slice(&global_id.to_be_bytes());
    wrap_metadata(metadata, &[])
}

fn datagram_frame(id: u16, target: &Endpoint, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::new(
            "Mux.Cool UDP packet exceeds 65535 bytes",
        ));
    }
    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[KEEP, DATA, 2]);
    metadata.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&mut metadata, &target.host)?;
    wrap_metadata(metadata, payload)
}

fn wrap_metadata(metadata: Vec<u8>, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    let length = u16::try_from(metadata.len())
        .map_err(|_| TransportError::new("Mux.Cool metadata exceeds 65535 bytes"))?;
    let mut frame = Vec::with_capacity(metadata.len() + payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&metadata);
    if !payload.is_empty() {
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
    }
    Ok(frame)
}

fn decode_endpoint(bytes: &[u8]) -> std::io::Result<Endpoint> {
    if bytes.len() < 3 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let host = match bytes[2] {
        1 if bytes.len() >= 7 => Host::Ip(IpAddr::V4(
            <[u8; 4]>::try_from(&bytes[3..7]).unwrap().into(),
        )),
        2 if bytes.len() >= 4 + bytes[3] as usize => {
            let length = bytes[3] as usize;
            let domain = std::str::from_utf8(&bytes[4..4 + length])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            Host::domain(domain)
        }
        3 if bytes.len() >= 19 => Host::Ip(IpAddr::V6(
            <[u8; 16]>::try_from(&bytes[3..19]).unwrap().into(),
        )),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Mux.Cool UDP address",
            ));
        }
    };
    Ok(Endpoint::new(host, port))
}

fn new_frame(id: u16, target: &Endpoint) -> Result<Vec<u8>, TransportError> {
    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[NEW, 0, 1]);
    metadata.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&mut metadata, &target.host)?;
    let mut frame = Vec::with_capacity(metadata.len() + 2);
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    Ok(frame)
}

fn data_frame(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = simple_frame_with_options(id, KEEP, DATA);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn simple_frame(id: u16, status: u8) -> Vec<u8> {
    simple_frame_with_options(id, status, 0)
}

fn simple_frame_with_options(id: u16, status: u8, options: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6);
    frame.extend_from_slice(&4_u16.to_be_bytes());
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[status, options]);
    frame
}

fn encode_address(output: &mut Vec<u8>, host: &Host) -> Result<(), TransportError> {
    match host {
        Host::Ip(IpAddr::V4(value)) => {
            output.push(1);
            output.extend_from_slice(&value.octets());
        }
        Host::Domain(value) => {
            output.push(2);
            output.push(
                u8::try_from(value.len())
                    .map_err(|_| TransportError::new("Mux.Cool domain exceeds 255 bytes"))?,
            );
            output.extend_from_slice(value.as_bytes());
        }
        Host::Ip(IpAddr::V6(value)) => {
            output.push(3);
            output.extend_from_slice(&value.octets());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_io::DatagramSocket;
    use rustbox_kernel::{BoxFuture, OutboundError};
    use rustbox_types::OutboundId;
    use std::num::NonZeroU64;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn new_frame_contains_target() {
        let frame = new_frame(7, &Endpoint::new(Host::domain("example.com"), 443)).unwrap();
        assert_eq!(&frame[2..4], &7_u16.to_be_bytes());
        assert!(frame.ends_with(b"example.com"));
    }

    #[test]
    fn datagram_frames_carry_network_target_and_global_id() {
        let target = Endpoint::new(Host::domain("dns.example"), 53);
        let frame = new_datagram_frame(9, &target, 42).unwrap();
        let metadata_length = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let metadata = &frame[2..2 + metadata_length];
        assert_eq!(&metadata[..5], &[0, 9, NEW, 0, 2]);
        assert_eq!(&metadata[metadata.len() - 8..], &42_u64.to_be_bytes());

        let keep = datagram_frame(9, &target, b"query").unwrap();
        assert_eq!(keep[4], KEEP);
        assert_eq!(keep[5], DATA);
        assert!(keep.ends_with(b"query"));
    }

    struct CarrierOutbound {
        streams: StdMutex<Vec<tokio::io::DuplexStream>>,
        connections: AtomicUsize,
    }

    impl Outbound for CarrierOutbound {
        fn id(&self) -> OutboundId {
            OutboundId::new(NonZeroU64::new(1).unwrap())
        }

        fn open_stream(
            &self,
            _ctx: OutboundContext<'_>,
            target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
            Box::pin(async move {
                assert_eq!(target.host, Host::domain("v1.mux.cool"));
                self.connections.fetch_add(1, Ordering::Relaxed);
                self.streams
                    .lock()
                    .unwrap()
                    .pop()
                    .map(|stream| Box::new(stream) as Box<dyn ByteStream>)
                    .ok_or_else(|| OutboundError::new("unexpected carrier reconnect"))
            })
        }

        fn open_datagram(
            &self,
            _ctx: OutboundContext<'_>,
            _target: Endpoint,
        ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
            Box::pin(async { Err(OutboundError::new("unused")) })
        }
    }

    #[tokio::test]
    async fn pool_multiplexes_two_streams_on_one_carrier() {
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let carrier = Arc::new(CarrierOutbound {
            streams: StdMutex::new(vec![client]),
            connections: AtomicUsize::new(0),
        });
        let server_task = tokio::spawn(async move {
            loop {
                let length = match server.read_u16().await {
                    Ok(value) => value as usize,
                    Err(_) => return,
                };
                let mut metadata = vec![0_u8; length];
                server.read_exact(&mut metadata).await.unwrap();
                let id = u16::from_be_bytes([metadata[0], metadata[1]]);
                let status = metadata[2];
                if metadata[3] & DATA != 0 {
                    let length = server.read_u16().await.unwrap() as usize;
                    let mut payload = vec![0_u8; length];
                    server.read_exact(&mut payload).await.unwrap();
                    server.write_all(&data_frame(id, &payload)).await.unwrap();
                } else if status == END {
                    server.write_all(&simple_frame(id, END)).await.unwrap();
                }
            }
        });
        let tasks = TaskScope::new();
        let pool = MuxCoolPool::new(carrier.clone(), MuxCoolConfig::default(), tasks.clone());
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let mut stream = pool.open(Endpoint::localhost_v4(80)).await.unwrap();
            stream.write_all(payload).await.unwrap();
            let mut echoed = vec![0_u8; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        }
        assert_eq!(carrier.connections.load(Ordering::Relaxed), 1);
        tasks.cancel();
        tasks.close();
        tasks.wait().await;
        server_task.abort();
    }

    #[tokio::test]
    async fn pool_opens_another_carrier_when_stream_capacity_is_full() {
        let (client_one, server_one) = tokio::io::duplex(64 * 1024);
        let (client_two, server_two) = tokio::io::duplex(64 * 1024);
        let carrier = Arc::new(CarrierOutbound {
            streams: StdMutex::new(vec![client_two, client_one]),
            connections: AtomicUsize::new(0),
        });
        let tasks = TaskScope::new();
        let pool = MuxCoolPool::new(
            carrier.clone(),
            MuxCoolConfig {
                max_streams: 1,
                max_connections: 2,
                buffer_size: 4096,
            },
            tasks.clone(),
        );
        let first = pool.open(Endpoint::localhost_v4(80)).await.unwrap();
        let second = pool.open(Endpoint::localhost_v4(81)).await.unwrap();
        assert_eq!(carrier.connections.load(Ordering::Relaxed), 2);
        drop(first);
        drop(second);
        drop(pool);
        drop(server_one);
        drop(server_two);
        tasks.cancel();
        tasks.close();
        tasks.wait().await;
    }

    #[tokio::test]
    async fn pool_relays_xudp_packets_with_per_packet_targets() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let carrier = Arc::new(CarrierOutbound {
            streams: StdMutex::new(vec![client]),
            connections: AtomicUsize::new(0),
        });
        let server_task = tokio::spawn(async move {
            let new_length = server.read_u16().await.unwrap() as usize;
            let mut new_metadata = vec![0; new_length];
            server.read_exact(&mut new_metadata).await.unwrap();
            let id = u16::from_be_bytes([new_metadata[0], new_metadata[1]]);
            assert_eq!(new_metadata[4], 2);

            let keep_length = server.read_u16().await.unwrap() as usize;
            let mut keep_metadata = vec![0; keep_length];
            server.read_exact(&mut keep_metadata).await.unwrap();
            assert_eq!(keep_metadata[2], KEEP);
            assert_eq!(keep_metadata[4], 2);
            let payload_length = server.read_u16().await.unwrap() as usize;
            let mut payload = vec![0; payload_length];
            server.read_exact(&mut payload).await.unwrap();
            let source = Endpoint::new(Host::domain("response.example"), 5353);
            server
                .write_all(&datagram_frame(id, &source, &payload).unwrap())
                .await
                .unwrap();
        });
        let tasks = TaskScope::new();
        let pool = MuxCoolPool::new(carrier, MuxCoolConfig::default(), tasks.clone());
        let mut socket = pool
            .open_datagram(Endpoint::new(Host::domain("dns.example"), 53))
            .await
            .unwrap();
        let target = Endpoint::new(Host::domain("other.example"), 53);
        std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_send_to(cx, b"query", &target))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (length, source) =
            std::future::poll_fn(|cx| Pin::new(&mut *socket).poll_recv_from(cx, &mut buffer))
                .await
                .unwrap();
        assert_eq!(&buffer[..length], b"query");
        assert_eq!(
            source,
            Endpoint::new(Host::domain("response.example"), 5353)
        );
        drop(socket);
        drop(pool);
        server_task.await.unwrap();
        tasks.cancel();
        tasks.close();
        tasks.wait().await;
    }
}
