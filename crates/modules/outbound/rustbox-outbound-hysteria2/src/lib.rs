//! Hysteria2 outbound backed by the MIT `rsteria2` protocol crate.
//!
//! One reconnectable QUIC client is owned per outbound. TCP streams are opened
//! directly; UDP sessions are driven by one Tokio task and bounded channels.

use core::pin::Pin;
use core::task::{Context, Poll};
use rsteria2::{Config, ReconnectableClient};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError, TaskScope};
use rustbox_types::{Endpoint, OutboundId};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2Config {
    pub server: Endpoint,
    pub password: String,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs_password: Option<String>,
    pub hop_ports: Option<String>,
    pub hop_interval_seconds: Option<u64>,
    pub pin_sha256: Option<String>,
    pub ca_pem: Option<String>,
    pub fast_open: bool,
}

pub struct Hysteria2Outbound {
    id: OutboundId,
    client: ReconnectableClient,
    tasks: TaskScope,
}

impl Hysteria2Outbound {
    pub fn new(
        id: OutboundId,
        config: Hysteria2Config,
        tasks: TaskScope,
    ) -> Result<Self, OutboundError> {
        if config.password.is_empty() {
            return Err(OutboundError::new("hysteria2 password must not be empty"));
        }
        let client = ReconnectableClient::new(Config {
            server_addr: config.server.to_string(),
            server_name: config.server_name.unwrap_or_default(),
            auth: config.password,
            insecure: config.insecure,
            rx_bps: mbps_to_bytes(config.down_mbps),
            tx_bps: mbps_to_bytes(config.up_mbps),
            obfs_password: config.obfs_password.unwrap_or_default(),
            hop_ports: config.hop_ports.unwrap_or_default(),
            hop_interval_min_secs: config.hop_interval_seconds.unwrap_or_default(),
            hop_interval_max_secs: config.hop_interval_seconds.unwrap_or_default(),
            fast_open: config.fast_open,
            pin_sha256: config.pin_sha256.unwrap_or_default(),
            ca_pem: config.ca_pem.unwrap_or_default(),
            ..Config::default()
        });
        Ok(Self { id, client, tasks })
    }
}

impl Outbound for Hysteria2Outbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            self.client
                .tcp_connect(&target.to_string())
                .await
                .map(|stream| Box::new(stream) as Box<dyn ByteStream>)
                .map_err(|error| OutboundError::new(format!("hysteria2 TCP connect: {error}")))
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            let session =
                self.client.udp().await.map_err(|error| {
                    OutboundError::new(format!("hysteria2 UDP session: {error}"))
                })?;
            let (command_tx, command_rx) = mpsc::channel(256);
            let (packet_tx, packet_rx) = mpsc::channel(256);
            self.tasks.spawn(run_udp(session, command_rx, packet_tx));
            Ok(Box::new(Hysteria2Datagram {
                commands: PollSender::new(command_tx),
                packets: packet_rx,
            }) as Box<dyn DatagramSocket>)
        })
    }
}

enum UdpCommand {
    Send(Vec<u8>, String),
}

struct Hysteria2Datagram {
    commands: PollSender<UdpCommand>,
    packets: mpsc::Receiver<Result<(Vec<u8>, Endpoint), IoError>>,
}

impl Drop for Hysteria2Datagram {
    fn drop(&mut self) {
        self.commands.close();
    }
}

impl DatagramSocket for Hysteria2Datagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        match self.packets.poll_recv(cx) {
            Poll::Ready(Some(Ok((packet, source)))) => {
                let length = packet.len().min(output.len());
                output[..length].copy_from_slice(&packet[..length]);
                Poll::Ready(Ok((length, source)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "hysteria2 UDP session closed",
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
            Poll::Ready(Ok(())) => match self
                .commands
                .send_item(UdpCommand::Send(packet.to_vec(), target.to_string()))
            {
                Ok(()) => Poll::Ready(Ok(length)),
                Err(_) => Poll::Ready(Err(IoError::new(
                    IoErrorKind::Closed,
                    "hysteria2 UDP session closed",
                ))),
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "hysteria2 UDP session closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn run_udp(
    mut session: rsteria2::UdpSession,
    mut commands: mpsc::Receiver<UdpCommand>,
    packets: mpsc::Sender<Result<(Vec<u8>, Endpoint), IoError>>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(UdpCommand::Send(packet, target)) => {
                    if let Err(error) = session.send(&packet, &target) {
                        let _ = packets.send(Err(IoError::new(IoErrorKind::Other, format!("hysteria2 UDP send: {error}")))).await;
                    }
                }
                None => return,
            },
            received = session.recv() => match received {
                Ok((packet, source)) => match parse_endpoint(&source) {
                    Ok(source) => { let _ = packets.send(Ok((packet, source))).await; }
                    Err(error) => { let _ = packets.send(Err(error)).await; }
                },
                Err(error) => {
                    let _ = packets.send(Err(IoError::new(IoErrorKind::Other, format!("hysteria2 UDP receive: {error}")))).await;
                    return;
                }
            }
        }
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, IoError> {
    value
        .parse()
        .map_err(|error: String| IoError::new(IoErrorKind::InvalidInput, error))
}

fn mbps_to_bytes(value: u64) -> u64 {
    value.saturating_mul(1_000_000) / 8
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn converts_bandwidth_without_overflow() {
        assert_eq!(mbps_to_bytes(8), 1_000_000);
        assert_eq!(mbps_to_bytes(u64::MAX), u64::MAX / 8);
    }
}
