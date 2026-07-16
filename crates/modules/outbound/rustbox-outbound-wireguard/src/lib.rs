//! Userspace WireGuard endpoint backed by WireTun and a Tokio-driven smoltcp
//! socket stack. The encrypted UDP device and TCP/UDP proxy sockets share one
//! userspace interface; no operating-system TUN interface is required.

use base64::Engine as _;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError, TaskScope};
use rustbox_types::{Endpoint, Host, IpAddress, IpCidr, OutboundId};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::PollSender;
use ts_netstack_smoltcp::CreateSocket;
use ts_netstack_smoltcp::netcore::{Channel, HasChannel, NetstackControl};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPeerConfig {
    pub server: Endpoint,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<IpCidr>,
    pub persistent_keepalive: Option<Duration>,
    pub reserved: [u8; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardConfig {
    pub addresses: Vec<IpCidr>,
    pub private_key: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeerConfig>,
    pub mtu: usize,
}

struct Session {
    channel: Channel,
}

pub struct WireGuardOutbound {
    id: OutboundId,
    config: WireGuardConfig,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    state: Mutex<Option<Session>>,
    next_port: AtomicU16,
    tasks: TaskScope,
}

impl WireGuardOutbound {
    pub fn new(
        id: OutboundId,
        config: WireGuardConfig,
        tasks: TaskScope,
    ) -> Result<Self, OutboundError> {
        if config.addresses.is_empty() {
            return Err(OutboundError::new(
                "WireGuard endpoint requires at least one address",
            ));
        }
        if config.peers.is_empty() {
            return Err(OutboundError::new(
                "WireGuard endpoint requires at least one peer",
            ));
        }
        decode_key("private_key", &config.private_key)?;
        for peer in &config.peers {
            decode_key("peer public_key", &peer.public_key)?;
            if let Some(key) = &peer.pre_shared_key {
                decode_key("peer pre_shared_key", key)?;
            }
            if peer.allowed_ips.is_empty() {
                return Err(OutboundError::new("WireGuard peer requires allowed_ips"));
            }
        }
        let local_v4 = config.addresses.iter().find_map(|cidr| match cidr.address {
            IpAddress::V4(value) => Some(Ipv4Addr::from(value)),
            IpAddress::V6(_) => None,
        });
        let local_v6 = config.addresses.iter().find_map(|cidr| match cidr.address {
            IpAddress::V6(value) => Some(Ipv6Addr::from(value)),
            IpAddress::V4(_) => None,
        });
        Ok(Self {
            id,
            config,
            local_v4,
            local_v6,
            state: Mutex::new(None),
            next_port: AtomicU16::new(30_000),
            tasks,
        })
    }

    async fn channel(&self) -> Result<Channel, OutboundError> {
        let mut state = self.state.lock().await;
        if let Some(session) = state.as_ref() {
            return Ok(session.channel.clone());
        }

        let stack_config = ts_netstack_smoltcp::netcore::Config {
            mtu: self.config.mtu.clamp(1280, 65_535),
            command_channel_capacity: Some(256),
            ..Default::default()
        };
        let (mut stack, pipe) = ts_netstack_smoltcp::piped(stack_config);
        let channel = stack.command_channel();
        self.tasks.spawn(async move { stack.run_tokio().await });
        channel
            .set_ips(
                self.config
                    .addresses
                    .iter()
                    .map(|cidr| to_std_ip(cidr.address)),
            )
            .await
            .map_err(|error| OutboundError::new(format!("WireGuard stack addresses: {error}")))?;

        let private_key = decode_key("private_key", &self.config.private_key)?;
        let mut peers = Vec::with_capacity(self.config.peers.len());
        for (index, peer) in self.config.peers.iter().enumerate() {
            let endpoint = resolve_endpoint(&peer.server).await?;
            let keepalive = peer
                .persistent_keepalive
                .map(|value| value.as_secs().clamp(1, u16::MAX as u64) as u16);
            peers.push(PeerRuntime {
                endpoint,
                allowed_ips: peer.allowed_ips.clone(),
                reserved: peer.reserved,
                tunnel: Tunn::new(
                    StaticSecret::from(private_key),
                    PublicKey::from(decode_key("peer public_key", &peer.public_key)?),
                    peer.pre_shared_key
                        .as_deref()
                        .map(|key| decode_key("peer pre_shared_key", key))
                        .transpose()?,
                    keepalive,
                    index as u32 + 1,
                    None,
                ),
            });
        }
        let bind = if peers.first().is_some_and(|peer| peer.endpoint.is_ipv6()) {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.config.listen_port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.config.listen_port)
        };
        if peers
            .iter()
            .any(|peer| peer.endpoint.is_ipv6() != bind.is_ipv6())
        {
            return Err(OutboundError::new(
                "WireGuard peers must currently use one endpoint address family",
            ));
        }
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|error| OutboundError::new(format!("WireGuard UDP bind: {error}")))?;
        self.tasks.spawn(run_wireguard(pipe, socket, peers));
        *state = Some(Session {
            channel: channel.clone(),
        });
        Ok(channel)
    }

    fn local_for(&self, remote: SocketAddr) -> Result<SocketAddr, OutboundError> {
        let ip = if remote.is_ipv4() {
            self.local_v4.map(IpAddr::V4)
        } else {
            self.local_v6.map(IpAddr::V6)
        }
        .ok_or_else(|| OutboundError::new("WireGuard endpoint has no address for target family"))?;
        let port = self.next_port.fetch_add(1, Ordering::Relaxed).max(1024);
        Ok(SocketAddr::new(ip, port))
    }
}

impl Outbound for WireGuardOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            let remote = resolve_endpoint(&target).await?;
            let channel = self.channel().await?;
            let stream = channel
                .tcp_connect(self.local_for(remote)?, remote)
                .await
                .map_err(|error| OutboundError::new(format!("WireGuard TCP connect: {error}")))?;
            Ok(Box::new(stream) as Box<dyn ByteStream>)
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            let remote = resolve_endpoint(&target).await?;
            let channel = self.channel().await?;
            let socket = channel
                .udp_bind(self.local_for(remote)?)
                .await
                .map_err(|error| OutboundError::new(format!("WireGuard UDP bind: {error}")))?;
            let (commands_tx, commands_rx) = mpsc::channel(256);
            let (packets_tx, packets_rx) = mpsc::channel(256);
            self.tasks.spawn(run_udp(socket, commands_rx, packets_tx));
            Ok(Box::new(WireGuardDatagram {
                commands: PollSender::new(commands_tx),
                packets: packets_rx,
            }) as Box<dyn DatagramSocket>)
        })
    }
}

struct PeerRuntime {
    endpoint: SocketAddr,
    allowed_ips: Vec<IpCidr>,
    reserved: [u8; 3],
    tunnel: Tunn,
}

async fn run_wireguard(
    mut pipe: ts_netstack_smoltcp::WakingPipe,
    socket: tokio::net::UdpSocket,
    mut peers: Vec<PeerRuntime>,
) {
    let mut encrypted = vec![0_u8; 65_535 + 256];
    let mut network = vec![0_u8; 65_535 + 256];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            packet = pipe.rx.recv_async() => {
                let Some(packet) = packet else { return };
                let Some(destination) = Tunn::dst_address(&packet) else { continue };
                let Some(peer) = peers.iter_mut().find(|peer| peer.allowed_ips.iter().any(|cidr| cidr_contains(*cidr, destination))) else { continue };
                if let TunnResult::WriteToNetwork(datagram) = peer.tunnel.encapsulate(&packet, &mut encrypted) {
                    apply_reserved(datagram, peer.reserved);
                    let _ = socket.send_to(datagram, peer.endpoint).await;
                }
            }
            received = socket.recv_from(&mut network) => {
                let Ok((length, source)) = received else { return };
                let Some(peer) = peers.iter_mut().find(|peer| peer.endpoint == source) else { continue };
                let mut input: &[u8] = &network[..length];
                loop {
                    match peer.tunnel.decapsulate(Some(source.ip()), input, &mut encrypted) {
                        TunnResult::WriteToNetwork(datagram) => {
                            apply_reserved(datagram, peer.reserved);
                            let _ = socket.send_to(datagram, peer.endpoint).await;
                        }
                        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => pipe.tx.send_async(packet).await,
                        TunnResult::Done | TunnResult::Err(_) => break,
                    }
                    input = &[];
                }
            }
            _ = timer.tick() => {
                for peer in &mut peers {
                    if let TunnResult::WriteToNetwork(datagram) = peer.tunnel.update_timers(&mut encrypted) {
                        apply_reserved(datagram, peer.reserved);
                        let _ = socket.send_to(datagram, peer.endpoint).await;
                    }
                }
            }
        }
    }
}

enum UdpCommand {
    Send(Vec<u8>, SocketAddr),
}

struct WireGuardDatagram {
    commands: PollSender<UdpCommand>,
    packets: mpsc::Receiver<Result<(Vec<u8>, Endpoint), IoError>>,
}

impl DatagramSocket for WireGuardDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        match self.packets.poll_recv(cx) {
            Poll::Ready(Some(Ok((packet, source)))) if packet.len() <= output.len() => {
                output[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(Ok(_))) => Poll::Ready(Err(IoError::new(
                IoErrorKind::InvalidInput,
                "WireGuard UDP packet exceeds receive buffer",
            ))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "WireGuard UDP socket closed",
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
        let Some(target) = endpoint_socket_addr(target) else {
            return Poll::Ready(Err(IoError::new(
                IoErrorKind::InvalidInput,
                "WireGuard UDP target must be resolved before sending",
            )));
        };
        let length = packet.len();
        match self.commands.poll_reserve(cx) {
            Poll::Ready(Ok(())) => self
                .commands
                .send_item(UdpCommand::Send(packet.to_vec(), target))
                .map(|()| Poll::Ready(Ok(length)))
                .unwrap_or_else(|_| {
                    Poll::Ready(Err(IoError::new(
                        IoErrorKind::Closed,
                        "WireGuard UDP sender closed",
                    )))
                }),
            Poll::Ready(Err(_)) => Poll::Ready(Err(IoError::new(
                IoErrorKind::Closed,
                "WireGuard UDP sender closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn run_udp(
    socket: ts_netstack_smoltcp::netsock::UdpSocket,
    mut commands: mpsc::Receiver<UdpCommand>,
    packets: mpsc::Sender<Result<(Vec<u8>, Endpoint), IoError>>,
) {
    // The netstack request remains queued while Recv would block, so keep the
    // same future alive when a send command wins the select. Canceling and
    // recreating it can let the abandoned receive consume the response.
    let receive = socket.recv_from_bytes();
    tokio::pin!(receive);
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(UdpCommand::Send(packet, target)) => {
                    if let Err(error) = socket.send_to(target, &packet).await {
                        let _ = packets.send(Err(io_error(format!("WireGuard UDP send: {error}")))).await;
                    }
                }
                None => return,
            },
            received = &mut receive => {
                match received {
                    Ok((source, packet)) => {
                        if packets.send(Ok((packet.to_vec(), socket_endpoint(source)))).await.is_err() { return; }
                    }
                    Err(error) => {
                        let _ = packets.send(Err(io_error(format!("WireGuard UDP receive: {error}")))).await;
                        return;
                    }
                }
                receive.set(socket.recv_from_bytes());
            }
        }
    }
}

fn decode_key(field: &str, value: &str) -> Result<[u8; 32], OutboundError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| OutboundError::new(format!("WireGuard {field}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| OutboundError::new(format!("WireGuard {field} must decode to 32 bytes")))
}

async fn resolve_endpoint(endpoint: &Endpoint) -> Result<SocketAddr, OutboundError> {
    if let Some(address) = endpoint_socket_addr(endpoint) {
        return Ok(address);
    }
    let Host::Domain(domain) = &endpoint.host else {
        unreachable!()
    };
    tokio::net::lookup_host((domain.as_str(), endpoint.port))
        .await
        .map_err(|error| OutboundError::new(format!("WireGuard DNS: {error}")))?
        .next()
        .ok_or_else(|| OutboundError::new("WireGuard DNS returned no address"))
}

fn endpoint_socket_addr(endpoint: &Endpoint) -> Option<SocketAddr> {
    match endpoint.host {
        Host::Ip(address) => Some(SocketAddr::new(to_std_ip(address), endpoint.port)),
        Host::Domain(_) => None,
    }
}

fn to_std_ip(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::V4(value) => IpAddr::V4(value.into()),
        IpAddress::V6(value) => IpAddr::V6(value.into()),
    }
}

fn cidr_contains(cidr: IpCidr, address: IpAddr) -> bool {
    match (cidr.address, address) {
        (IpAddress::V4(network), IpAddr::V4(address)) => {
            let bits = u32::from_be_bytes(network) ^ u32::from(address);
            bits.leading_zeros() >= u32::from(cidr.prefix_len)
        }
        (IpAddress::V6(network), IpAddr::V6(address)) => {
            let bits = u128::from_be_bytes(network) ^ u128::from(address);
            bits.leading_zeros() >= u32::from(cidr.prefix_len)
        }
        _ => false,
    }
}

fn apply_reserved(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.len() >= 4 {
        packet[1..4].copy_from_slice(&reserved);
    }
}

fn socket_endpoint(address: SocketAddr) -> Endpoint {
    let host = match address.ip() {
        IpAddr::V4(value) => Host::Ip(IpAddress::V4(value.octets())),
        IpAddr::V6(value) => Host::Ip(IpAddress::V6(value.octets())),
    };
    Endpoint::new(host, address.port())
}

fn io_error(message: String) -> IoError {
    IoError::new(IoErrorKind::Other, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_key_length() {
        let error = decode_key("key", "AA==").expect_err("invalid key");
        assert!(error.message.contains("32 bytes"));
    }
}
