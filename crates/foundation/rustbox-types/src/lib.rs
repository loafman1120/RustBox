//! RustBox 的可移植基础数据模型。
//!
//! 本 crate 位于 L0 Foundation，只描述协议和内核都能共享的纯数据。
//! 这里刻意不出现 socket、executor、Tokio、平台句柄或操作系统语义。

use core::fmt;
use core::num::NonZeroU64;
use core::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// 可路由的主机标识，可以是域名，也可以是已经解析出的 IP。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    pub fn domain(value: impl Into<String>) -> Self {
        Self::Domain(value.into())
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => f.write_str(domain),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

impl FromStr for Host {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value
            .parse::<IpAddr>()
            .map(Self::Ip)
            .unwrap_or_else(|_| Self::Domain(value.to_string())))
    }
}

/// 平台无关的 CIDR 表示，用于 TUN 地址、自动路由 include/exclude 和控制面快照。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IpCidr {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    /// 返回 `None` 而不是 panic，配置层可以把它转成带路径的诊断。
    pub fn new(address: IpAddr, prefix_len: u8) -> Option<Self> {
        let max_prefix_len = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len <= max_prefix_len {
            Some(Self {
                address,
                prefix_len,
            })
        } else {
            None
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| format!("CIDR `{value}` must include prefix length"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|_| format!("CIDR `{value}` has invalid prefix length"))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| format!("CIDR `{value}` has invalid IP address"))?;
        Self::new(address, prefix_len)
            .ok_or_else(|| format!("CIDR `{value}` has invalid prefix length"))
    }
}

/// Inclusive port range used by route rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn new(start: u16, end: u16) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = value.split_once('-') {
            let start = start
                .parse::<u16>()
                .map_err(|_| format!("port range `{value}` has invalid start"))?;
            let end = end
                .parse::<u16>()
                .map_err(|_| format!("port range `{value}` has invalid end"))?;
            Self::new(start, end).ok_or_else(|| format!("port range `{value}` has start after end"))
        } else {
            value
                .parse::<u16>()
                .map(Self::single)
                .map_err(|_| format!("port `{value}` is invalid"))
        }
    }
}

/// 网络端点，由主机和端口组成，是配置、路由、能力调用之间的通用地址。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    pub fn localhost_v4(port: u16) -> Self {
        Self {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
        }
    }

    /// Returns a standard socket address when the endpoint already contains an
    /// IP address. Domain resolution intentionally remains the caller's job.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self.host {
            Host::Ip(ip) => Some(SocketAddr::new(ip, self.port)),
            Host::Domain(_) => None,
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(value: SocketAddr) -> Self {
        Self::new(Host::Ip(value.ip()), value.port())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(_)) => write!(f, "[{}]:{}", self.host, self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

impl FromStr for Endpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, port) = split_host_port(value)?;
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("endpoint `{value}` has invalid port"))?;
        Ok(Self {
            host: host.parse::<Host>()?,
            port,
        })
    }
}

fn split_host_port(value: &str) -> Result<(&str, &str), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| format!("endpoint `{value}` has invalid bracketed IPv6 host"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("endpoint `{value}` must include host and port"))?;
        return Ok((host, port));
    }

    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("endpoint `{value}` must include host and port"))?;
    if host.contains(':') {
        return Err(format!(
            "endpoint `{value}` uses an IPv6 host and must wrap it in brackets"
        ));
    }
    Ok((host, port))
}

/// RustBox 数据面当前处理的网络类别。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Quic,
    Other(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolHint {
    Http,
    Tls,
    Quic,
    Dns,
    Socks5,
    Other(&'static str),
}

/// Platform network classification captured before routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkType {
    Ethernet,
    Wifi,
    Cellular,
    Other,
}

/// Optional process ownership metadata. Missing fields mean the platform could
/// not determine them; they never imply an empty name/path/user.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessMetadata {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub package_name: Option<String>,
    pub user_id: Option<u32>,
    pub user_name: Option<String>,
}

/// Optional platform/network metadata used by route conditions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformMetadata {
    pub process: Option<ProcessMetadata>,
    pub interface: Option<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_type: Option<NetworkType>,
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub fn new(value: NonZeroU64) -> Self {
                Self(value)
            }

            pub fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

id_type!(FlowId);
id_type!(InboundId);
id_type!(OutboundId);
id_type!(SessionId);
id_type!(ServiceId);

/// Stable internal service id used by the route `hijack-dns` action.
pub fn dns_hijack_service_id() -> ServiceId {
    ServiceId::new(NonZeroU64::MIN)
}

/// 流元数据是路由和观测的核心输入，不持有真实 socket 或平台资源。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowMeta {
    pub id: FlowId,
    pub network: Network,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub inbound: InboundId,
    pub domain: Option<Host>,
    pub protocol_hint: Option<ProtocolHint>,
    pub platform: PlatformMetadata,
}

/// 路由层输出的纯决策：转发、拒绝或交给内部服务处理。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Forward(OutboundId),
    Reject(RejectReason),
    Hijack(ServiceId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    Policy,
    NoRoute,
    UnsupportedNetwork,
    Drop,
    TcpReset,
    IcmpPortUnreachable,
    IcmpHostUnreachable,
}

/// 跨层传播的轻量错误信息，保留错误类别但不绑定具体平台错误类型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorInfo {
    pub kind: ErrorKind,
    pub message: String,
}

impl ErrorInfo {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Io,
    Network,
    Capability,
    Protocol,
    Route,
    Outbound,
    Service,
    Engine,
    Config,
    Platform,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_endpoint_hosts_and_ports() {
        let ipv4 = Endpoint::from_str("127.0.0.1:18080").expect("ipv4 endpoint");
        assert_eq!(ipv4.port, 18080);
        assert_eq!(ipv4.host, Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let ipv6 = Endpoint::from_str("[::1]:1080").expect("ipv6 endpoint");
        assert_eq!(ipv6.port, 1080);
        assert_eq!(ipv6.host, Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let domain = Endpoint::from_str("proxy.example.test:443").expect("domain endpoint");
        assert_eq!(domain.host, Host::Domain("proxy.example.test".to_string()));
    }

    #[test]
    fn parses_cidr_and_port_ranges() {
        assert_eq!(
            IpCidr::from_str("198.18.0.0/15").expect("cidr"),
            IpCidr::new(IpAddr::from([198, 18, 0, 0]), 15).expect("cidr")
        );
        assert_eq!(
            PortRange::from_str("443").expect("single"),
            PortRange::single(443)
        );
        assert_eq!(
            PortRange::from_str("1000-2000").expect("range"),
            PortRange::new(1000, 2000).expect("range")
        );
    }
}
