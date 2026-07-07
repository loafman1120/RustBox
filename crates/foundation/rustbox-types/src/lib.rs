//! RustBox 的可移植基础数据模型。
//!
//! 本 crate 位于 L0 Foundation，只描述协议和内核都能共享的纯数据。
//! 这里刻意不出现 socket、executor、Tokio、平台句柄或操作系统语义。

use core::fmt;
use core::num::NonZeroU64;

/// 可路由的主机标识，可以是域名，也可以是已经解析出的 IP。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddress),
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

/// 平台无关的 IP 表示，避免在基础层泄漏 `std::net` 具体类型。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    /// CIDR 前缀长度依赖 IP 版本，放在基础层可避免平台层重复判断。
    pub fn max_prefix_len(self) -> u8 {
        match self {
            Self::V4(_) => 32,
            Self::V6(_) => 128,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(octets) => {
                write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            Self::V6(octets) => {
                let segments = [
                    u16::from_be_bytes([octets[0], octets[1]]),
                    u16::from_be_bytes([octets[2], octets[3]]),
                    u16::from_be_bytes([octets[4], octets[5]]),
                    u16::from_be_bytes([octets[6], octets[7]]),
                    u16::from_be_bytes([octets[8], octets[9]]),
                    u16::from_be_bytes([octets[10], octets[11]]),
                    u16::from_be_bytes([octets[12], octets[13]]),
                    u16::from_be_bytes([octets[14], octets[15]]),
                ];
                write!(
                    f,
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7]
                )
            }
        }
    }
}

/// 平台无关的 CIDR 表示，用于 TUN 地址、自动路由 include/exclude 和控制面快照。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IpCidr {
    pub address: IpAddress,
    pub prefix_len: u8,
}

impl IpCidr {
    /// 返回 `None` 而不是 panic，配置层可以把它转成带路径的诊断。
    pub fn new(address: IpAddress, prefix_len: u8) -> Option<Self> {
        if prefix_len <= address.max_prefix_len() {
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
            host: Host::Ip(IpAddress::V4([127, 0, 0, 1])),
            port,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddress::V6(_)) => write!(f, "[{}]:{}", self.host, self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// RustBox 数据面当前处理的网络类别。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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
    Dns,
    Socks5,
    Other(&'static str),
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
