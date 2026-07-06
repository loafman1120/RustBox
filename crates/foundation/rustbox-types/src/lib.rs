//! Portable RustBox data types.
//!
//! This crate intentionally contains no runtime, socket, executor, or platform
//! implementation details.

use core::fmt;
use core::num::NonZeroU64;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
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
