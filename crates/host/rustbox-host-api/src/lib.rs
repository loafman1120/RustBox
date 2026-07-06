//! Host capability contracts.
//!
//! The portable kernel depends on these traits, never on concrete host
//! implementations such as Tokio, Linux, or Windows adapters.

use core::future::Future;
use core::pin::Pin;
use rustbox_io::{ByteStream, DatagramSocket, PacketDevice};
use rustbox_types::Endpoint;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type AcceptedStream = (Box<dyn ByteStream>, Endpoint);

pub trait NetworkProvider: Send + Sync {
    fn connect_tcp(
        &self,
        request: TcpConnect,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, NetError>>;

    fn bind_tcp(
        &self,
        request: TcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn StreamListener>, NetError>>;

    fn bind_udp(
        &self,
        request: UdpBind,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, NetError>>;
}

pub trait StreamListener: Send {
    fn local_endpoint(&self) -> Option<Endpoint>;

    fn accept(&mut self) -> BoxFuture<'_, Result<AcceptedStream, NetError>>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> HostInstant;

    fn sleep_until(&self, deadline: HostInstant) -> BoxFuture<'_, ()>;
}

pub trait Entropy: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError>;
}

pub trait TaskSpawner: Send + Sync {
    fn spawn(&self, name: TaskName, task: BoxFuture<'static, ()>)
    -> Result<TaskHandle, SpawnError>;
}

pub trait PacketDeviceProvider: Send + Sync {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<Box<dyn PacketDevice>, PacketDeviceError>>;
}

pub trait NetworkControl: Send + Sync {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>>;
}

pub trait ObservabilitySink: Send + Sync {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()>;
}

#[derive(Clone, Debug, Default)]
pub struct NoopObservabilitySink;

impl ObservabilitySink for NoopObservabilitySink {
    fn emit(&self, _event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnect {
    pub target: Endpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpBind {
    pub listen: Endpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpBind {
    pub listen: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HostInstant {
    monotonic_millis: u64,
}

impl HostInstant {
    pub fn from_millis(monotonic_millis: u64) -> Self {
        Self { monotonic_millis }
    }

    pub fn as_millis(self) -> u64 {
        self.monotonic_millis
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskName(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TaskHandle {
    pub id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketDeviceConfig {
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTransaction {
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkLease {
    pub id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub level: EventLevel,
    pub target: EventTarget,
    pub flow_id: Option<rustbox_types::FlowId>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(
        level: EventLevel,
        target: impl Into<EventTarget>,
        flow_id: Option<rustbox_types::FlowId>,
        kind: EventKind,
    ) -> Self {
        Self {
            level,
            target: target.into(),
            flow_id,
            kind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventTarget(pub String);

impl From<&str> for EventTarget {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for EventTarget {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    ServiceStarting {
        service: String,
    },
    ServiceStarted {
        service: String,
    },
    ServiceStopping {
        service: String,
    },
    ServiceStopped {
        service: String,
    },
    ConnectionAccepted {
        listener: String,
        peer: String,
    },
    FlowAccepted {
        source: String,
        destination: String,
        network: String,
    },
    RouteSelected {
        decision: String,
    },
    OutboundConnecting {
        outbound: String,
        target: String,
    },
    OutboundConnected {
        outbound: String,
        target: String,
    },
    OutboundFailed {
        outbound: String,
        target: String,
        error: String,
    },
    FlowCompleted {
        outcome: String,
    },
    FlowFailed {
        error: String,
    },
    Diagnostic(String),
}

macro_rules! capability_error {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub message: String,
        }

        impl $name {
            pub fn new(message: impl Into<String>) -> Self {
                Self {
                    message: message.into(),
                }
            }
        }
    };
}

capability_error!(NetError);
capability_error!(EntropyError);
capability_error!(SpawnError);
capability_error!(PacketDeviceError);
capability_error!(NetworkControlError);
