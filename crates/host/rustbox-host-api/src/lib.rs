//! RustBox 使用的 Tokio 网络实现与平台能力契约。
//!
//! Tokio 是项目的直接依赖。这里的 trait 用于测试替身和操作系统能力注入，
//! 不是为了抽象或替换 Tokio runtime。

pub mod net;
mod tokio_host;

pub use tokio_host::TokioHost;

use core::future::Future;
use core::pin::Pin;
use rustbox_io::{ByteStream, DatagramSocket, PacketDevice};
use rustbox_types::{Endpoint, IpAddress, IpCidr, Network};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type AcceptedStream = (Box<dyn ByteStream>, Endpoint);

/// 网络能力端口：核心通过它请求 TCP/UDP 操作，而不是直接打开系统 socket。
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

/// TCP 监听器抽象，由具体运行时负责 accept 并返回可移植字节流。
pub trait StreamListener: Send {
    fn local_endpoint(&self) -> Option<Endpoint>;

    fn accept(&mut self) -> BoxFuture<'_, Result<AcceptedStream, NetError>>;
}

/// 时钟能力端口，用于超时、定时器和可确定性测试。
pub trait Clock: Send + Sync {
    fn now(&self) -> HostInstant;

    fn sleep_until(&self, deadline: HostInstant) -> BoxFuture<'_, ()>;
}

/// 熵能力端口，避免协议代码隐式绑定平台随机源。
pub trait Entropy: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError>;
}

/// 任务派生能力端口，让后台任务拥有显式生命周期归属。
pub trait TaskSpawner: Send + Sync {
    fn spawn(&self, name: TaskName, task: BoxFuture<'static, ()>)
    -> Result<TaskHandle, SpawnError>;

    /// Cancel a previously spawned background task. Cancellation is idempotent.
    fn cancel(&self, handle: TaskHandle) -> Result<(), SpawnError>;
}

/// 包设备能力端口，TUN/Wintun/VpnService 等平台设施从这里进入系统。
pub trait PacketDeviceProvider: Send + Sync {
    fn open(
        &self,
        config: PacketDeviceConfig,
    ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>>;
}

/// 网络控制能力端口，承载路由、透明代理、策略路由等平台状态变更。
pub trait NetworkControl: Send + Sync {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>>;

    /// Undo every platform mutation represented by a lease. Implementations
    /// must make releasing an inactive/no-op lease harmless.
    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>>;
}

/// 透明代理能力端口。平台适配器负责监听被 redirect/TPROXY/WFP 送来的连接，
/// 并把连接的 original destination 一起交给 portable inbound。
pub trait TransparentProxyProvider: Send + Sync {
    fn bind_tcp(
        &self,
        request: TransparentTcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn TransparentStreamListener>, TransparentProxyError>>;
}

pub trait TransparentStreamListener: Send {
    fn local_endpoint(&self) -> Option<Endpoint>;

    fn accept(&mut self)
    -> BoxFuture<'_, Result<AcceptedTransparentStream, TransparentProxyError>>;
}

/// 观测能力端口，核心只发结构化事件，不选择最终日志后端。
pub trait ObservabilitySink: Send + Sync {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()>;
}

/// 默认空观测实现，供库调用者尚未注入日志后端时使用。
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentTcpBind {
    pub listen: Endpoint,
    pub mode: TransparentRedirectMode,
    pub mark: Option<u32>,
}

pub struct AcceptedTransparentStream {
    pub stream: Box<dyn ByteStream>,
    pub peer: Endpoint,
    pub original_destination: Endpoint,
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
    /// 平台可选择忽略名称，由系统分配真实 interface 名称。
    pub name: Option<String>,
    /// TUN 设备自身地址。路由 include/exclude 仍属于 `NetworkControl`。
    pub addresses: Vec<IpCidr>,
    /// 可选 MTU；为空时平台 adapter 使用系统默认值。
    pub mtu: Option<u16>,
    /// 自动路由策略只作为意图进入平台层，不在 portable core 操作系统路由表。
    pub route_mode: RouteMode,
    /// DNS 劫持/绑定策略需要和系统路由一起应用，因此也留在能力边界。
    pub dns_mode: TunDnsMode,
}

pub struct PacketDeviceInfo {
    pub name: String,
    pub index: Option<u32>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
}

pub struct PacketDeviceLease {
    pub device: Box<dyn PacketDevice>,
    pub info: PacketDeviceInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTransaction {
    pub reason: NetworkControlReason,
    pub operations: Vec<NetworkOperation>,
    pub rollback_policy: RollbackPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkLease {
    pub id: u64,
    /// lease 记录已接收的操作，后续真实平台实现可据此做幂等回滚。
    pub operations: Vec<NetworkOperation>,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMode {
    Manual,
    Auto,
    Strict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunDnsMode {
    None,
    Hijack,
    Platform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkControlReason {
    TunInbound,
    TransparentProxy,
    LeakProtection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackPolicy {
    BestEffort,
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum InterfaceRef {
    Name(String),
    Index(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransparentRedirectMode {
    Redirect,
    Tproxy,
    WfpRedirect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformProxyConfig {
    pub listen: Endpoint,
    pub bypass: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkOperation {
    AddRoute {
        destination: IpCidr,
        gateway: Option<IpAddress>,
        interface: InterfaceRef,
        metric: Option<u32>,
    },
    /// Preserve the route that currently reaches this prefix before a broader
    /// TUN route is installed. Platforms resolve the existing best route and
    /// install a more-specific copy for the requested prefix.
    PreserveRoute {
        destination: IpCidr,
    },
    SetInterfaceDns {
        interface: InterfaceRef,
        servers: Vec<IpAddress>,
    },
    SetPlatformHttpProxy(PlatformProxyConfig),
}

/// 进程归属查询是路由前的元数据增强能力，不属于路由器本身。
pub trait ProcessLookup: Send + Sync {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionKey {
    pub network: Network,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub direction: FlowDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub package_name: Option<String>,
    pub user_id: Option<u32>,
}

/// 结构化事件是核心和模块跨观测边界传递的唯一载体。
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

/// 数据面和控制面的关键事件类型，保持可序列化、可转接。
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
    TrafficRecorded {
        inbound_to_outbound_bytes: u64,
        outbound_to_inbound_bytes: u64,
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
capability_error!(ProcessLookupError);
capability_error!(TransparentProxyError);
