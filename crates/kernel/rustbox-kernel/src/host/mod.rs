//! RustBox 使用的 Tokio 网络实现与平台能力契约。
//!
//! Tokio 是项目的直接依赖。这里的 trait 用于测试替身和操作系统能力注入，
//! 不是为了抽象或替换 Tokio runtime。

mod tokio_host;

pub use tokio_host::{
    DefaultTokioSocketPolicy, TokioNetworkProvider, TokioNetworkProviderFactory, TokioSocketPolicy,
};

use core::future::Future;
use core::pin::Pin;
use rustbox_io::{ByteStream, DatagramSocket, PacketDevice};
use rustbox_types::{Endpoint, IpCidr, Network, ProcessMetadata};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

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

/// 一组由组合根拥有的 Tokio 任务。
#[derive(Clone, Debug)]
pub struct TaskScope {
    cancellation: CancellationToken,
    tracker: TaskTracker,
}

/// Creates network providers for a particular dial policy.
///
/// Embedded hosts use this boundary to ensure every physical data-plane socket
/// is opened by host-owned code (for example, so Android can call
/// `VpnService.protect`).
/// Detoured connections do not pass through this factory because they are
/// opened by another outbound rather than by the physical network.
pub trait NetworkProviderFactory: Send + Sync {
    fn create(
        &self,
        purpose: NetworkProviderPurpose,
        options: DialOptions,
        resolver: Option<Arc<dyn DomainResolver>>,
    ) -> Arc<dyn NetworkProvider>;
}

/// Distinguishes local listeners from sockets that must escape through the
/// physical network. Mobile factories commonly protect only `Outbound`
/// providers from the VPN route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkProviderPurpose {
    Inbound,
    Outbound,
}

/// Minimal DNS boundary consumed by the dialer.  DNS protocol and caching stay
/// in rustbox-dns-core; the socket layer only needs ordered addresses.
pub trait DomainResolver: Send + Sync {
    fn resolve(&self, domain: String) -> BoxFuture<'_, Result<Vec<IpAddr>, NetError>>;
}

impl TaskScope {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tracker: TaskTracker::new(),
        }
    }

    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let cancellation = self.cancellation.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = task => {}
            }
        });
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn close(&self) {
        self.tracker.close();
    }

    pub async fn wait(&self) {
        self.tracker.wait().await;
    }

    pub fn is_empty(&self) -> bool {
        self.tracker.is_empty()
    }
}

impl Default for TaskScope {
    fn default() -> Self {
        Self::new()
    }
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

/// Per-outbound socket policy.  This is deliberately a value type: protocol
/// implementations borrow one configured provider instead of carrying a bag
/// of shared option objects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DialOptions {
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<IpAddr>,
    pub inet6_bind_address: Option<IpAddr>,
    pub routing_mark: Option<u32>,
    pub connect_timeout: Option<Duration>,
    /// `None` leaves the platform default untouched; `Some(None)` disables it.
    pub tcp_keepalive: Option<Option<TcpKeepaliveOptions>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpKeepaliveOptions {
    pub idle: Duration,
    pub interval: Option<Duration>,
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
    /// Desired operations retained for diagnostics and compatibility.
    pub operations: Vec<NetworkOperation>,
    /// Exact records produced after inspecting the pre-existing platform
    /// state. Release consumes these records rather than guessing from the
    /// desired operations.
    pub undo_operations: Vec<NetworkUndo>,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkUndo {
    DeleteRoute {
        destination: IpCidr,
        gateway: Option<IpAddr>,
        interface: InterfaceRef,
        metric: Option<u32>,
    },
    /// Versioned platform payload. Registry, WFP, NetworkManager and
    /// SystemConfiguration details remain outside the portable kernel.
    RestorePlatformState { namespace: String, payload: String },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
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
        gateway: Option<IpAddr>,
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
        servers: Vec<IpAddr>,
    },
    /// Install a fail-closed platform policy that permits the TUN path and the
    /// current RustBox executable while blocking other plaintext DNS paths.
    EnforceDnsLeakProtection {
        tunnel_interface_alias: String,
    },
    SetPlatformHttpProxy(PlatformProxyConfig),
}

/// 进程归属查询是路由前的元数据增强能力，不属于路由器本身。
pub trait ProcessLookup: Send + Sync {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessMetadata>, ProcessLookupError>>;
}

/// Platform network context sampled before route evaluation. Implementations
/// may cache OS queries, but must not mutate network state.
pub trait NetworkMetadataLookup: Send + Sync {
    fn lookup_network(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<NetworkMetadataInfo, NetworkMetadataError>>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkMetadataInfo {
    pub interface: Option<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_type: Option<rustbox_types::NetworkType>,
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
        source_host: String,
        source_port: u16,
        destination_host: String,
        destination_port: u16,
        domain: Option<String>,
        protocol: Option<String>,
        process: Option<String>,
        process_path: Option<String>,
        user_id: Option<u32>,
        network: String,
        inbound: String,
    },
    RouteSelected {
        decision: String,
        outbound: Option<String>,
        outbound_chain: Vec<String>,
        rule_index: Option<usize>,
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
capability_error!(PacketDeviceError);
capability_error!(NetworkControlError);
capability_error!(ProcessLookupError);
capability_error!(NetworkMetadataError);
capability_error!(TransparentProxyError);

#[cfg(test)]
mod task_scope_tests {
    use super::TaskScope;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn cancellation_drops_and_drains_tracked_tasks() {
        let scope = TaskScope::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_flag = DropFlag(dropped.clone());
        scope.spawn(async move {
            let _flag = task_flag;
            core::future::pending::<()>().await;
        });

        scope.close();
        scope.cancel();
        scope.wait().await;

        assert!(scope.is_empty());
        assert!(dropped.load(Ordering::Acquire));
    }
}
