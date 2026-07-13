//! TUN packet-device inbound.
//!
//! The service owns lifecycle for packet-device open, network-control planning,
//! and packet-stack attachment. Platform-specific TUN creation and route
//! mutation stay behind host capability traits.

use core::sync::atomic::{AtomicBool, Ordering};
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, InterfaceRef, NetworkControl, NetworkControlReason,
    NetworkOperation, NetworkTransaction, NoopObservabilitySink, ObservabilitySink,
    PacketDeviceConfig, PacketDeviceProvider, RollbackPolicy, RouteMode, TaskName, TaskSpawner,
    TunDnsMode,
};
use rustbox_kernel::{FlowSink, Inbound, Service, ServiceContext, ServiceError};
use rustbox_stack::NetworkStack;
use rustbox_types::{InboundId, IpAddress, IpCidr};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunInboundConfig {
    pub interface_name: Option<String>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    pub route_mode: RouteMode,
    pub dns_mode: TunDnsMode,
    pub auto_route: bool,
    pub strict_route: bool,
    pub route_includes: Vec<IpCidr>,
    pub route_excludes: Vec<IpCidr>,
    pub dns_servers: Vec<IpAddress>,
    pub platform_proxy: Option<rustbox_kernel::PlatformProxyConfig>,
    pub platform_http_proxy: bool,
    pub auto_redirect: bool,
}

pub struct TunInbound {
    id: InboundId,
    packet_devices: Arc<dyn PacketDeviceProvider>,
    network_control: Arc<dyn NetworkControl>,
    spawner: Arc<dyn TaskSpawner>,
    stack: Option<Box<dyn NetworkStack>>,
    sink: Arc<dyn FlowSink>,
    config: TunInboundConfig,
    observability: Arc<dyn ObservabilitySink>,
    started: AtomicBool,
    network_lease: Arc<Mutex<Option<rustbox_kernel::NetworkLease>>>,
    stack_task: Option<rustbox_kernel::TaskHandle>,
}

impl TunInbound {
    pub fn new(
        id: InboundId,
        packet_devices: Arc<dyn PacketDeviceProvider>,
        network_control: Arc<dyn NetworkControl>,
        spawner: Arc<dyn TaskSpawner>,
        stack: Box<dyn NetworkStack>,
        sink: Arc<dyn FlowSink>,
        config: TunInboundConfig,
    ) -> Self {
        Self {
            id,
            packet_devices,
            network_control,
            spawner,
            stack: Some(stack),
            sink,
            config,
            observability: Arc::new(NoopObservabilitySink),
            started: AtomicBool::new(false),
            network_lease: Arc::new(Mutex::new(None)),
            stack_task: None,
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn network_lease(&self) -> Option<rustbox_kernel::NetworkLease> {
        self.network_lease
            .lock()
            .expect("tun inbound network lease lock")
            .clone()
    }
}

impl Inbound for TunInbound {
    fn id(&self) -> InboundId {
        self.id
    }
}

impl Service for TunInbound {
    fn start(&mut self, _ctx: ServiceContext<'_>) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            if self.started.swap(true, Ordering::SeqCst) {
                return Err(ServiceError::new("tun inbound already started"));
            }

            self.emit(
                EventLevel::Info,
                EventKind::ServiceStarting {
                    service: format!("tun/{}", self.id),
                },
            )
            .await;

            let packet_config = PacketDeviceConfig {
                name: self.config.interface_name.clone(),
                addresses: self.config.addresses.clone(),
                mtu: self.config.mtu,
                route_mode: self.config.route_mode,
                dns_mode: self.config.dns_mode,
            };
            let lease = self
                .packet_devices
                .open(packet_config)
                .await
                .map_err(|err| ServiceError::new(err.message))?;

            let transaction = network_transaction(&self.config, &lease.info);
            let network_lease = self
                .network_control
                .apply(transaction)
                .await
                .map_err(|err| ServiceError::new(err.message))?;
            *self
                .network_lease
                .lock()
                .expect("tun inbound network lease lock") = Some(network_lease);

            let mut stack = self
                .stack
                .take()
                .ok_or_else(|| ServiceError::new("tun inbound stack already attached"))?;
            let sink = self.sink.clone();
            let observability = self.observability.clone();
            let inbound_id = self.id;
            let task = match self.spawner.spawn(
                TaskName(format!("tun-inbound-stack-{inbound_id}")),
                Box::pin(async move {
                    if let Err(err) = stack.attach(lease.device, sink).await {
                        observability
                            .emit(Event::new(
                                EventLevel::Error,
                                "rustbox.inbound.tun",
                                None,
                                EventKind::Diagnostic(format!(
                                    "tun/{inbound_id} stack stopped: {}",
                                    err.message
                                )),
                            ))
                            .await;
                    }
                }),
            ) {
                Ok(task) => task,
                Err(err) => {
                    let lease = self
                        .network_lease
                        .lock()
                        .expect("tun inbound network lease lock")
                        .take();
                    if let Some(lease) = lease {
                        self.network_control
                            .release(lease)
                            .await
                            .map_err(|release| {
                                ServiceError::new(format!(
                                    "{}; network rollback failed: {}",
                                    err.message, release.message
                                ))
                            })?;
                    }
                    self.started.store(false, Ordering::SeqCst);
                    return Err(ServiceError::new(err.message));
                }
            };
            self.stack_task = Some(task);

            self.emit(
                EventLevel::Info,
                EventKind::ServiceStarted {
                    service: format!("tun/{}@{}", self.id, lease.info.name),
                },
            )
            .await;
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async {
            self.started.store(false, Ordering::SeqCst);
            if let Some(task) = self.stack_task.take() {
                self.spawner
                    .cancel(task)
                    .map_err(|err| ServiceError::new(err.message))?;
            }
            let lease = self
                .network_lease
                .lock()
                .expect("tun inbound network lease lock")
                .take();
            if let Some(mut lease) = lease {
                self.network_control
                    .release(lease.clone())
                    .await
                    .map_err(|err| ServiceError::new(err.message))?;
                lease.active = false;
            }
            self.emit(
                EventLevel::Info,
                EventKind::ServiceStopped {
                    service: format!("tun/{}", self.id),
                },
            )
            .await;
            Ok(())
        })
    }
}

impl TunInbound {
    async fn emit(&self, level: EventLevel, kind: EventKind) {
        self.observability
            .emit(Event::new(level, "rustbox.inbound.tun", None, kind))
            .await;
    }
}

fn network_transaction(
    config: &TunInboundConfig,
    info: &rustbox_kernel::PacketDeviceInfo,
) -> NetworkTransaction {
    let mut operations = Vec::new();
    if config.auto_route {
        let interface = match info.index {
            Some(index) => InterfaceRef::Index(index),
            None => InterfaceRef::Name(info.name.clone()),
        };
        let includes = if config.route_includes.is_empty() {
            if config.strict_route {
                strict_route_includes(&config.addresses)
            } else {
                default_route_includes(&config.addresses)
            }
        } else {
            config.route_includes.clone()
        };
        operations.extend(
            includes
                .into_iter()
                .map(|destination| NetworkOperation::AddRoute {
                    destination,
                    gateway: None,
                    interface: interface.clone(),
                    metric: Some(1),
                }),
        );
        if !config.dns_servers.is_empty() {
            operations.push(NetworkOperation::SetInterfaceDns {
                interface: interface.clone(),
                servers: config.dns_servers.clone(),
            });
        }
        if let Some(proxy) = &config.platform_proxy {
            operations.push(NetworkOperation::SetPlatformHttpProxy(proxy.clone()));
        }
        operations.extend(
            config
                .route_excludes
                .iter()
                .copied()
                .map(|destination| NetworkOperation::PreserveRoute { destination }),
        );
    }

    NetworkTransaction {
        reason: NetworkControlReason::TunInbound,
        operations,
        rollback_policy: RollbackPolicy::Required,
    }
}

fn default_route_includes(addresses: &[IpCidr]) -> Vec<IpCidr> {
    let mut includes = Vec::new();
    if addresses
        .iter()
        .any(|address| matches!(address.address, IpAddress::V4(_)))
    {
        includes.push(IpCidr::new(IpAddress::V4([0, 0, 0, 0]), 0).expect("default v4 route"));
    }
    if addresses
        .iter()
        .any(|address| matches!(address.address, IpAddress::V6(_)))
    {
        includes.push(IpCidr::new(IpAddress::V6([0; 16]), 0).expect("default v6 route"));
    }
    includes
}

fn strict_route_includes(addresses: &[IpCidr]) -> Vec<IpCidr> {
    let mut includes = Vec::new();
    if addresses
        .iter()
        .any(|address| matches!(address.address, IpAddress::V4(_)))
    {
        includes.push(IpCidr::new(IpAddress::V4([0, 0, 0, 0]), 1).expect("v4 lower half"));
        includes.push(IpCidr::new(IpAddress::V4([128, 0, 0, 0]), 1).expect("v4 upper half"));
    }
    if addresses
        .iter()
        .any(|address| matches!(address.address, IpAddress::V6(_)))
    {
        includes.push(IpCidr::new(IpAddress::V6([0; 16]), 1).expect("v6 lower half"));
        let mut upper = [0; 16];
        upper[0] = 0x80;
        includes.push(IpCidr::new(IpAddress::V6(upper), 1).expect("v6 upper half"));
    }
    includes
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use rustbox_io::{IoError, IoErrorKind, PacketDevice};
    use rustbox_kernel::{Flow, FlowError, FlowOutcome};
    use rustbox_kernel::{
        NetworkControlError, NetworkLease, PacketDeviceError, PacketDeviceInfo, PacketDeviceLease,
        SpawnError, TaskHandle,
    };
    use rustbox_types::{FlowId, RejectReason};

    #[test]
    fn starts_packet_device_and_applies_manual_transaction() {
        let packet_provider = Arc::new(FakePacketDeviceProvider);
        let network_control = Arc::new(FakeNetworkControl::default());
        let spawner = Arc::new(FakeSpawner);
        let sink = Arc::new(RejectingSink);
        let mut inbound = TunInbound::new(
            InboundId::new(core::num::NonZeroU64::new(1).expect("id")),
            packet_provider,
            network_control.clone(),
            spawner,
            Box::new(FakeStack),
            sink,
            TunInboundConfig {
                interface_name: Some("rustbox0".to_string()),
                addresses: vec![IpCidr::new(IpAddress::V4([172, 18, 0, 1]), 30).expect("cidr")],
                mtu: Some(1500),
                route_mode: RouteMode::Manual,
                dns_mode: TunDnsMode::None,
                auto_route: false,
                strict_route: false,
                route_includes: Vec::new(),
                route_excludes: Vec::new(),
                dns_servers: Vec::new(),
                platform_proxy: None,
                platform_http_proxy: false,
                auto_redirect: false,
            },
        );

        block_on_ready(inbound.start(ServiceContext {
            engine_name: "test",
        }))
        .expect("start tun");

        let transactions = network_control.transactions.lock().expect("transactions");
        assert_eq!(transactions.len(), 1);
        assert!(transactions[0].operations.is_empty());
        assert!(inbound.network_lease().is_some());
    }

    #[test]
    fn plans_auto_route_from_device_index() {
        let config = TunInboundConfig {
            interface_name: Some("rustbox0".to_string()),
            addresses: vec![IpCidr::new(IpAddress::V4([172, 18, 0, 1]), 30).expect("cidr")],
            mtu: Some(1500),
            route_mode: RouteMode::Auto,
            dns_mode: TunDnsMode::None,
            auto_route: true,
            strict_route: false,
            route_includes: vec![IpCidr::new(IpAddress::V4([10, 0, 0, 0]), 8).expect("cidr")],
            route_excludes: Vec::new(),
            dns_servers: Vec::new(),
            platform_proxy: None,
            platform_http_proxy: false,
            auto_redirect: false,
        };
        let transaction = network_transaction(
            &config,
            &PacketDeviceInfo {
                name: "rustbox0".to_string(),
                index: Some(9),
                addresses: config.addresses.clone(),
                mtu: config.mtu,
            },
        );

        assert_eq!(transaction.operations.len(), 1);
        assert!(matches!(
            &transaction.operations[0],
            NetworkOperation::AddRoute {
                interface: InterfaceRef::Index(9),
                ..
            }
        ));
    }

    #[test]
    fn stop_cancels_stack_and_releases_network_lease() {
        let network_control = Arc::new(FakeNetworkControl::default());
        let mut inbound = test_inbound(network_control.clone(), Arc::new(FakeSpawner));
        block_on_ready(inbound.start(ServiceContext {
            engine_name: "test",
        }))
        .expect("start");

        block_on_ready(inbound.stop()).expect("stop");

        assert_eq!(network_control.released.load(Ordering::SeqCst), 1);
        assert!(inbound.network_lease().is_none());
        assert!(!inbound.started.load(Ordering::SeqCst));
    }

    #[test]
    fn spawn_failure_rolls_back_network_lease_and_resets_started_state() {
        let network_control = Arc::new(FakeNetworkControl::default());
        let mut inbound = test_inbound(network_control.clone(), Arc::new(FailingSpawner));

        let error = block_on_ready(inbound.start(ServiceContext {
            engine_name: "test",
        }))
        .expect_err("spawn must fail");

        assert!(error.message.contains("spawn rejected"));
        assert_eq!(network_control.released.load(Ordering::SeqCst), 1);
        assert!(inbound.network_lease().is_none());
        assert!(!inbound.started.load(Ordering::SeqCst));
    }

    #[test]
    fn strict_route_uses_split_defaults_and_plans_dns_and_proxy() {
        let mut config = test_tun_config();
        config.auto_route = true;
        config.strict_route = true;
        config.route_mode = RouteMode::Strict;
        config.dns_servers = vec![IpAddress::V4([172, 18, 0, 1])];
        config.platform_proxy = Some(rustbox_kernel::PlatformProxyConfig {
            listen: rustbox_types::Endpoint::localhost_v4(7890),
            bypass: vec!["<local>".to_string()],
        });
        let transaction = network_transaction(
            &config,
            &PacketDeviceInfo {
                name: "rustbox0".to_string(),
                index: Some(9),
                addresses: config.addresses.clone(),
                mtu: config.mtu,
            },
        );

        assert_eq!(transaction.operations.len(), 4);
        assert!(transaction.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::AddRoute { destination, .. } if destination.prefix_len == 1
        )));
        assert!(
            transaction
                .operations
                .iter()
                .any(|operation| matches!(operation, NetworkOperation::SetInterfaceDns { .. }))
        );
        assert!(
            transaction
                .operations
                .iter()
                .any(|operation| matches!(operation, NetworkOperation::SetPlatformHttpProxy(_)))
        );
    }

    fn test_inbound(
        network_control: Arc<FakeNetworkControl>,
        spawner: Arc<dyn TaskSpawner>,
    ) -> TunInbound {
        TunInbound::new(
            InboundId::new(core::num::NonZeroU64::new(9).expect("id")),
            Arc::new(FakePacketDeviceProvider),
            network_control,
            spawner,
            Box::new(FakeStack),
            Arc::new(RejectingSink),
            test_tun_config(),
        )
    }

    fn test_tun_config() -> TunInboundConfig {
        TunInboundConfig {
            interface_name: Some("rustbox0".to_string()),
            addresses: vec![IpCidr::new(IpAddress::V4([172, 18, 0, 1]), 30).expect("cidr")],
            mtu: Some(1500),
            route_mode: RouteMode::Manual,
            dns_mode: TunDnsMode::None,
            auto_route: false,
            strict_route: false,
            route_includes: Vec::new(),
            route_excludes: Vec::new(),
            dns_servers: Vec::new(),
            platform_proxy: None,
            platform_http_proxy: false,
            auto_redirect: false,
        }
    }

    #[derive(Default)]
    struct FakePacketDeviceProvider;

    impl PacketDeviceProvider for FakePacketDeviceProvider {
        fn open(
            &self,
            config: PacketDeviceConfig,
        ) -> BoxFuture<'_, Result<PacketDeviceLease, PacketDeviceError>> {
            Box::pin(async move {
                Ok(PacketDeviceLease {
                    device: Box::new(ClosedPacketDevice),
                    info: PacketDeviceInfo {
                        name: config.name.unwrap_or_else(|| "rustbox-test0".to_string()),
                        index: Some(42),
                        addresses: config.addresses,
                        mtu: config.mtu,
                    },
                })
            })
        }
    }

    #[derive(Default)]
    struct FakeNetworkControl {
        transactions: Mutex<Vec<NetworkTransaction>>,
        released: core::sync::atomic::AtomicUsize,
    }

    impl NetworkControl for FakeNetworkControl {
        fn apply(
            &self,
            transaction: NetworkTransaction,
        ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
            self.transactions
                .lock()
                .expect("transactions")
                .push(transaction.clone());
            Box::pin(async move {
                Ok(NetworkLease {
                    id: 1,
                    operations: transaction.operations,
                    active: true,
                })
            })
        }

        fn release(&self, _lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
            self.released.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct FakeSpawner;

    impl TaskSpawner for FakeSpawner {
        fn spawn(
            &self,
            _name: TaskName,
            _task: BoxFuture<'static, ()>,
        ) -> Result<TaskHandle, SpawnError> {
            Ok(TaskHandle { id: 1 })
        }

        fn cancel(&self, _handle: TaskHandle) -> Result<(), SpawnError> {
            Ok(())
        }
    }

    struct FailingSpawner;

    impl TaskSpawner for FailingSpawner {
        fn spawn(
            &self,
            _name: TaskName,
            _task: BoxFuture<'static, ()>,
        ) -> Result<TaskHandle, SpawnError> {
            Err(SpawnError::new("spawn rejected"))
        }

        fn cancel(&self, _handle: TaskHandle) -> Result<(), SpawnError> {
            Ok(())
        }
    }

    struct FakeStack;

    impl NetworkStack for FakeStack {
        fn attach(
            &mut self,
            _device: Box<dyn PacketDevice>,
            _sink: Arc<dyn FlowSink>,
        ) -> BoxFuture<'_, Result<(), rustbox_stack::StackError>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ClosedPacketDevice;

    impl PacketDevice for ClosedPacketDevice {
        fn poll_recv_packet(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<Result<usize, IoError>> {
            Poll::Ready(Err(IoError::new(IoErrorKind::Closed, "closed")))
        }

        fn poll_send_packet(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _packet: &[u8],
        ) -> Poll<Result<usize, IoError>> {
            Poll::Ready(Err(IoError::new(IoErrorKind::Closed, "closed")))
        }
    }

    struct RejectingSink;

    impl FlowSink for RejectingSink {
        fn submit(&self, flow: Flow) -> BoxFuture<'_, Result<FlowOutcome, FlowError>> {
            let _ = FlowId::new(core::num::NonZeroU64::new(flow.meta.id.get()).expect("id"));
            Box::pin(async { Ok(FlowOutcome::Rejected(RejectReason::Policy)) })
        }
    }

    fn block_on_ready<T>(future: impl core::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut future = core::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
