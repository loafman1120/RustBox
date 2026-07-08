//! TUN packet-device inbound.
//!
//! The service owns lifecycle for packet-device open, network-control planning,
//! and packet-stack attachment. Platform-specific TUN creation and route
//! mutation stay behind host capability traits.

use core::sync::atomic::{AtomicBool, Ordering};
use rustbox_host_api::{
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
    network_lease: Arc<Mutex<Option<rustbox_host_api::NetworkLease>>>,
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
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }

    pub fn network_lease(&self) -> Option<rustbox_host_api::NetworkLease> {
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

            if !self.config.route_excludes.is_empty() {
                self.emit(
                    EventLevel::Warn,
                    EventKind::Diagnostic(format!(
                        "tun/{} route_excludes are parsed but route exclusion planning is not implemented yet",
                        self.id
                    )),
                )
                .await;
            }
            if self.config.platform_http_proxy || self.config.auto_redirect {
                self.emit(
                    EventLevel::Warn,
                    EventKind::Diagnostic(format!(
                        "tun/{} platform_http_proxy/auto_redirect are parsed but platform planning is not implemented yet",
                        self.id
                    )),
                )
                .await;
            }

            let mut stack = self
                .stack
                .take()
                .ok_or_else(|| ServiceError::new("tun inbound stack already attached"))?;
            let sink = self.sink.clone();
            let observability = self.observability.clone();
            let inbound_id = self.id;
            self.spawner
                .spawn(
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
                )
                .map_err(|err| ServiceError::new(err.message))?;

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
            if let Some(mut lease) = self
                .network_lease
                .lock()
                .expect("tun inbound network lease lock")
                .take()
            {
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
    info: &rustbox_host_api::PacketDeviceInfo,
) -> NetworkTransaction {
    let mut operations = Vec::new();
    if config.auto_route {
        let interface = match info.index {
            Some(index) => InterfaceRef::Index(index),
            None => InterfaceRef::Name(info.name.clone()),
        };
        let includes = if config.route_includes.is_empty() {
            default_route_includes(&config.addresses)
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use rustbox_host_api::{
        NetworkControlError, NetworkLease, PacketDeviceError, PacketDeviceInfo, PacketDeviceLease,
        SpawnError, TaskHandle,
    };
    use rustbox_io::{IoError, IoErrorKind, PacketDevice};
    use rustbox_kernel::{Flow, FlowError, FlowOutcome};
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
