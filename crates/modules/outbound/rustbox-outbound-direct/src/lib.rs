//! direct outbound。
//!
//! 本模块执行“直连”出站：把内核给出的目标 Endpoint 转换为宿主
//! `NetworkProvider.connect_tcp` 调用，不直接接触系统 socket。

use rustbox_io::{ByteStream, DatagramSocket};
use rustbox_kernel::{
    BoxFuture, Event, EventKind, EventLevel, NetworkProvider, NoopObservabilitySink,
    ObservabilitySink, TcpConnect, UdpBind,
};
use rustbox_kernel::{Outbound, OutboundContext, OutboundError};
use rustbox_types::{Endpoint, Host, IpAddress, OutboundId};
use std::sync::Arc;

/// 直连出站实现，依赖注入的网络能力负责真正的 TCP 连接。
pub struct DirectOutbound {
    id: OutboundId,
    network: Arc<dyn NetworkProvider>,
    observability: Arc<dyn ObservabilitySink>,
}

impl DirectOutbound {
    pub fn new(id: OutboundId, network: Arc<dyn NetworkProvider>) -> Self {
        Self {
            id,
            network,
            observability: Arc::new(NoopObservabilitySink),
        }
    }

    pub fn with_observability(mut self, observability: Arc<dyn ObservabilitySink>) -> Self {
        self.observability = observability;
        self
    }
}

impl Outbound for DirectOutbound {
    fn id(&self) -> OutboundId {
        self.id
    }

    fn open_stream(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        // 出站模块只执行连接动作，并在能力调用前后发出结构化观测事件。
        let outbound = self.id.to_string();
        let flow_id = ctx.flow_id();
        let target_text = target.to_string();

        Box::pin(async move {
            self.observability
                .emit(Event::new(
                    EventLevel::Debug,
                    "rustbox.outbound.direct",
                    flow_id,
                    EventKind::OutboundConnecting {
                        outbound: outbound.clone(),
                        target: target_text.clone(),
                    },
                ))
                .await;

            let result = self
                .network
                .connect_tcp(TcpConnect { target })
                .await
                .map_err(|err| OutboundError::new(err.message));

            match &result {
                Ok(_) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Info,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundConnected {
                                outbound,
                                target: target_text,
                            },
                        ))
                        .await;
                }
                Err(err) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Error,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundFailed {
                                outbound,
                                target: target_text,
                                error: err.message.clone(),
                            },
                        ))
                        .await;
                }
            }

            result
        })
    }

    fn open_datagram(
        &self,
        ctx: OutboundContext<'_>,
        target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        let outbound = self.id.to_string();
        let flow_id = ctx.flow_id();
        let target_text = target.to_string();

        Box::pin(async move {
            self.observability
                .emit(Event::new(
                    EventLevel::Debug,
                    "rustbox.outbound.direct",
                    flow_id,
                    EventKind::OutboundConnecting {
                        outbound: outbound.clone(),
                        target: target_text.clone(),
                    },
                ))
                .await;

            let bind = udp_bind_endpoint_for_target(&target);
            let result = self
                .network
                .bind_udp(UdpBind { listen: bind })
                .await
                .map_err(|err| OutboundError::new(err.message));

            match &result {
                Ok(_) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Info,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundConnected {
                                outbound,
                                target: target_text,
                            },
                        ))
                        .await;
                }
                Err(err) => {
                    self.observability
                        .emit(Event::new(
                            EventLevel::Error,
                            "rustbox.outbound.direct",
                            flow_id,
                            EventKind::OutboundFailed {
                                outbound,
                                target: target_text,
                                error: err.message.clone(),
                            },
                        ))
                        .await;
                }
            }

            result
        })
    }
}

fn udp_bind_endpoint_for_target(target: &Endpoint) -> Endpoint {
    let host = match &target.host {
        Host::Ip(IpAddress::V6(octets)) if octets.iter().all(|byte| *byte == 0) => {
            Host::Ip(IpAddress::V4([0, 0, 0, 0]))
        }
        Host::Ip(IpAddress::V6(_)) => Host::Ip(IpAddress::V6([0; 16])),
        _ => Host::Ip(IpAddress::V4([0, 0, 0, 0])),
    };
    Endpoint::new(host, 0)
}
