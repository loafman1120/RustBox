//! Late-bound DNS socket adapters.

use crate::ComposeError;
use rustbox_config::{CompiledConfig, ConfigError};
use rustbox_dns_core::{
    DnsConfig, DnsError, DnsServerConfig, DnsServerProtocol, DnsSocketProvider, DnsSubsystem,
    SocketFuture,
};
use rustbox_kernel::{Outbound, OutboundContext};
use rustbox_types::{Endpoint, OutboundId};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub(super) struct DnsComposition {
    pub subsystem: Arc<DnsSubsystem>,
    bindings: Vec<(OutboundId, Arc<LateBoundDnsSocket>)>,
}

impl DnsComposition {
    pub fn bind(
        &self,
        outbounds: &HashMap<OutboundId, Arc<dyn Outbound>>,
    ) -> Result<(), ComposeError> {
        for (id, socket) in &self.bindings {
            let outbound = outbounds.get(id).cloned().ok_or_else(|| {
                ComposeError::Config(ConfigError::new(format!(
                    "DNS outbound {id} was not composed"
                )))
            })?;
            socket.bind(outbound)?;
        }
        Ok(())
    }
}

pub(super) fn compose_dns(
    compiled: &CompiledConfig,
) -> Result<Option<DnsComposition>, ComposeError> {
    let Some(dns) = &compiled.dns else {
        return Ok(None);
    };
    let mut servers = Vec::with_capacity(dns.servers.len());
    let mut sockets: HashMap<String, Arc<dyn DnsSocketProvider>> = HashMap::new();
    let mut bindings = Vec::new();
    for server in &dns.servers {
        if let Some(outbound) = server.outbound {
            if server.protocol == DnsServerProtocol::Quic {
                return Err(ComposeError::Config(ConfigError::new(format!(
                    "DNS server `{}` uses DoQ with an outbound; Hickory requires a synchronous QUIC UDP binder and RustBox does not silently bypass the configured outbound",
                    server.id
                ))));
            }
            let socket = Arc::new(LateBoundDnsSocket::new(server.endpoint.clone()));
            sockets.insert(server.id.clone(), socket.clone());
            bindings.push((outbound, socket));
        }
        servers.push(DnsServerConfig {
            id: server.id.clone(),
            protocol: server.protocol,
            endpoint: server.endpoint.clone(),
            outbound: server.outbound.map(|id| id.to_string()),
        });
    }
    let config = DnsConfig {
        servers,
        rules: dns.rules.clone(),
        final_server: Some(dns.final_server.clone()),
        cache: dns.cache.clone(),
        fake_ip: dns.fake_ip.clone(),
        hijack: dns.hijack.clone(),
    };
    let subsystem = DnsSubsystem::from_config_with_sockets(config, sockets)
        .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
    Ok(Some(DnsComposition {
        subsystem: Arc::new(subsystem),
        bindings,
    }))
}

struct LateBoundDnsSocket {
    target: Endpoint,
    outbound: OnceLock<Arc<dyn Outbound>>,
}

impl LateBoundDnsSocket {
    fn new(target: Endpoint) -> Self {
        Self {
            target,
            outbound: OnceLock::new(),
        }
    }
    fn bind(&self, outbound: Arc<dyn Outbound>) -> Result<(), ComposeError> {
        self.outbound
            .set(outbound)
            .map_err(|_| ComposeError::State("DNS outbound socket was bound twice".into()))
    }
    fn get(&self) -> Result<Arc<dyn Outbound>, DnsError> {
        self.outbound
            .get()
            .cloned()
            .ok_or_else(|| DnsError::new("DNS outbound socket used before runtime graph binding"))
    }
}

impl DnsSocketProvider for LateBoundDnsSocket {
    fn open_stream(&self) -> SocketFuture<'_, Box<dyn rustbox_io::ByteStream>> {
        Box::pin(async move {
            self.get()?
                .open_stream(OutboundContext::background(), self.target.clone())
                .await
                .map_err(|e| {
                    DnsError::new(format!("open DNS stream through outbound: {}", e.message))
                })
        })
    }
    fn open_datagram(&self) -> SocketFuture<'_, Box<dyn rustbox_io::DatagramSocket>> {
        Box::pin(async move {
            let inner = self
                .get()?
                .open_datagram(OutboundContext::background(), self.target.clone())
                .await
                .map_err(|e| {
                    DnsError::new(format!("open DNS datagram through outbound: {}", e.message))
                })?;
            Ok(Box::new(TargetedDnsDatagram {
                inner,
                target: self.target.clone(),
            }) as Box<dyn rustbox_io::DatagramSocket>)
        })
    }
}

struct TargetedDnsDatagram {
    inner: Box<dyn rustbox_io::DatagramSocket>,
    target: Endpoint,
}
impl rustbox_io::DatagramSocket for TargetedDnsDatagram {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_endpoint()
    }
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), rustbox_io::IoError>> {
        Pin::new(&mut *self.inner).poll_recv_from(cx, buf)
    }
    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _target: &Endpoint,
    ) -> Poll<Result<usize, rustbox_io::IoError>> {
        let target = self.target.clone();
        Pin::new(&mut *self.inner).poll_send_to(cx, buf, &target)
    }
}
