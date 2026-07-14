use crate::{
    ComposeError,
    platform::{transparent_proxy_provider, tun_platform_capabilities},
};
use rustbox_config::{CompiledInbound, CompiledInboundKind, ConfigError};
use rustbox_inbound_anytls::{AnyTlsInbound, AnyTlsServerConfig};
use rustbox_inbound_http::{HttpInboundCredentials, HttpProxyInbound};
use rustbox_inbound_socks5::{
    MixedInbound, MixedInboundCredentials, Socks5Inbound, Socks5InboundCredentials,
};
use rustbox_inbound_transparent::{
    TransparentInboundConfig as RuntimeTransparentInboundConfig, TransparentProxyInbound,
};
use rustbox_inbound_tun::{TunInbound, TunInboundConfig as RuntimeTunInboundConfig};
use rustbox_kernel::{FlowSink, Service};
use rustbox_kernel::{ObservabilitySink, TokioNetworkProvider};
use rustbox_types::Host;
use std::sync::Arc;

pub(crate) fn compose_inbounds(
    inbounds: Vec<CompiledInbound>,
    host: &Arc<TokioNetworkProvider>,
    observability: &Arc<dyn ObservabilitySink>,
    sink: &Arc<dyn FlowSink>,
) -> Result<Vec<Box<dyn Service>>, ComposeError> {
    let mut services: Vec<Box<dyn Service>> = Vec::new();
    let platform_proxy_listen = inbounds.iter().find_map(|inbound| match &inbound.kind {
        CompiledInboundKind::Mixed { listen, .. }
        | CompiledInboundKind::HttpConnect { listen, .. } => Some(listen.clone()),
        _ => None,
    });

    for inbound in inbounds {
        match inbound.kind {
            CompiledInboundKind::Mixed {
                listen,
                username,
                password,
            } => {
                let mut inbound = MixedInbound::new(inbound.id, listen, host.clone(), sink.clone())
                    .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username, password) {
                    inbound =
                        inbound.with_credentials(MixedInboundCredentials { username, password });
                }
                services.push(Box::new(inbound));
            }
            CompiledInboundKind::HttpConnect {
                listen,
                username,
                password,
            } => {
                let mut inbound =
                    HttpProxyInbound::new(inbound.id, listen, host.clone(), sink.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username, password) {
                    inbound =
                        inbound.with_credentials(HttpInboundCredentials { username, password });
                }
                services.push(Box::new(inbound));
            }
            CompiledInboundKind::Socks5 {
                listen,
                username,
                password,
            } => {
                let mut inbound =
                    Socks5Inbound::new(inbound.id, listen, host.clone(), sink.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username, password) {
                    inbound =
                        inbound.with_credentials(Socks5InboundCredentials { username, password });
                }
                services.push(Box::new(inbound));
            }
            CompiledInboundKind::AnyTls {
                listen,
                password,
                tls,
            } => {
                let certificate_pem =
                    std::fs::read_to_string(&tls.certificate_path).map_err(|error| {
                        ComposeError::Config(ConfigError::new(format!(
                            "read AnyTLS certificate `{}`: {error}",
                            tls.certificate_path
                        )))
                    })?;
                let private_key_pem =
                    std::fs::read_to_string(&tls.private_key_path).map_err(|error| {
                        ComposeError::Config(ConfigError::new(format!(
                            "read AnyTLS private key `{}`: {error}",
                            tls.private_key_path
                        )))
                    })?;
                let inbound = AnyTlsInbound::new(
                    inbound.id,
                    listen,
                    AnyTlsServerConfig {
                        password,
                        certificate_pem,
                        private_key_pem,
                        alpn: tls.alpn,
                    },
                    host.clone(),
                    sink.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                services.push(Box::new(inbound));
            }
            CompiledInboundKind::Transparent(config) => {
                let provider = transparent_proxy_provider()?;
                let inbound = TransparentProxyInbound::new(
                    inbound.id,
                    config.listen,
                    provider,
                    sink.clone(),
                    RuntimeTransparentInboundConfig {
                        mode: config.mode,
                        mark: config.mark,
                    },
                )
                .with_observability(observability.clone());
                services.push(Box::new(inbound));
            }
            CompiledInboundKind::Tun(config) => {
                let (packet_devices, network_control) = tun_platform_capabilities()?;
                let mtu = config.mtu.unwrap_or(1500) as usize;
                let stack = rustbox_stack::PacketFlowStack::new(inbound.id)
                    .with_mtu(mtu)
                    .with_observability(observability.clone());
                let dns_servers = config
                    .dns_hijack
                    .iter()
                    .map(|target| match target.endpoint.host {
                        Host::Ip(ip) => Ok(ip),
                        Host::Domain(_) => Err(ComposeError::Config(ConfigError::new(
                            "TUN dns_hijack endpoints must use literal IP addresses",
                        ))),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let platform_proxy = if config.platform_http_proxy {
                    Some(rustbox_kernel::PlatformProxyConfig {
                        listen: platform_proxy_listen.clone().ok_or_else(|| {
                            ComposeError::Config(ConfigError::new(
                                "TUN platform_http_proxy requires a mixed or http-connect inbound",
                            ))
                        })?,
                        bypass: vec!["<local>".to_string()],
                    })
                } else {
                    None
                };
                let inbound = TunInbound::new(
                    inbound.id,
                    packet_devices,
                    network_control,
                    Box::new(stack),
                    sink.clone(),
                    RuntimeTunInboundConfig {
                        interface_name: config.interface_name,
                        addresses: config.addresses,
                        mtu: config.mtu,
                        route_mode: config.route_mode,
                        dns_mode: config.dns_mode,
                        auto_route: config.auto_route,
                        strict_route: config.strict_route,
                        route_includes: config.route_includes,
                        route_excludes: config.route_excludes,
                        dns_servers,
                        platform_proxy,
                        platform_http_proxy: config.platform_http_proxy,
                        auto_redirect: config.auto_redirect,
                    },
                )
                .with_observability(observability.clone());
                services.push(Box::new(inbound));
            }
        }
    }

    Ok(services)
}
