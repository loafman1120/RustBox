use crate::{ComposeError, routing::route_table};
use rustbox_config::{CompiledConfig, CompiledOutboundKind, ConfigError};
use rustbox_host_api::{ObservabilitySink, TokioHost};
use rustbox_kernel::Engine;
use rustbox_outbound_anytls::{AnyTlsOutbound, AnyTlsTlsConfig};
use rustbox_outbound_direct::DirectOutbound;
use rustbox_outbound_http::{HttpProxyCredentials, HttpProxyOutbound};
use rustbox_outbound_shadowsocks::ShadowsocksOutbound;
use rustbox_outbound_socks5::{Socks5Credentials, Socks5Outbound};
use rustbox_outbound_trojan::{TrojanOutbound, TrojanTlsConfig};
use rustbox_outbound_vless::{VlessOutbound, VlessTlsConfig};
use rustbox_outbound_vmess::{VmessOutbound, VmessTlsConfig};
use std::sync::Arc;

pub(crate) fn compose_engine(
    compiled: &CompiledConfig,
    host: &Arc<TokioHost>,
    observability: &Arc<dyn ObservabilitySink>,
) -> Result<Arc<Engine>, ComposeError> {
    let router = route_table(&compiled);
    let mut builder = Engine::builder(Box::new(router)).observability(observability.clone());

    for outbound in &compiled.outbounds {
        match &outbound.kind {
            CompiledOutboundKind::Direct => {
                builder = builder
                    .register_outbound(Box::new(
                        DirectOutbound::new(outbound.id, host.clone())
                            .with_observability(observability.clone()),
                    ))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Socks5 {
                server,
                username,
                password,
            } => {
                let mut runtime_outbound =
                    Socks5Outbound::new(outbound.id, server.clone(), host.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                    runtime_outbound =
                        runtime_outbound.with_credentials(Socks5Credentials { username, password });
                }
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Block => {
                // `block` outbound 在配置编译阶段会被路由规则转成 Reject 决策，
                // 组合根不需要为它注册会发起 I/O 的数据面组件。
            }
            CompiledOutboundKind::Http {
                server,
                username,
                password,
            } => {
                let mut runtime_outbound =
                    HttpProxyOutbound::new(outbound.id, server.clone(), host.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                    runtime_outbound = runtime_outbound
                        .with_credentials(HttpProxyCredentials { username, password });
                }
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Shadowsocks {
                server,
                method,
                password,
            } => {
                let outbound = ShadowsocksOutbound::new(
                    outbound.id,
                    server.clone(),
                    method,
                    password,
                    host.clone(),
                )
                .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                .with_observability(observability.clone());
                builder = builder
                    .register_outbound(Box::new(outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Selector { .. } | CompiledOutboundKind::UrlTest { .. } => {
                // Group outbounds are compiled to their current child route decision.
            }
            CompiledOutboundKind::Vmess {
                server,
                uuid,
                security,
                alter_id: _,
                tls,
                transport,
            } => {
                let _ = transport;
                let tls = tls.as_ref();
                let runtime_outbound = VmessOutbound::new(
                    outbound.id,
                    server.clone(),
                    uuid,
                    security.as_deref(),
                    VmessTlsConfig {
                        enabled: tls.is_some_and(|value| value.enabled),
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    host.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Vless {
                server,
                uuid,
                flow,
                tls,
                transport,
            } => {
                let _ = (flow, transport);
                let tls = tls.as_ref();
                let runtime_outbound = VlessOutbound::new(
                    outbound.id,
                    server.clone(),
                    uuid,
                    VlessTlsConfig {
                        enabled: tls.is_some_and(|value| value.enabled),
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    host.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::Trojan {
                server,
                password,
                tls,
                transport,
            } => {
                let _ = transport;
                let tls = tls.as_ref();
                let runtime_outbound = TrojanOutbound::new(
                    outbound.id,
                    server.clone(),
                    password,
                    TrojanTlsConfig {
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    host.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
            CompiledOutboundKind::AnyTls {
                server,
                password,
                tls,
            } => {
                let tls = tls.as_ref();
                let runtime_outbound = AnyTlsOutbound::new(
                    outbound.id,
                    server.clone(),
                    password,
                    AnyTlsTlsConfig {
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    host.clone(),
                )
                .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                .with_observability(observability.clone());
                builder = builder
                    .register_outbound(Box::new(runtime_outbound))
                    .map_err(ComposeError::Engine)?;
            }
        }
    }

    let engine = Arc::new(builder.build().map_err(ComposeError::Engine)?);
    Ok(engine)
}
