use crate::{
    ComposeError, RuntimeCapabilities,
    dns_hijack::DnsHijackOutbound,
    routing::{RuntimeRouter, route_table},
};
use base64::Engine as _;
use rustbox_config::{
    CompiledConfig, CompiledOutboundKind, ConfigError, MultiplexConfig, OutboundTlsConfig,
    V2RayTransportConfig,
};
use rustbox_control::OutboundGroupRegistry;
use rustbox_dns_core::{DnsName, DnsQuery, DnsRecordType, DnsResponse, DnsSubsystem, ReverseDns};
use rustbox_inspect::{FlowEnricher, ProtocolSniffer, SniffConfig};
use rustbox_kernel::Engine;
use rustbox_kernel::{
    BoxFuture, Dialer, DomainResolver, NetError, NetworkProvider, NetworkProviderPurpose,
    ObservabilitySink, Outbound, RouteResolver, TaskScope,
};
use rustbox_outbound_anytls::{AnyTlsOutbound, AnyTlsTlsConfig};
use rustbox_outbound_direct::DirectOutbound;
use rustbox_outbound_http::{HttpProxyCredentials, HttpProxyOutbound};
use rustbox_outbound_hysteria2::{Hysteria2Config, Hysteria2Outbound};
use rustbox_outbound_mux::MuxOutbound;
use rustbox_outbound_naive::NaiveOutbound;
use rustbox_outbound_shadowsocks::ShadowsocksOutbound;
use rustbox_outbound_shadowtls::ShadowTlsOutbound;
use rustbox_outbound_socks5::{Socks5Credentials, Socks5Outbound};
use rustbox_outbound_trojan::{TrojanOutbound, TrojanTlsConfig};
use rustbox_outbound_tuic::{TuicConfig, TuicOutbound};
use rustbox_outbound_vless::{VlessOutbound, VlessTlsConfig};
use rustbox_outbound_vmess::{VmessOutbound, VmessTlsConfig};
use rustbox_outbound_wireguard::{
    WireGuardConfig as RuntimeWireGuardConfig, WireGuardOutbound,
    WireGuardPeerConfig as RuntimeWireGuardPeerConfig,
};
use rustbox_route::ResolveStrategy;
use rustbox_transport::{
    H2TunnelPool, LayeredTransport, MuxCoolConfig, MuxCoolPool, RealityLayerConfig,
    ShadowTlsTransport, StreamTransport, TcpTransport, TlsLayerConfig,
    V2RayTransportConfig as RuntimeTransportConfig,
};
use rustbox_types::{Host, IpAddress};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

type ComposedEngine = (
    Arc<Engine<FlowEnricher>>,
    Arc<OutboundGroupRegistry>,
    rustbox_route::RuleSetStore,
);

pub(crate) fn compose_engine(
    compiled: &CompiledConfig,
    capabilities: &RuntimeCapabilities,
    observability: &Arc<dyn ObservabilitySink>,
    dns: Option<Arc<DnsSubsystem>>,
    reverse_dns: Option<Arc<ReverseDns>>,
    session_tasks: &TaskScope,
) -> Result<ComposedEngine, ComposeError> {
    let groups = Arc::new(OutboundGroupRegistry::from_compiled(compiled));
    let table = route_table(compiled);
    let rule_sets = table.rule_set_store();
    let router = RuntimeRouter::new(table, groups.clone());
    let sniffer = reverse_dns.map_or_else(ProtocolSniffer::default, |reverse| {
        ProtocolSniffer::with_reverse_dns(SniffConfig::default(), reverse)
    });
    let enricher = FlowEnricher::new(sniffer, capabilities.process_lookup.clone())
        .with_network_lookup(capabilities.network_metadata.clone());
    let mut base_builder = Engine::builder(Box::new(router)).observability(observability.clone());
    if let Some(dns) = &dns {
        base_builder = base_builder.route_resolver(Arc::new(RouteDnsResolver { dns: dns.clone() }));
        base_builder = base_builder
            .register_hijacker(
                rustbox_types::dns_hijack_service_id(),
                Arc::new(DnsHijackOutbound::new(dns.clone(), session_tasks.clone())),
            )
            .map_err(ComposeError::Engine)?;
    }
    let mut builder = base_builder.with_enricher(enricher);

    let mut runtime_outbounds: HashMap<_, Arc<dyn Outbound>> = HashMap::new();
    for outbound in topological_outbounds(compiled)? {
        let network: Arc<dyn NetworkProvider> = match outbound.dial.detour {
            Some(detour) => Arc::new(Dialer::detour(
                runtime_outbounds.get(&detour).cloned().ok_or_else(|| {
                    ComposeError::Config(ConfigError::new(format!(
                        "detour outbound {detour} was not composed"
                    )))
                })?,
            )),
            None => {
                let resolver = if let Some(server) = &outbound.dial.domain_resolver {
                    let dns = dns.clone().ok_or_else(|| {
                        ComposeError::Config(ConfigError::new(
                            "domain_resolver requires a configured DNS subsystem",
                        ))
                    })?;
                    Some(Arc::new(DialDomainResolver {
                        dns,
                        server: server.clone(),
                    }) as Arc<dyn DomainResolver>)
                } else {
                    None
                };
                capabilities.network.create(
                    NetworkProviderPurpose::Outbound,
                    outbound.dial.options.clone(),
                    resolver,
                )
            }
        };
        match &outbound.kind {
            CompiledOutboundKind::Direct => {
                let runtime: Arc<dyn Outbound> = Arc::new(
                    DirectOutbound::new(outbound.id, network.clone())
                        .with_observability(observability.clone()),
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Socks5 {
                server,
                username,
                password,
            } => {
                let mut runtime_outbound =
                    Socks5Outbound::new(outbound.id, server.clone(), network.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                    runtime_outbound =
                        runtime_outbound.with_credentials(Socks5Credentials { username, password });
                }
                let runtime: Arc<dyn Outbound> = Arc::new(runtime_outbound);
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
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
                    HttpProxyOutbound::new(outbound.id, server.clone(), network.clone())
                        .with_observability(observability.clone());
                if let (Some(username), Some(password)) = (username.clone(), password.clone()) {
                    runtime_outbound = runtime_outbound
                        .with_credentials(HttpProxyCredentials { username, password });
                }
                let runtime: Arc<dyn Outbound> = Arc::new(runtime_outbound);
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Shadowsocks {
                server,
                method,
                password,
            } => {
                let id = outbound.id;
                let multiplex = outbound.dial.multiplex.as_ref();
                let runtime_outbound = ShadowsocksOutbound::new(
                    outbound.id,
                    server.clone(),
                    method,
                    password,
                    network.clone(),
                )
                .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                .with_observability(observability.clone());
                let runtime: Arc<dyn Outbound> =
                    apply_multiplex(Arc::new(runtime_outbound), id, multiplex, session_tasks);
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(id, runtime);
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
                let tls = tls.as_ref();
                let mut runtime_outbound = VmessOutbound::new(
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
                    network.clone(),
                    session_tasks.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                if let Some(transport) =
                    compose_transport(server, tls, transport.as_ref(), false, network.clone())?
                {
                    runtime_outbound = runtime_outbound.with_transport(transport);
                }
                let runtime: Arc<dyn Outbound> = apply_multiplex(
                    Arc::new(runtime_outbound),
                    outbound.id,
                    outbound.dial.multiplex.as_ref(),
                    session_tasks,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Vless {
                server,
                uuid,
                flow,
                tls,
                transport,
            } => {
                let tls = tls.as_ref();
                let mut runtime_outbound = VlessOutbound::new(
                    outbound.id,
                    server.clone(),
                    uuid,
                    flow.as_deref(),
                    VlessTlsConfig {
                        enabled: tls.is_some_and(|value| value.enabled),
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    network.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                if let Some(transport) =
                    compose_transport(server, tls, transport.as_ref(), false, network.clone())?
                {
                    runtime_outbound = runtime_outbound.with_transport(transport);
                }
                let runtime: Arc<dyn Outbound> = apply_multiplex(
                    Arc::new(runtime_outbound),
                    outbound.id,
                    outbound.dial.multiplex.as_ref(),
                    session_tasks,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Trojan {
                server,
                password,
                tls,
                transport,
            } => {
                let tls = tls.as_ref();
                let mut runtime_outbound = TrojanOutbound::new(
                    outbound.id,
                    server.clone(),
                    password,
                    TrojanTlsConfig {
                        server_name: tls.and_then(|value| value.server_name.clone()),
                        insecure: tls.is_some_and(|value| value.insecure),
                        alpn: tls.map(|value| value.alpn.clone()).unwrap_or_default(),
                    },
                    network.clone(),
                )
                .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?;
                if let Some(transport) =
                    compose_transport(server, tls, transport.as_ref(), true, network.clone())?
                {
                    runtime_outbound = runtime_outbound.with_transport(transport);
                }
                let runtime: Arc<dyn Outbound> = apply_multiplex(
                    Arc::new(runtime_outbound),
                    outbound.id,
                    outbound.dial.multiplex.as_ref(),
                    session_tasks,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
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
                    network.clone(),
                )
                .map_err(|err| ComposeError::Config(ConfigError::new(err.message)))?
                .with_observability(observability.clone());
                let runtime: Arc<dyn Outbound> = Arc::new(runtime_outbound);
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Hysteria2 {
                server,
                password,
                server_name,
                insecure,
                up_mbps,
                down_mbps,
                obfs_password,
                hop_ports,
                hop_interval,
                pin_sha256,
                ca_pem,
                fast_open,
            } => {
                let runtime: Arc<dyn Outbound> = Arc::new(
                    Hysteria2Outbound::new(
                        outbound.id,
                        Hysteria2Config {
                            server: server.clone(),
                            password: password.clone(),
                            server_name: server_name.clone(),
                            insecure: *insecure,
                            up_mbps: *up_mbps,
                            down_mbps: *down_mbps,
                            obfs_password: obfs_password.clone(),
                            hop_ports: hop_ports.clone(),
                            hop_interval_seconds: hop_interval.map(|value| value.as_secs()),
                            pin_sha256: pin_sha256.clone(),
                            ca_pem: ca_pem.clone(),
                            fast_open: *fast_open,
                        },
                        session_tasks.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Naive {
                server,
                username,
                password,
                tls,
                headers,
            } => {
                let mut tls_config = compose_tls_config(
                    tls.as_ref().ok_or_else(|| {
                        ComposeError::Config(ConfigError::new("Naive outbound requires TLS"))
                    })?,
                    &server.host.to_string(),
                )?;
                if tls_config.alpn.is_empty() {
                    tls_config.alpn.push("h2".into());
                } else if !tls_config.alpn.iter().any(|value| value == "h2") {
                    return Err(ComposeError::Config(ConfigError::new(
                        "Naive outbound TLS ALPN must include h2",
                    )));
                }
                let transport: Arc<dyn StreamTransport> = Arc::new(
                    LayeredTransport::new(network.clone(), Some(tls_config), None)
                        .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?,
                );
                let pool = H2TunnelPool::new(server.clone(), transport, session_tasks.clone());
                let runtime: Arc<dyn Outbound> = Arc::new(NaiveOutbound::new(
                    outbound.id,
                    pool,
                    username,
                    password,
                    headers
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                ));
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::Tuic {
                server,
                uuid,
                password,
                tls,
                heartbeat,
            } => {
                let tls = tls.as_ref().ok_or_else(|| {
                    ComposeError::Config(ConfigError::new("TUIC outbound requires TLS"))
                })?;
                let runtime: Arc<dyn Outbound> = Arc::new(
                    TuicOutbound::new(
                        outbound.id,
                        TuicConfig {
                            server: server.clone(),
                            uuid: uuid.clone(),
                            password: password.clone(),
                            tls: compose_tls_config(tls, &server.host.to_string())?,
                            heartbeat: *heartbeat,
                        },
                        session_tasks.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::WireGuard {
                addresses,
                private_key,
                listen_port,
                peers,
                mtu,
            } => {
                let runtime: Arc<dyn Outbound> = Arc::new(
                    WireGuardOutbound::new(
                        outbound.id,
                        RuntimeWireGuardConfig {
                            addresses: addresses.clone(),
                            private_key: private_key.clone(),
                            listen_port: *listen_port,
                            peers: peers
                                .iter()
                                .map(|peer| RuntimeWireGuardPeerConfig {
                                    server: peer.server.clone(),
                                    public_key: peer.public_key.clone(),
                                    pre_shared_key: peer.pre_shared_key.clone(),
                                    allowed_ips: peer.allowed_ips.clone(),
                                    persistent_keepalive: peer.persistent_keepalive,
                                    reserved: peer.reserved,
                                })
                                .collect(),
                            mtu: *mtu,
                        },
                        session_tasks.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?,
                );
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
            CompiledOutboundKind::ShadowTls {
                server,
                version: _,
                password,
                tls,
            } => {
                let tls = tls.as_ref().ok_or_else(|| {
                    ComposeError::Config(ConfigError::new("ShadowTLS outbound requires TLS"))
                })?;
                let underlay: Arc<dyn StreamTransport> =
                    Arc::new(TcpTransport::new(network.clone()));
                let transport: Arc<dyn StreamTransport> = Arc::new(
                    ShadowTlsTransport::new(
                        server.clone(),
                        password.clone(),
                        compose_tls_config(tls, &server.host.to_string())?,
                        underlay,
                        session_tasks.clone(),
                    )
                    .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))?,
                );
                let runtime: Arc<dyn Outbound> = Arc::new(ShadowTlsOutbound::new(
                    outbound.id,
                    transport,
                    network.clone(),
                ));
                builder = builder
                    .register_outbound_arc(runtime.clone())
                    .map_err(ComposeError::Engine)?;
                runtime_outbounds.insert(outbound.id, runtime);
            }
        }
    }

    let engine = Arc::new(builder.build().map_err(ComposeError::Engine)?);
    Ok((engine, groups, rule_sets))
}

fn apply_multiplex(
    runtime: Arc<dyn Outbound>,
    id: rustbox_types::OutboundId,
    config: Option<&MultiplexConfig>,
    tasks: &TaskScope,
) -> Arc<dyn Outbound> {
    let Some(config) = config.filter(|value| value.enabled) else {
        return runtime;
    };
    Arc::new(MuxOutbound::new(
        id,
        MuxCoolPool::new(
            runtime,
            MuxCoolConfig {
                max_streams: config.max_streams,
                max_connections: config.max_connections,
                buffer_size: config.buffer_size,
            },
            tasks.clone(),
        ),
    ))
}

fn compose_transport(
    server: &rustbox_types::Endpoint,
    tls: Option<&OutboundTlsConfig>,
    transport: Option<&V2RayTransportConfig>,
    force_tls: bool,
    network: Arc<dyn NetworkProvider>,
) -> Result<Option<Arc<dyn StreamTransport>>, ComposeError> {
    let transport = transport.filter(|value| !matches!(value, V2RayTransportConfig::Tcp));
    let needs_advanced_tls = tls.is_some_and(|tls| {
        tls.client_certificate_pem.is_some()
            || !tls.certificate_authorities_pem.is_empty()
            || !tls.certificate_public_key_sha256.is_empty()
            || tls.fingerprint.is_some()
            || tls.ech_config.is_some()
            || tls.reality.is_some()
    });
    if transport.is_none() && !needs_advanced_tls {
        return Ok(None);
    }
    let host = server.host.to_string();
    let runtime_transport = transport.map(|transport| match transport {
        V2RayTransportConfig::Tcp => unreachable!(),
        V2RayTransportConfig::WebSocket {
            path,
            host: configured_host,
            headers,
            max_early_data,
            early_data_header,
        } => RuntimeTransportConfig::WebSocket {
            path: path.clone(),
            host: Some(configured_host.clone().unwrap_or_else(|| host.clone())),
            headers: headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            max_early_data: *max_early_data,
            early_data_header: early_data_header.clone(),
        },
        V2RayTransportConfig::Http2 { path, hosts } => RuntimeTransportConfig::Http2 {
            path: path.clone(),
            hosts: hosts.clone(),
        },
        V2RayTransportConfig::Grpc {
            service_name,
            authority,
        } => RuntimeTransportConfig::Grpc {
            service_name: service_name.clone(),
            authority: authority.clone().unwrap_or_else(|| host.clone()),
        },
        V2RayTransportConfig::HttpUpgrade {
            path,
            host: configured_host,
            headers,
        } => RuntimeTransportConfig::HttpUpgrade {
            path: path.clone(),
            host: Some(configured_host.clone().unwrap_or_else(|| host.clone())),
            headers: headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        },
    });
    let tls_config = tls
        .map(|tls| compose_tls_config(tls, &host))
        .transpose()?
        .or_else(|| {
            force_tls.then(|| TlsLayerConfig {
                enabled: true,
                server_name: Some(host),
                ..TlsLayerConfig::default()
            })
        });
    LayeredTransport::new(network, tls_config, runtime_transport)
        .map(|transport| Some(Arc::new(transport) as Arc<dyn StreamTransport>))
        .map_err(|error| ComposeError::Config(ConfigError::new(error.message)))
}

fn compose_tls_config(
    tls: &OutboundTlsConfig,
    default_server_name: &str,
) -> Result<TlsLayerConfig, ComposeError> {
    if tls.client_certificate_pem.is_some() != tls.client_private_key_pem.is_some() {
        return Err(ComposeError::Config(ConfigError::new(
            "TLS client_certificate_pem and client_private_key_pem must be configured together",
        )));
    }
    let mut roots = Vec::new();
    for pem in &tls.certificate_authorities_pem {
        let certificates = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ComposeError::Config(ConfigError::new(format!(
                    "invalid TLS certificate authority PEM: {error}"
                )))
            })?;
        if certificates.is_empty() {
            return Err(ComposeError::Config(ConfigError::new(
                "TLS certificate authority PEM contains no certificates",
            )));
        }
        roots.extend(
            certificates
                .into_iter()
                .map(|certificate| certificate.to_vec()),
        );
    }
    let ech_config = tls.ech_config.as_deref().map(decode_base64).transpose()?;
    let public_key_pins = tls
        .certificate_public_key_sha256
        .iter()
        .map(|pin| {
            decode_base64(pin)?.try_into().map_err(|_| {
                ComposeError::Config(ConfigError::new(
                    "TLS certificate public-key SHA-256 pin must decode to 32 bytes",
                ))
            })
        })
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let reality = tls
        .reality
        .as_ref()
        .map(|reality| {
            let public_key = decode_base64(&reality.public_key)?;
            let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
                ComposeError::Config(ConfigError::new(
                    "REALITY public_key must decode to exactly 32 bytes",
                ))
            })?;
            let short = hex::decode(&reality.short_id).map_err(|error| {
                ComposeError::Config(ConfigError::new(format!(
                    "invalid REALITY short_id: {error}"
                )))
            })?;
            if short.len() > 8 {
                return Err(ComposeError::Config(ConfigError::new(
                    "REALITY short_id must not exceed eight bytes",
                )));
            }
            let mut short_id = [0_u8; 8];
            short_id[..short.len()].copy_from_slice(&short);
            Ok(RealityLayerConfig {
                public_key,
                short_id,
                support_x25519_mlkem768: reality.support_x25519_mlkem768,
            })
        })
        .transpose()?;
    if ech_config.is_some() && reality.is_some() {
        return Err(ComposeError::Config(ConfigError::new(
            "ECH and REALITY cannot be enabled on the same TLS layer",
        )));
    }
    Ok(TlsLayerConfig {
        enabled: tls.enabled,
        server_name: Some(
            tls.server_name
                .clone()
                .unwrap_or_else(|| default_server_name.to_string()),
        ),
        insecure: tls.insecure,
        alpn: tls.alpn.clone(),
        client_certificate_pem: tls
            .client_certificate_pem
            .as_ref()
            .map(|value| value.as_bytes().to_vec()),
        client_private_key_pem: tls
            .client_private_key_pem
            .as_ref()
            .map(|value| value.as_bytes().to_vec()),
        certificate_authorities_der: roots,
        fingerprint: tls.fingerprint.clone(),
        ech_config,
        reality,
        public_key_pins,
    })
}

fn decode_base64(value: &str) -> Result<Vec<u8>, ComposeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|error| {
            ComposeError::Config(ConfigError::new(format!(
                "invalid base64 encoded TLS value: {error}"
            )))
        })
}

struct DialDomainResolver {
    dns: Arc<DnsSubsystem>,
    server: String,
}

struct RouteDnsResolver {
    dns: Arc<DnsSubsystem>,
}

impl RouteResolver for RouteDnsResolver {
    fn resolve(
        &self,
        domain: String,
        server: Option<String>,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'_, Result<Vec<IpAddress>, NetError>> {
        Box::pin(async move {
            let name = DnsName::new(domain).map_err(|error| NetError::new(error.message))?;
            let query = |record_type| DnsQuery {
                name: name.clone(),
                record_type,
            };
            let resolve = |query| async {
                match &server {
                    Some(server) => self.dns.resolve_with_server(server, query).await,
                    None => self.dns.resolve(query).await,
                }
            };
            let (ipv4, ipv6) = tokio::join!(
                resolve(query(DnsRecordType::A)),
                resolve(query(DnsRecordType::Aaaa)),
            );
            let extract = |response: Result<DnsResponse, rustbox_dns_core::DnsError>| {
                response
                    .map(|response| {
                        response
                            .answers
                            .into_iter()
                            .filter_map(|answer| match answer.host {
                                Host::Ip(ip) => Some(ip),
                                Host::Domain(_) => None,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            let mut v4 = extract(ipv4);
            let mut v6 = extract(ipv6);
            let mut addresses = match strategy {
                ResolveStrategy::PreferIpv4 => {
                    v4.append(&mut v6);
                    v4
                }
                ResolveStrategy::PreferIpv6 => {
                    v6.append(&mut v4);
                    v6
                }
                ResolveStrategy::Ipv4Only => v4,
                ResolveStrategy::Ipv6Only => v6,
            };
            if addresses.is_empty() {
                return Err(NetError::new("route DNS resolution returned no addresses"));
            }
            addresses.dedup();
            Ok(addresses)
        })
    }
}

impl DomainResolver for DialDomainResolver {
    fn resolve(&self, domain: String) -> BoxFuture<'_, Result<Vec<IpAddress>, NetError>> {
        Box::pin(async move {
            let name = DnsName::new(domain).map_err(|error| NetError::new(error.message))?;
            let (ipv4, ipv6) = tokio::join!(
                self.dns.resolve_with_server(
                    &self.server,
                    DnsQuery {
                        name: name.clone(),
                        record_type: DnsRecordType::A
                    }
                ),
                self.dns.resolve_with_server(
                    &self.server,
                    DnsQuery {
                        name,
                        record_type: DnsRecordType::Aaaa
                    }
                ),
            );
            let mut addresses = Vec::new();
            for response in [ipv4, ipv6] {
                match response {
                    Ok(response) => {
                        addresses.extend(response.answers.into_iter().filter_map(|answer| {
                            match answer.host {
                                Host::Ip(ip) => Some(ip),
                                Host::Domain(_) => None,
                            }
                        }))
                    }
                    Err(error) if addresses.is_empty() => return Err(NetError::new(error.message)),
                    Err(_) => {}
                }
            }
            if addresses.is_empty() {
                return Err(NetError::new("domain resolver returned no addresses"));
            }
            Ok(addresses)
        })
    }
}

fn topological_outbounds(
    compiled: &CompiledConfig,
) -> Result<Vec<&rustbox_config::CompiledOutbound>, ComposeError> {
    let mut ordered = Vec::with_capacity(compiled.outbounds.len());
    let mut emitted = HashSet::new();
    while ordered.len() < compiled.outbounds.len() {
        let before = ordered.len();
        for outbound in &compiled.outbounds {
            if emitted.contains(&outbound.id) {
                continue;
            }
            if outbound.dial.detour.is_none_or(|id| emitted.contains(&id)) {
                emitted.insert(outbound.id);
                ordered.push(outbound);
            }
        }
        if before == ordered.len() {
            return Err(ComposeError::Config(ConfigError::new(
                "outbound detour graph contains a cycle",
            )));
        }
    }
    Ok(ordered)
}
