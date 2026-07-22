use super::*;
use base64::Engine as _;
use garde::Validate as _;

impl ConfigCompiler {
    pub fn parse(source: SourceConfig) -> Result<ParsedConfig, ConfigError> {
        Ok(ParsedConfig { source })
    }

    pub fn normalize(parsed: ParsedConfig) -> Result<NormalizedConfig, ConfigError> {
        let mut source = parsed.source;
        for inbound in &mut source.inbounds {
            if let InboundConfigKind::Tun(config) = &mut inbound.kind {
                config.normalize_derived_modes();
            }
        }
        Ok(NormalizedConfig { source })
    }

    pub fn validate(normalized: NormalizedConfig) -> Result<ValidatedConfig, ConfigError> {
        // 验证阶段只检查语义正确性，不创建 socket、任务或运行时对象。
        if normalized.source.inbounds.is_empty() {
            return Err(ConfigError::new("at least one inbound is required"));
        }
        if normalized.source.outbounds.is_empty() {
            return Err(ConfigError::new("at least one outbound is required"));
        }

        let mut outbound_ids = HashSet::new();
        let mut outbound_kinds = HashMap::new();
        for outbound in &normalized.source.outbounds {
            outbound.validate().map_err(|error| {
                ConfigError::new(format!("outbound `{}`: {error}", outbound.logical_id()))
            })?;
            let logical_id = outbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("outbound id must not be empty"));
            }
            if !outbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate outbound id `{logical_id}`"
                )));
            }
            outbound_kinds.insert(logical_id.to_string(), outbound.kind());
        }

        validate_dial_policies(&normalized.source, &outbound_ids, &outbound_kinds)?;

        for outbound in &normalized.source.outbounds {
            let logical_id = outbound.logical_id();
            if let Some(multiplex) = &outbound.dial.multiplex
                && multiplex.enabled
                && (multiplex.max_streams == 0
                    || multiplex.max_connections == 0
                    || multiplex.buffer_size < 4096)
            {
                return Err(ConfigError::new(format!(
                    "outbound `{logical_id}` multiplex requires max_streams/max_connections > 0 and buffer_size >= 4096"
                )));
            }
            match &outbound.kind {
                OutboundConfigKind::Socks5 {
                    username, password, ..
                } => validate_optional_credentials(
                    "socks5",
                    logical_id,
                    username.as_deref(),
                    password.as_deref(),
                )?,
                OutboundConfigKind::Http {
                    username, password, ..
                } => validate_optional_credentials(
                    "http",
                    logical_id,
                    username.as_deref(),
                    password.as_deref(),
                )?,
                OutboundConfigKind::Shadowsocks {
                    method, password, ..
                } => {
                    if method.is_empty() {
                        return Err(ConfigError::new(format!(
                            "shadowsocks outbound `{logical_id}` method must not be empty"
                        )));
                    }
                    if password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "shadowsocks outbound `{logical_id}` password must not be empty"
                        )));
                    }
                }
                OutboundConfigKind::Selector {
                    outbounds, default, ..
                } => validate_outbound_group(
                    "selector",
                    logical_id,
                    outbounds,
                    default.as_deref(),
                    &outbound_ids,
                    &outbound_kinds,
                )?,
                OutboundConfigKind::UrlTest {
                    outbounds,
                    url,
                    interval_seconds,
                    interrupt_exist_connections,
                    ..
                } => {
                    validate_outbound_group(
                        "urltest",
                        logical_id,
                        outbounds,
                        None,
                        &outbound_ids,
                        &outbound_kinds,
                    )?;
                    if url.is_empty() {
                        return Err(ConfigError::new(format!(
                            "urltest outbound `{logical_id}` url must not be empty"
                        )));
                    }
                    if *interval_seconds == 0 {
                        return Err(ConfigError::new(format!(
                            "urltest outbound `{logical_id}` interval_seconds must be greater than zero"
                        )));
                    }
                    if *interrupt_exist_connections {
                        return Err(ConfigError::new(format!(
                            "urltest outbound `{logical_id}` interrupt_exist_connections is not supported by the current session runtime"
                        )));
                    }
                }
                OutboundConfigKind::Vmess {
                    uuid,
                    security,
                    alter_id,
                    tls,
                    transport,
                    ..
                } => {
                    validate_proxy_protocol_config(
                        "vmess",
                        logical_id,
                        uuid,
                        security.as_deref(),
                        tls.as_ref(),
                        transport.as_ref(),
                    )?;
                    if alter_id.is_some_and(|value| value != 0) {
                        return Err(ConfigError::new(format!(
                            "vmess outbound `{logical_id}` supports only alter_id=0 AEAD"
                        )));
                    }
                }
                OutboundConfigKind::Vless {
                    uuid,
                    flow,
                    tls,
                    transport,
                    ..
                } => {
                    validate_proxy_protocol_config(
                        "vless",
                        logical_id,
                        uuid,
                        flow.as_deref(),
                        tls.as_ref(),
                        transport.as_ref(),
                    )?;
                    if flow
                        .as_deref()
                        .is_some_and(|value| !value.is_empty() && value != "xtls-rprx-vision")
                    {
                        return Err(ConfigError::new(format!(
                            "vless outbound `{logical_id}` has an unsupported flow"
                        )));
                    }
                    if flow.as_deref() == Some("xtls-rprx-vision")
                        && !tls.as_ref().is_some_and(|tls| tls.enabled)
                    {
                        return Err(ConfigError::new(format!(
                            "vless outbound `{logical_id}` Vision flow requires TLS or REALITY"
                        )));
                    }
                }
                OutboundConfigKind::Trojan {
                    password,
                    tls,
                    transport,
                    ..
                } => {
                    validate_secret_protocol_config(
                        "trojan",
                        logical_id,
                        password,
                        tls.as_ref(),
                        transport.as_ref(),
                    )?;
                    if tls.as_ref().is_some_and(|value| !value.enabled) {
                        return Err(ConfigError::new(format!(
                            "trojan outbound `{logical_id}` requires TLS"
                        )));
                    }
                }
                OutboundConfigKind::AnyTls { password, tls, .. } => {
                    validate_secret_protocol_config(
                        "anytls",
                        logical_id,
                        password,
                        tls.as_ref(),
                        None,
                    )?;
                    if tls.as_ref().is_some_and(|tls| !tls.enabled) {
                        return Err(ConfigError::new(format!(
                            "anytls outbound `{logical_id}` requires TLS"
                        )));
                    }
                }
                OutboundConfigKind::Hysteria2 {
                    password,
                    hop_interval,
                    ..
                } => {
                    if password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "hysteria2 outbound `{logical_id}` password must not be empty"
                        )));
                    }
                    if hop_interval.is_some_and(|interval| interval.is_zero()) {
                        return Err(ConfigError::new(format!(
                            "hysteria2 outbound `{logical_id}` hop_interval must be greater than zero"
                        )));
                    }
                }
                OutboundConfigKind::Naive {
                    username,
                    password,
                    tls,
                    ..
                } => {
                    if username.is_empty() || password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "naive outbound `{logical_id}` requires non-empty username and password"
                        )));
                    }
                    if !tls.as_ref().is_some_and(|tls| tls.enabled) {
                        return Err(ConfigError::new(format!(
                            "naive outbound `{logical_id}` requires TLS"
                        )));
                    }
                    validate_tls_and_transport("naive", logical_id, tls.as_ref(), None)?;
                }
                OutboundConfigKind::Tuic {
                    uuid,
                    password,
                    tls,
                    heartbeat,
                    ..
                } => {
                    if uuid.is_empty() || password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "tuic outbound `{logical_id}` requires non-empty uuid and password"
                        )));
                    }
                    if heartbeat.is_zero() {
                        return Err(ConfigError::new(format!(
                            "tuic outbound `{logical_id}` heartbeat must be greater than zero"
                        )));
                    }
                    if !tls.as_ref().is_some_and(|tls| tls.enabled) {
                        return Err(ConfigError::new(format!(
                            "tuic outbound `{logical_id}` requires TLS"
                        )));
                    }
                    validate_tls_and_transport("tuic", logical_id, tls.as_ref(), None)?;
                }
                OutboundConfigKind::WireGuard {
                    addresses,
                    private_key,
                    peers,
                    mtu,
                    ..
                } => {
                    if addresses.is_empty() || private_key.is_empty() || peers.is_empty() {
                        return Err(ConfigError::new(format!(
                            "wireguard outbound `{logical_id}` requires addresses, private_key and peers"
                        )));
                    }
                    if !(1280..=u16::MAX as usize).contains(mtu) {
                        return Err(ConfigError::new(format!(
                            "wireguard outbound `{logical_id}` MTU must be between 1280 and 65535"
                        )));
                    }
                    for peer in peers {
                        if peer.public_key.is_empty() || peer.allowed_ips.is_empty() {
                            return Err(ConfigError::new(format!(
                                "wireguard outbound `{logical_id}` peer requires public_key and allowed_ips"
                            )));
                        }
                        if peer
                            .persistent_keepalive
                            .is_some_and(|value| value.is_zero())
                        {
                            return Err(ConfigError::new(format!(
                                "wireguard outbound `{logical_id}` peer keepalive must be greater than zero"
                            )));
                        }
                    }
                }
                OutboundConfigKind::ShadowTls {
                    version,
                    password,
                    tls,
                    ..
                } => {
                    if *version != 3 {
                        return Err(ConfigError::new(format!(
                            "shadowtls outbound `{logical_id}` currently supports only version 3"
                        )));
                    }
                    if password.is_empty() || !tls.as_ref().is_some_and(|value| value.enabled) {
                        return Err(ConfigError::new(format!(
                            "shadowtls outbound `{logical_id}` requires password and TLS"
                        )));
                    }
                    validate_tls_and_transport("shadowtls", logical_id, tls.as_ref(), None)?;
                }
                OutboundConfigKind::Direct | OutboundConfigKind::Block => {}
            }
        }

        let mut inbound_ids = HashSet::new();
        for inbound in &normalized.source.inbounds {
            let logical_id = inbound.logical_id();
            if logical_id.is_empty() {
                return Err(ConfigError::new("inbound id must not be empty"));
            }
            if !inbound_ids.insert(logical_id.to_string()) {
                return Err(ConfigError::new(format!(
                    "duplicate inbound id `{logical_id}`"
                )));
            }
            match &inbound.kind {
                InboundConfigKind::Mixed {
                    username, password, ..
                } => validate_optional_credentials(
                    "mixed inbound",
                    logical_id,
                    username.as_deref(),
                    password.as_deref(),
                )?,
                InboundConfigKind::HttpConnect {
                    username, password, ..
                } => validate_optional_credentials(
                    "http inbound",
                    logical_id,
                    username.as_deref(),
                    password.as_deref(),
                )?,
                InboundConfigKind::Socks5 {
                    username, password, ..
                } => validate_optional_credentials(
                    "socks5 inbound",
                    logical_id,
                    username.as_deref(),
                    password.as_deref(),
                )?,
                InboundConfigKind::AnyTls { password, tls, .. } => {
                    if password.is_empty() {
                        return Err(ConfigError::new(format!(
                            "anytls inbound `{logical_id}` password must not be empty"
                        )));
                    }
                    if tls.certificate_path.is_empty() || tls.private_key_path.is_empty() {
                        return Err(ConfigError::new(format!(
                            "anytls inbound `{logical_id}` requires certificate_path and private_key_path"
                        )));
                    }
                }
                InboundConfigKind::Tun(config) => validate_tun_inbound(logical_id, config)?,
                InboundConfigKind::Transparent(config) => {
                    validate_transparent_inbound(logical_id, config)?
                }
            }
        }

        if let Some(dns) = &normalized.source.dns {
            validate_dns_config(dns, &outbound_ids)?;
        }

        let mut rule_set_ids = HashSet::new();
        for rule_set in &normalized.source.route_rule_sets {
            if rule_set.id.is_empty() {
                return Err(ConfigError::new("route rule-set id must not be empty"));
            }
            if !rule_set_ids.insert(rule_set.id.clone()) {
                return Err(ConfigError::new(format!(
                    "duplicate route rule-set id `{}`",
                    rule_set.id
                )));
            }
            if rule_set.rules.is_empty()
                && matches!(rule_set.source, RouteRuleSetSourceConfig::Inline)
            {
                return Err(ConfigError::new(format!(
                    "route rule-set `{}` must contain at least one rule",
                    rule_set.id
                )));
            }
        }

        for rule_set in &normalized.source.route_rule_sets {
            for matcher in &rule_set.rules {
                validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
            }
        }

        for rule in &normalized.source.routes {
            match rule {
                RouteRuleConfig::Default { outbound } => {
                    if !outbound_ids.contains(outbound.as_str()) {
                        return Err(ConfigError::new(format!(
                            "route references unknown outbound `{outbound}`"
                        )));
                    }
                }
                RouteRuleConfig::RejectDefault { .. } => {}
                RouteRuleConfig::Rule { matcher, action } => {
                    validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
                    validate_route_action(action, &outbound_ids)?;
                }
                RouteRuleConfig::Logical { rules, action, .. } => {
                    if rules.is_empty() {
                        return Err(ConfigError::new("logical route must include rules"));
                    }
                    for matcher in rules {
                        validate_route_matcher(matcher, &inbound_ids, &rule_set_ids)?;
                    }
                    validate_route_action(action, &outbound_ids)?;
                }
            }
        }

        Ok(ValidatedConfig {
            source: normalized.source,
        })
    }

    pub fn compile(validated: &ValidatedConfig) -> Result<CompiledConfig, ConfigError> {
        // 编译阶段把用户可读的逻辑 ID 映射为内核使用的稳定非零 ID。
        let inbounds = validated
            .source
            .inbounds
            .iter()
            .enumerate()
            .map(|(index, inbound)| {
                Ok(CompiledInbound {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: inbound.id.clone(),
                    kind: inbound.kind.clone(),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let source_outbound_ids = validated
            .source
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| {
                (
                    outbound.logical_id().to_string(),
                    OutboundId::new(non_zero_id(index)),
                )
            })
            .collect::<HashMap<_, _>>();

        let source_outbounds = validated
            .source
            .outbounds
            .iter()
            .map(|outbound| (outbound.logical_id().to_string(), outbound))
            .collect::<HashMap<_, _>>();

        let outbounds = validated
            .source
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| {
                let kind = match &outbound.kind {
                    OutboundConfigKind::Direct => CompiledOutboundKind::Direct,
                    OutboundConfigKind::Block => CompiledOutboundKind::Block,
                    OutboundConfigKind::Socks5 {
                        server,
                        username,
                        password,
                    } => CompiledOutboundKind::Socks5 {
                        server: server.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Http {
                        server,
                        username,
                        password,
                    } => CompiledOutboundKind::Http {
                        server: server.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Shadowsocks {
                        server,
                        method,
                        password,
                    } => CompiledOutboundKind::Shadowsocks {
                        server: server.clone(),
                        method: method.clone(),
                        password: password.clone(),
                    },
                    OutboundConfigKind::Selector {
                        outbounds,
                        default,
                        cache_path,
                    } => {
                        let selected = default.as_deref().unwrap_or_else(|| outbounds[0].as_str());
                        CompiledOutboundKind::Selector {
                            outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                            selected: source_outbound_route_decision(
                                selected,
                                &source_outbound_ids,
                                &source_outbounds,
                            )?,
                            cache_path: cache_path.clone(),
                        }
                    }
                    OutboundConfigKind::UrlTest {
                        outbounds,
                        url,
                        interval_seconds,
                        tolerance_ms,
                        timeout_seconds,
                        concurrency,
                        failure_threshold,
                        cache_path,
                        interrupt_exist_connections,
                    } => CompiledOutboundKind::UrlTest {
                        outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                        selected: source_outbound_route_decision(
                            &outbounds[0],
                            &source_outbound_ids,
                            &source_outbounds,
                        )?,
                        url: url::Url::parse(url).map_err(|error| {
                            ConfigError::new(format!(
                                "urltest outbound `{}` has invalid URL: {error}",
                                outbound.logical_id()
                            ))
                        })?,
                        interval_seconds: *interval_seconds,
                        tolerance_ms: *tolerance_ms,
                        timeout_seconds: *timeout_seconds,
                        concurrency: *concurrency,
                        failure_threshold: *failure_threshold,
                        cache_path: cache_path.clone(),
                        interrupt_exist_connections: *interrupt_exist_connections,
                    },
                    OutboundConfigKind::Vmess {
                        server,
                        uuid,
                        security,
                        alter_id,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Vmess {
                        server: server.clone(),
                        uuid: compile_uuid("vmess", outbound.logical_id(), uuid)?,
                        security: security.clone(),
                        alter_id: *alter_id,
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                        transport: compile_transport(transport.as_ref(), server),
                    },
                    OutboundConfigKind::Vless {
                        server,
                        uuid,
                        flow,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Vless {
                        server: server.clone(),
                        uuid: compile_uuid("vless", outbound.logical_id(), uuid)?,
                        flow: flow.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                        transport: compile_transport(transport.as_ref(), server),
                    },
                    OutboundConfigKind::Trojan {
                        server,
                        password,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Trojan {
                        server: server.clone(),
                        password: password.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                        transport: compile_transport(transport.as_ref(), server),
                    },
                    OutboundConfigKind::AnyTls {
                        server,
                        password,
                        tls,
                    } => CompiledOutboundKind::AnyTls {
                        server: server.clone(),
                        password: password.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                    },
                    OutboundConfigKind::Hysteria2 {
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
                    } => CompiledOutboundKind::Hysteria2 {
                        server: server.clone(),
                        password: password.clone(),
                        server_name: server_name.clone(),
                        insecure: *insecure,
                        up_mbps: *up_mbps,
                        down_mbps: *down_mbps,
                        obfs_password: obfs_password.clone(),
                        hop_ports: hop_ports.clone(),
                        hop_interval: *hop_interval,
                        pin_sha256: pin_sha256.clone(),
                        ca_pem: ca_pem.clone(),
                        fast_open: *fast_open,
                    },
                    OutboundConfigKind::Naive {
                        server,
                        username,
                        password,
                        tls,
                        headers,
                    } => CompiledOutboundKind::Naive {
                        server: server.clone(),
                        username: username.clone(),
                        password: password.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                        headers: headers.clone(),
                    },
                    OutboundConfigKind::Tuic {
                        server,
                        uuid,
                        password,
                        tls,
                        heartbeat,
                    } => CompiledOutboundKind::Tuic {
                        server: server.clone(),
                        uuid: compile_uuid("tuic", outbound.logical_id(), uuid)?,
                        password: password.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                        heartbeat: *heartbeat,
                    },
                    OutboundConfigKind::WireGuard {
                        addresses,
                        private_key,
                        listen_port,
                        peers,
                        mtu,
                    } => CompiledOutboundKind::WireGuard(rustbox_runtime_config::WireGuardPlan {
                        addresses: addresses.clone(),
                        private_key: compile_wireguard_key("private_key", private_key)?,
                        listen_port: *listen_port,
                        peers: peers
                            .iter()
                            .map(|peer| {
                                Ok(rustbox_runtime_config::WireGuardPeerPlan {
                                    server: peer.server.clone(),
                                    public_key: compile_wireguard_key(
                                        "peer public_key",
                                        &peer.public_key,
                                    )?,
                                    pre_shared_key: peer
                                        .pre_shared_key
                                        .as_deref()
                                        .map(|key| {
                                            compile_wireguard_key("peer pre_shared_key", key)
                                        })
                                        .transpose()?,
                                    allowed_ips: peer.allowed_ips.clone(),
                                    persistent_keepalive: peer.persistent_keepalive,
                                    reserved: peer.reserved,
                                })
                            })
                            .collect::<Result<Vec<_>, ConfigError>>()?,
                        mtu: *mtu,
                    }),
                    OutboundConfigKind::ShadowTls {
                        server,
                        version,
                        password,
                        tls,
                    } => CompiledOutboundKind::ShadowTls {
                        server: server.clone(),
                        version: *version,
                        password: password.clone(),
                        tls: compile_optional_tls(tls.as_ref(), server)?,
                    },
                };
                Ok(CompiledOutbound {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: outbound.id.clone(),
                    dial: compile_dial_policy(&outbound.dial, &source_outbound_ids),
                    kind,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let inbound_by_logical_id = inbounds
            .iter()
            .map(|inbound| (inbound.logical_id().to_string(), inbound.internal_id()))
            .collect::<HashMap<_, _>>();
        let outbound_by_logical_id = outbounds
            .iter()
            .map(|outbound| (outbound.logical_id().to_string(), outbound.internal_id()))
            .collect::<HashMap<_, _>>();
        let dns = validated
            .source
            .dns
            .as_ref()
            .map(|dns| compile_dns_config(dns, &outbound_by_logical_id))
            .transpose()?;

        let route_rule_sets = validated
            .source
            .route_rule_sets
            .iter()
            .map(|rule_set| {
                let rules = rule_set
                    .rules
                    .iter()
                    .map(|matcher| compile_route_matcher(matcher, &inbound_by_logical_id))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CompiledRouteRuleSet {
                    id: rule_set.id.clone(),
                    rules,
                    source: rule_set.source.clone(),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let route_rules = validated
            .source
            .routes
            .iter()
            .map(|rule| match rule {
                RouteRuleConfig::Default { outbound } => {
                    let outbound_id = outbounds
                        .iter()
                        .find(|compiled| compiled.logical_id() == outbound)
                        .ok_or_else(|| {
                            ConfigError::new(format!("unknown outbound `{outbound}`"))
                        })?;
                    Ok(CompiledRouteRule::Default(outbound_id.route_decision()))
                }
                RouteRuleConfig::RejectDefault { reason } => Ok(CompiledRouteRule::Default(
                    RouteDecision::Reject(reason.clone()),
                )),
                RouteRuleConfig::Rule { matcher, action } => Ok(CompiledRouteRule::Rule {
                    matcher: compile_route_matcher(matcher, &inbound_by_logical_id)?,
                    action: compile_route_action(action, &outbounds)?,
                }),
                RouteRuleConfig::Logical {
                    mode,
                    rules,
                    invert,
                    action,
                } => Ok(CompiledRouteRule::Rule {
                    matcher: rustbox_route::RouteMatcher::Logical {
                        mode: match mode {
                            LogicalModeConfig::And => rustbox_route::LogicalMode::And,
                            LogicalModeConfig::Or => rustbox_route::LogicalMode::Or,
                        },
                        rules: rules
                            .iter()
                            .map(|matcher| compile_route_matcher(matcher, &inbound_by_logical_id))
                            .collect::<Result<Vec<_>, _>>()?,
                        invert: *invert,
                    },
                    action: compile_route_action(action, &outbounds)?,
                }),
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        Ok(CompiledConfig {
            inbounds,
            outbounds,
            dns,
            route_rule_sets,
            route_rules,
        })
    }
}

impl InboundConfig {
    pub fn logical_id(&self) -> &str {
        &self.id
    }
}

impl CompiledInbound {
    fn logical_id(&self) -> &str {
        &self.logical_id
    }

    fn internal_id(&self) -> InboundId {
        self.id
    }
}

impl OutboundConfig {
    pub fn logical_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> OutboundKind {
        match &self.kind {
            OutboundConfigKind::Block => OutboundKind::Unavailable,
            OutboundConfigKind::Selector { .. } => OutboundKind::Selector,
            OutboundConfigKind::UrlTest { .. } => OutboundKind::UrlTest,
            _ => OutboundKind::Concrete,
        }
    }
}

impl CompiledOutbound {
    fn logical_id(&self) -> &str {
        &self.logical_id
    }

    fn internal_id(&self) -> OutboundId {
        self.id
    }

    fn route_decision(&self) -> RouteDecision {
        match &self.kind {
            CompiledOutboundKind::Direct
            | CompiledOutboundKind::Socks5 { .. }
            | CompiledOutboundKind::Http { .. }
            | CompiledOutboundKind::Shadowsocks { .. }
            | CompiledOutboundKind::Vmess { .. }
            | CompiledOutboundKind::Vless { .. }
            | CompiledOutboundKind::Trojan { .. }
            | CompiledOutboundKind::AnyTls { .. }
            | CompiledOutboundKind::Hysteria2 { .. }
            | CompiledOutboundKind::Naive { .. }
            | CompiledOutboundKind::Tuic { .. }
            | CompiledOutboundKind::WireGuard(..)
            | CompiledOutboundKind::ShadowTls { .. } => RouteDecision::Forward(self.id),
            CompiledOutboundKind::Block => RouteDecision::Reject(RejectReason::Policy),
            CompiledOutboundKind::Selector { .. } | CompiledOutboundKind::UrlTest { .. } => {
                RouteDecision::Forward(self.id)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundKind {
    Concrete,
    Unavailable,
    Selector,
    UrlTest,
}

fn validate_dial_policies(
    source: &SourceConfig,
    outbound_ids: &HashSet<String>,
    outbound_kinds: &HashMap<String, OutboundKind>,
) -> Result<(), ConfigError> {
    let policies = source
        .outbounds
        .iter()
        .map(|outbound| (outbound.id.as_str(), outbound.dial.detour.as_deref()))
        .collect::<HashMap<_, _>>();
    let dns_servers = source
        .dns
        .as_ref()
        .map(|dns| {
            dns.servers
                .iter()
                .map(|server| server.id.as_str())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    for outbound in &source.outbounds {
        let dial = &outbound.dial;
        if dial.disable_tcp_keep_alive
            && (dial.tcp_keep_alive.is_some() || dial.tcp_keep_alive_interval.is_some())
        {
            return Err(ConfigError::new(format!(
                "outbound `{}` cannot disable and configure TCP keepalive together",
                outbound.id
            )));
        }
        if matches!(dial.inet4_bind_address, Some(std::net::IpAddr::V6(_))) {
            return Err(ConfigError::new(format!(
                "outbound `{}` inet4_bind_address must be IPv4",
                outbound.id
            )));
        }
        if matches!(dial.inet6_bind_address, Some(std::net::IpAddr::V4(_))) {
            return Err(ConfigError::new(format!(
                "outbound `{}` inet6_bind_address must be IPv6",
                outbound.id
            )));
        }
        if let Some(resolver) = &dial.domain_resolver
            && !dns_servers.contains(resolver.as_str())
        {
            return Err(ConfigError::new(format!(
                "outbound `{}` references unknown domain_resolver `{resolver}`",
                outbound.id
            )));
        }
        if let Some(detour) = &dial.detour {
            if !outbound_ids.contains(detour) {
                return Err(ConfigError::new(format!(
                    "outbound `{}` references unknown detour `{detour}`",
                    outbound.id
                )));
            }
            if outbound_kinds.get(detour) != Some(&OutboundKind::Concrete) {
                return Err(ConfigError::new(format!(
                    "outbound `{}` detour `{detour}` must be a concrete outbound",
                    outbound.id
                )));
            }
        }

        let mut seen = HashSet::new();
        let mut cursor = Some(outbound.id.as_str());
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(ConfigError::new(format!(
                    "detour cycle detected from outbound `{}` at `{id}`",
                    outbound.id
                )));
            }
            cursor = policies.get(id).copied().flatten();
        }
    }
    Ok(())
}

fn compile_dial_policy(
    dial: &DialConfig,
    outbound_ids: &HashMap<String, OutboundId>,
) -> CompiledDialPolicy {
    let tcp_keepalive = if dial.disable_tcp_keep_alive {
        Some(None)
    } else {
        dial.tcp_keep_alive
            .or_else(|| {
                dial.tcp_keep_alive_interval
                    .map(|_| std::time::Duration::from_secs(300))
            })
            .map(|idle| {
                Some(rustbox_kernel::TcpKeepaliveOptions {
                    idle,
                    interval: dial.tcp_keep_alive_interval,
                })
            })
    };
    CompiledDialPolicy {
        detour: dial.detour.as_ref().map(|id| outbound_ids[id]),
        options: rustbox_kernel::DialOptions {
            bind_interface: dial.bind_interface.clone(),
            inet4_bind_address: dial.inet4_bind_address,
            inet6_bind_address: dial.inet6_bind_address,
            routing_mark: dial.routing_mark,
            connect_timeout: dial.connect_timeout,
            tcp_keepalive,
        },
        domain_resolver: dial.domain_resolver.clone(),
        multiplex: dial.multiplex.clone(),
    }
}

fn compile_uuid(protocol: &str, logical_id: &str, value: &str) -> Result<uuid::Uuid, ConfigError> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` has invalid UUID: {error}"
        ))
    })
}

fn compile_wireguard_key(
    field: &str,
    value: &str,
) -> Result<rustbox_runtime_config::WireGuardKey, ConfigError> {
    value
        .parse()
        .map_err(|error: String| ConfigError::new(format!("WireGuard {field}: {error}")))
}

fn compile_optional_tls(
    tls: Option<&OutboundTlsConfig>,
    server: &Endpoint,
) -> Result<Option<rustbox_runtime_config::TlsClientConfig>, ConfigError> {
    tls.map(|tls| compile_tls(tls, &server.host.to_string()))
        .transpose()
}

fn compile_tls(
    tls: &OutboundTlsConfig,
    default_server_name: &str,
) -> Result<rustbox_runtime_config::TlsClientConfig, ConfigError> {
    if let Some(certificate_pem) = &tls.client_certificate_pem {
        let certificates = rustls_pemfile::certs(&mut certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ConfigError::new(format!("invalid TLS client certificate: {error}"))
            })?;
        if certificates.is_empty() {
            return Err(ConfigError::new(
                "TLS client certificate PEM contains no certificates",
            ));
        }
    }
    if let Some(private_key_pem) = &tls.client_private_key_pem {
        let key =
            rustls_pemfile::private_key(&mut private_key_pem.as_bytes()).map_err(|error| {
                ConfigError::new(format!("invalid TLS client private key: {error}"))
            })?;
        if key.is_none() {
            return Err(ConfigError::new(
                "TLS client private-key PEM contains no private key",
            ));
        }
    }

    let mut roots = Vec::new();
    for pem in &tls.certificate_authorities_pem {
        let certificates = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ConfigError::new(format!("invalid TLS certificate authority PEM: {error}"))
            })?;
        if certificates.is_empty() {
            return Err(ConfigError::new(
                "TLS certificate authority PEM contains no certificates",
            ));
        }
        roots.extend(
            certificates
                .into_iter()
                .map(|certificate| certificate.to_vec()),
        );
    }

    let ech_config = tls
        .ech_config
        .as_deref()
        .map(|value| decode_base64("TLS ECH config", value))
        .transpose()?;
    let public_key_pins = tls
        .certificate_public_key_sha256
        .iter()
        .map(|pin| {
            decode_base64("TLS certificate public-key pin", pin)?
                .try_into()
                .map_err(|_| {
                    ConfigError::new(
                        "TLS certificate public-key pin must decode to exactly 32 bytes",
                    )
                })
        })
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let reality = tls
        .reality
        .as_ref()
        .map(|reality| {
            let public_key: [u8; 32] = decode_base64("REALITY public_key", &reality.public_key)?
                .try_into()
                .map_err(|_| {
                    ConfigError::new("REALITY public_key must decode to exactly 32 bytes")
                })?;
            let short = hex::decode(&reality.short_id)
                .map_err(|error| ConfigError::new(format!("invalid REALITY short_id: {error}")))?;
            if short.len() > 8 {
                return Err(ConfigError::new(
                    "REALITY short_id must not exceed eight bytes",
                ));
            }
            let mut short_id = [0_u8; 8];
            short_id[..short.len()].copy_from_slice(&short);
            Ok(rustbox_runtime_config::RealityConfig {
                public_key,
                short_id,
                support_x25519_mlkem768: reality.support_x25519_mlkem768,
            })
        })
        .transpose()?;

    Ok(rustbox_runtime_config::TlsClientConfig {
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

fn compile_transport(
    transport: Option<&V2RayTransportConfig>,
    server: &Endpoint,
) -> Option<rustbox_runtime_config::V2RayTransportPlan> {
    let host = server.host.to_string();
    transport.and_then(|transport| match transport {
        V2RayTransportConfig::Tcp => None,
        V2RayTransportConfig::WebSocket {
            path,
            host: configured_host,
            headers,
            max_early_data,
            early_data_header,
        } => Some(rustbox_runtime_config::V2RayTransportPlan::WebSocket {
            path: path.clone(),
            host: Some(configured_host.clone().unwrap_or(host)),
            headers: headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            max_early_data: *max_early_data,
            early_data_header: early_data_header.clone(),
        }),
        V2RayTransportConfig::Http2 { path, hosts } => {
            Some(rustbox_runtime_config::V2RayTransportPlan::Http2 {
                path: path.clone(),
                hosts: hosts.clone(),
            })
        }
        V2RayTransportConfig::Grpc {
            service_name,
            authority,
        } => Some(rustbox_runtime_config::V2RayTransportPlan::Grpc {
            service_name: service_name.clone(),
            authority: authority.clone().unwrap_or(host),
        }),
        V2RayTransportConfig::HttpUpgrade {
            path,
            host: configured_host,
            headers,
        } => Some(rustbox_runtime_config::V2RayTransportPlan::HttpUpgrade {
            path: path.clone(),
            host: Some(configured_host.clone().unwrap_or(host)),
            headers: headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }),
    })
}

fn decode_base64(field: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|error| ConfigError::new(format!("invalid base64 encoded {field}: {error}")))
}

fn validate_optional_credentials(
    protocol: &str,
    logical_id: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), ConfigError> {
    // 代理认证字段成对出现，避免运行时猜测“空用户名”或“空密码”的含义。
    if username.is_some() != password.is_some() {
        return Err(ConfigError::new(format!(
            "{protocol} `{logical_id}` must set username and password together"
        )));
    }
    if username == Some("") || password == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} `{logical_id}` credentials must not be empty"
        )));
    }
    Ok(())
}

fn validate_tun_inbound(logical_id: &str, config: &TunInboundConfig) -> Result<(), ConfigError> {
    if config.addresses.is_empty() {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` must include at least one address"
        )));
    }
    if let Some(mtu) = config.mtu
        && mtu < 1280
    {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` mtu must be at least 1280"
        )));
    }
    if config.strict_route && !config.auto_route {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` strict_route requires auto_route"
        )));
    }
    if config.strict_route && config.dns_hijack.is_empty() {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` strict_route requires a literal-IP dns_hijack endpoint"
        )));
    }
    if config.auto_redirect && !config.auto_route {
        return Err(ConfigError::new(format!(
            "tun inbound `{logical_id}` auto_redirect requires auto_route"
        )));
    }
    Ok(())
}

fn validate_transparent_inbound(
    logical_id: &str,
    config: &TransparentInboundConfig,
) -> Result<(), ConfigError> {
    if config.network != TransparentNetwork::Tcp {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` currently supports tcp only"
        )));
    }
    if config.mode != TransparentRedirectMode::Redirect {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` currently supports redirect mode only"
        )));
    }
    if config.auto_rules {
        return Err(ConfigError::new(format!(
            "transparent inbound `{logical_id}` auto_rules are not implemented; set auto_rules = false and install platform redirect rules externally"
        )));
    }
    Ok(())
}

fn validate_outbound_group(
    protocol: &str,
    logical_id: &str,
    outbounds: &[String],
    default: Option<&str>,
    outbound_ids: &HashSet<String>,
    outbound_kinds: &HashMap<String, OutboundKind>,
) -> Result<(), ConfigError> {
    if outbounds.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` must include at least one outbound"
        )));
    }
    let mut seen = HashSet::new();
    for child in outbounds {
        if child.is_empty() {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` child outbound id must not be empty"
            )));
        }
        if child == logical_id {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` must not reference itself"
            )));
        }
        if !seen.insert(child) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` references duplicate child `{child}`"
            )));
        }
        if !outbound_ids.contains(child.as_str()) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` references unknown outbound `{child}`"
            )));
        }
        if outbound_kinds
            .get(child)
            .is_some_and(|kind| *kind != OutboundKind::Concrete)
        {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` must not reference group outbound `{child}`"
            )));
        }
    }
    if let Some(default) = default
        && !outbounds.iter().any(|child| child == default)
    {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` default `{default}` is not in outbounds"
        )));
    }
    Ok(())
}

fn validate_proxy_protocol_config(
    protocol: &str,
    logical_id: &str,
    uuid: &str,
    option: Option<&str>,
    tls: Option<&OutboundTlsConfig>,
    transport: Option<&V2RayTransportConfig>,
) -> Result<(), ConfigError> {
    if uuid.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` uuid must not be empty"
        )));
    }
    if option == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` optional protocol field must not be empty"
        )));
    }
    validate_tls_and_transport(protocol, logical_id, tls, transport)
}

fn validate_secret_protocol_config(
    protocol: &str,
    logical_id: &str,
    password: &str,
    tls: Option<&OutboundTlsConfig>,
    transport: Option<&V2RayTransportConfig>,
) -> Result<(), ConfigError> {
    if password.is_empty() {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` password must not be empty"
        )));
    }
    validate_tls_and_transport(protocol, logical_id, tls, transport)
}

fn validate_tls_and_transport(
    protocol: &str,
    logical_id: &str,
    tls: Option<&OutboundTlsConfig>,
    transport: Option<&V2RayTransportConfig>,
) -> Result<(), ConfigError> {
    if let Some(V2RayTransportConfig::Http2 { hosts, .. }) = transport
        && hosts.is_empty()
    {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` HTTP/2 transport requires at least one host"
        )));
    }
    if let Some(tls) = tls {
        if tls.server_name.as_deref() == Some("") {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` tls.server_name must not be empty"
            )));
        }
        if tls.alpn.iter().any(String::is_empty) {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` tls.alpn must not contain empty values"
            )));
        }
        if tls.client_certificate_pem.is_some() != tls.client_private_key_pem.is_some() {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` TLS client certificate and private key must be configured together"
            )));
        }
        if tls.ech_config.is_some() && tls.reality.is_some() {
            return Err(ConfigError::new(format!(
                "{protocol} outbound `{logical_id}` cannot combine ECH and REALITY"
            )));
        }
        if let Some(reality) = &tls.reality {
            if reality.public_key.is_empty() {
                return Err(ConfigError::new(format!(
                    "{protocol} outbound `{logical_id}` REALITY public_key must not be empty"
                )));
            }
            if reality.short_id.len() > 16 || reality.short_id.len() % 2 != 0 {
                return Err(ConfigError::new(format!(
                    "{protocol} outbound `{logical_id}` REALITY short_id must be even-length hex of at most eight bytes"
                )));
            }
        }
    }
    Ok(())
}

fn validate_route_action(
    action: &RouteActionConfig,
    outbound_ids: &HashSet<String>,
) -> Result<(), ConfigError> {
    match action {
        RouteActionConfig::Outbound(outbound) => {
            if outbound_ids.contains(outbound.as_str()) {
                Ok(())
            } else {
                Err(ConfigError::new(format!(
                    "route references unknown outbound `{outbound}`"
                )))
            }
        }
        RouteActionConfig::Reject(_)
        | RouteActionConfig::HijackDns
        | RouteActionConfig::Options(_) => Ok(()),
        RouteActionConfig::Resolve(resolve) => {
            if resolve.server.as_deref() == Some("") {
                Err(ConfigError::new("route resolve server must not be empty"))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_route_matcher(
    matcher: &RouteMatcherConfig,
    inbound_ids: &HashSet<String>,
    rule_set_ids: &HashSet<String>,
) -> Result<(), ConfigError> {
    match matcher {
        RouteMatcherConfig::Conditions(conditions) => {
            for inbound in &conditions.inbound {
                if !inbound_ids.contains(inbound.as_str()) {
                    return Err(ConfigError::new(format!(
                        "route references unknown inbound `{inbound}`"
                    )));
                }
            }
            for rule_set in &conditions.rule_set {
                if !rule_set_ids.contains(rule_set.as_str()) {
                    return Err(ConfigError::new(format!(
                        "route references unknown rule-set `{rule_set}`"
                    )));
                }
            }
            for pattern in &conditions.domain_regex {
                Regex::new(pattern).map_err(|err| {
                    ConfigError::new(format!("route domain_regex `{pattern}` is invalid: {err}"))
                })?;
            }
            Ok(())
        }
        RouteMatcherConfig::Logical { rules, .. } => {
            if rules.is_empty() {
                return Err(ConfigError::new("logical route matcher must include rules"));
            }
            for rule in rules {
                validate_route_matcher(rule, inbound_ids, rule_set_ids)?;
            }
            Ok(())
        }
    }
}

fn validate_dns_config(dns: &DnsConfig, outbound_ids: &HashSet<String>) -> Result<(), ConfigError> {
    if dns.servers.is_empty() {
        return Err(ConfigError::new(
            "dns.servers must contain at least one server",
        ));
    }
    let mut server_ids = HashSet::new();
    for server in &dns.servers {
        if server.id.is_empty() {
            return Err(ConfigError::new("dns server id must not be empty"));
        }
        if !server_ids.insert(server.id.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate dns server id `{}`",
                server.id
            )));
        }
        if let Some(outbound) = &server.outbound
            && !outbound_ids.contains(outbound.as_str())
        {
            return Err(ConfigError::new(format!(
                "dns server `{}` references unknown outbound `{outbound}`",
                server.id
            )));
        }
    }

    if let Some(final_server) = &dns.final_server
        && !server_ids.contains(final_server)
    {
        return Err(ConfigError::new(format!(
            "dns final_server references unknown server `{final_server}`"
        )));
    }

    for rule in &dns.rules {
        match rule {
            DnsRuleConfig::Server { server, .. } if !server_ids.contains(server) => {
                return Err(ConfigError::new(format!(
                    "dns rule references unknown server `{server}`"
                )));
            }
            DnsRuleConfig::Server { .. }
            | DnsRuleConfig::Reject { .. }
            | DnsRuleConfig::FakeIp { .. } => {}
        }
        if matches!(rule, DnsRuleConfig::FakeIp { .. })
            && !dns.fake_ip.as_ref().is_some_and(|fake_ip| fake_ip.enabled)
        {
            return Err(ConfigError::new(
                "dns rule selects fake-ip but dns.fake_ip is disabled",
            ));
        }
    }

    if dns.cache.min_ttl_seconds > dns.cache.max_ttl_seconds {
        return Err(ConfigError::new(
            "dns cache min_ttl_seconds must be <= max_ttl_seconds",
        ));
    }
    if let Some(fake_ip) = &dns.fake_ip
        && fake_ip.enabled
    {
        rustbox_dns_core::FakeIpAllocator::new(fake_ip.clone())
            .map_err(|err| ConfigError::new(err.message))?;
    }
    Ok(())
}

fn compile_dns_config(
    dns: &DnsConfig,
    outbound_by_logical_id: &HashMap<String, OutboundId>,
) -> Result<CompiledDnsConfig, ConfigError> {
    let final_server = dns
        .final_server
        .clone()
        .unwrap_or_else(|| dns.servers[0].id.clone());
    let servers = dns
        .servers
        .iter()
        .map(|server| {
            let outbound = server
                .outbound
                .as_ref()
                .map(|logical_id| {
                    outbound_by_logical_id
                        .get(logical_id)
                        .copied()
                        .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
                })
                .transpose()?;
            Ok(CompiledDnsServerConfig {
                id: server.id.clone(),
                protocol: server.protocol,
                endpoint: server.endpoint.clone(),
                outbound,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;

    Ok(CompiledDnsConfig {
        servers,
        rules: dns.rules.clone(),
        final_server,
        cache: dns.cache.clone(),
        fake_ip: dns.fake_ip.clone(),
        hijack: dns.hijack.clone(),
    })
}

fn compile_route_matcher(
    matcher: &RouteMatcherConfig,
    inbound_by_logical_id: &HashMap<String, InboundId>,
) -> Result<rustbox_route::RouteMatcher, ConfigError> {
    match matcher {
        RouteMatcherConfig::Conditions(conditions) => {
            let inbounds = conditions
                .inbound
                .iter()
                .map(|logical_id| {
                    inbound_by_logical_id
                        .get(logical_id)
                        .copied()
                        .ok_or_else(|| ConfigError::new(format!("unknown inbound `{logical_id}`")))
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(rustbox_route::RouteMatcher::Conditions(Box::new(
                rustbox_route::RouteConditions {
                    inbounds,
                    networks: conditions.network.clone(),
                    protocols: conditions.protocol.clone(),
                    domains: conditions.domain.clone(),
                    domain_suffixes: conditions.domain_suffix.clone(),
                    domain_keywords: conditions.domain_keyword.clone(),
                    domain_regexes: conditions.domain_regex.clone(),
                    ip_cidrs: conditions.ip_cidr.clone(),
                    source_ip_cidrs: conditions.source_ip_cidr.clone(),
                    ports: conditions.port.clone(),
                    source_ports: conditions.source_port.clone(),
                    rule_sets: conditions.rule_set.clone(),
                    process_names: conditions.process_name.clone(),
                    process_paths: conditions.process_path.clone(),
                    package_names: conditions.package_name.clone(),
                    user_ids: conditions.user_id.clone(),
                    user_names: conditions.user_name.clone(),
                    interfaces: conditions.interface.clone(),
                    wifi_ssids: conditions.wifi_ssid.clone(),
                    wifi_bssids: conditions.wifi_bssid.clone(),
                    network_types: conditions.network_type.clone(),
                    invert: conditions.invert,
                },
            )))
        }
        RouteMatcherConfig::Logical {
            mode,
            rules,
            invert,
        } => Ok(rustbox_route::RouteMatcher::Logical {
            mode: match mode {
                LogicalModeConfig::And => rustbox_route::LogicalMode::And,
                LogicalModeConfig::Or => rustbox_route::LogicalMode::Or,
            },
            rules: rules
                .iter()
                .map(|rule| compile_route_matcher(rule, inbound_by_logical_id))
                .collect::<Result<Vec<_>, _>>()?,
            invert: *invert,
        }),
    }
}

pub fn compile_headless_route_matcher(
    matcher: &RouteMatcherConfig,
) -> Result<rustbox_route::RouteMatcher, ConfigError> {
    compile_route_matcher(matcher, &HashMap::new())
}

fn compile_route_action(
    action: &RouteActionConfig,
    outbounds: &[CompiledOutbound],
) -> Result<RouteAction, ConfigError> {
    match action {
        RouteActionConfig::Outbound(outbound) => outbounds
            .iter()
            .find(|compiled| compiled.logical_id() == outbound)
            .ok_or_else(|| ConfigError::new(format!("unknown outbound `{outbound}`")))
            .map(CompiledOutbound::route_decision)
            .map(RouteAction::Final),
        RouteActionConfig::Reject(reason) => {
            Ok(RouteAction::Final(RouteDecision::Reject(reason.clone())))
        }
        RouteActionConfig::HijackDns => Ok(RouteAction::Final(RouteDecision::Hijack(
            rustbox_types::dns_hijack_service_id(),
        ))),
        RouteActionConfig::Options(options) => Ok(RouteAction::Options(RouteOptions {
            override_host: options.override_address.clone(),
            override_port: options.override_port,
            udp_timeout: options.udp_timeout,
            udp_connect: options.udp_connect,
            udp_disable_domain_unmapping: options.udp_disable_domain_unmapping,
        })),
        RouteActionConfig::Resolve(resolve) => Ok(RouteAction::Resolve(RouteResolve {
            server: resolve.server.clone(),
            strategy: resolve.strategy,
        })),
    }
}

fn compile_child_outbounds(
    outbounds: &[String],
    outbound_by_logical_id: &HashMap<String, OutboundId>,
) -> Result<Vec<OutboundId>, ConfigError> {
    outbounds
        .iter()
        .map(|logical_id| {
            outbound_by_logical_id
                .get(logical_id)
                .copied()
                .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
        })
        .collect()
}

fn source_outbound_route_decision(
    logical_id: &str,
    outbound_by_logical_id: &HashMap<String, OutboundId>,
    source_outbounds: &HashMap<String, &OutboundConfig>,
) -> Result<RouteDecision, ConfigError> {
    let outbound = source_outbounds
        .get(logical_id)
        .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))?;
    if matches!(&outbound.kind, OutboundConfigKind::Block) {
        Ok(RouteDecision::Reject(RejectReason::Policy))
    } else {
        outbound_by_logical_id
            .get(logical_id)
            .copied()
            .map(RouteDecision::Forward)
            .ok_or_else(|| ConfigError::new(format!("unknown outbound `{logical_id}`")))
    }
}

fn non_zero_id(index: usize) -> NonZeroU64 {
    NonZeroU64::new(index as u64 + 1).expect("index plus one is non-zero")
}
