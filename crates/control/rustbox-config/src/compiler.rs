use super::*;

impl ConfigCompiler {
    pub fn parse(source: SourceConfig) -> Result<ParsedConfig, ConfigError> {
        Ok(ParsedConfig { source })
    }

    pub fn normalize(parsed: ParsedConfig) -> Result<NormalizedConfig, ConfigError> {
        Ok(NormalizedConfig {
            source: parsed.source,
        })
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

        for outbound in &normalized.source.outbounds {
            let logical_id = outbound.logical_id();
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
                        transport.as_deref(),
                    )?;
                    validate_tcp_transport("vmess", logical_id, transport.as_deref())?;
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
                        transport.as_deref(),
                    )?;
                    validate_tcp_transport("vless", logical_id, transport.as_deref())?;
                    if flow.as_deref().is_some_and(|value| !value.is_empty()) {
                        return Err(ConfigError::new(format!(
                            "vless outbound `{logical_id}` currently supports only plain VLESS without Vision flow"
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
                        transport.as_deref(),
                    )?;
                    validate_tcp_transport("trojan", logical_id, transport.as_deref())?;
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
            if rule_set.rules.is_empty() {
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
                let kind = match &inbound.kind {
                    InboundConfigKind::Mixed {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::Mixed {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::HttpConnect {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::HttpConnect {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::Socks5 {
                        listen,
                        username,
                        password,
                    } => CompiledInboundKind::Socks5 {
                        listen: listen.clone(),
                        username: username.clone(),
                        password: password.clone(),
                    },
                    InboundConfigKind::AnyTls {
                        listen,
                        password,
                        tls,
                    } => CompiledInboundKind::AnyTls {
                        listen: listen.clone(),
                        password: password.clone(),
                        tls: tls.clone(),
                    },
                    InboundConfigKind::Tun(config) => CompiledInboundKind::Tun(config.clone()),
                    InboundConfigKind::Transparent(config) => {
                        CompiledInboundKind::Transparent(config.clone())
                    }
                };
                Ok(CompiledInbound {
                    id: InboundId::new(non_zero_id(index)),
                    logical_id: inbound.id.clone(),
                    kind,
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
                    OutboundConfigKind::Selector { outbounds, default } => {
                        let selected = default.as_deref().unwrap_or_else(|| outbounds[0].as_str());
                        CompiledOutboundKind::Selector {
                            outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                            selected: source_outbound_route_decision(
                                selected,
                                &source_outbound_ids,
                                &source_outbounds,
                            )?,
                        }
                    }
                    OutboundConfigKind::UrlTest {
                        outbounds,
                        url,
                        interval_seconds,
                        tolerance_ms,
                    } => CompiledOutboundKind::UrlTest {
                        outbounds: compile_child_outbounds(outbounds, &source_outbound_ids)?,
                        selected: source_outbound_route_decision(
                            &outbounds[0],
                            &source_outbound_ids,
                            &source_outbounds,
                        )?,
                        url: url.clone(),
                        interval_seconds: *interval_seconds,
                        tolerance_ms: *tolerance_ms,
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
                        uuid: uuid.clone(),
                        security: security.clone(),
                        alter_id: *alter_id,
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::Vless {
                        server,
                        uuid,
                        flow,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Vless {
                        server: server.clone(),
                        uuid: uuid.clone(),
                        flow: flow.clone(),
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::Trojan {
                        server,
                        password,
                        tls,
                        transport,
                    } => CompiledOutboundKind::Trojan {
                        server: server.clone(),
                        password: password.clone(),
                        tls: tls.clone(),
                        transport: transport.clone(),
                    },
                    OutboundConfigKind::AnyTls {
                        server,
                        password,
                        tls,
                    } => CompiledOutboundKind::AnyTls {
                        server: server.clone(),
                        password: password.clone(),
                        tls: tls.clone(),
                    },
                };
                Ok(CompiledOutbound {
                    id: OutboundId::new(non_zero_id(index)),
                    logical_id: outbound.id.clone(),
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
                    decision: route_action_decision(action, &outbounds)?,
                }),
                RouteRuleConfig::Logical {
                    mode,
                    rules,
                    invert,
                    action,
                } => Ok(CompiledRouteRule::Rule {
                    matcher: CompiledRouteMatcher::Logical {
                        mode: mode.clone(),
                        rules: rules
                            .iter()
                            .map(|matcher| compile_route_matcher(matcher, &inbound_by_logical_id))
                            .collect::<Result<Vec<_>, _>>()?,
                        invert: *invert,
                    },
                    decision: route_action_decision(action, &outbounds)?,
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
            | CompiledOutboundKind::AnyTls { .. } => RouteDecision::Forward(self.id),
            CompiledOutboundKind::Block => RouteDecision::Reject(RejectReason::Policy),
            CompiledOutboundKind::Selector { selected, .. }
            | CompiledOutboundKind::UrlTest { selected, .. } => selected.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundKind {
    Concrete,
    Selector,
    UrlTest,
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
    transport: Option<&str>,
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
    transport: Option<&str>,
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
    transport: Option<&str>,
) -> Result<(), ConfigError> {
    if transport == Some("") {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` transport must not be empty"
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
    }
    Ok(())
}

fn validate_tcp_transport(
    protocol: &str,
    logical_id: &str,
    transport: Option<&str>,
) -> Result<(), ConfigError> {
    if transport.is_some_and(|value| value != "tcp") {
        return Err(ConfigError::new(format!(
            "{protocol} outbound `{logical_id}` currently supports only tcp transport"
        )));
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
        RouteActionConfig::Reject(_) => Ok(()),
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
        match &rule.action {
            DnsRuleAction::Server(server) if !server_ids.contains(server) => {
                return Err(ConfigError::new(format!(
                    "dns rule references unknown server `{server}`"
                )));
            }
            DnsRuleAction::Server(_) | DnsRuleAction::Reject | DnsRuleAction::FakeIp => {}
        }
        if matches!(rule.action, DnsRuleAction::FakeIp)
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
) -> Result<CompiledRouteMatcher, ConfigError> {
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

            Ok(CompiledRouteMatcher::Conditions(Box::new(
                CompiledRouteConditions {
                    inbounds,
                    networks: conditions.network.clone(),
                    domains: conditions.domain.clone(),
                    domain_suffixes: conditions.domain_suffix.clone(),
                    domain_keywords: conditions.domain_keyword.clone(),
                    domain_regexes: conditions.domain_regex.clone(),
                    ip_cidrs: conditions.ip_cidr.clone(),
                    source_ip_cidrs: conditions.source_ip_cidr.clone(),
                    ports: conditions.port.clone(),
                    source_ports: conditions.source_port.clone(),
                    rule_sets: conditions.rule_set.clone(),
                    invert: conditions.invert,
                },
            )))
        }
        RouteMatcherConfig::Logical {
            mode,
            rules,
            invert,
        } => Ok(CompiledRouteMatcher::Logical {
            mode: mode.clone(),
            rules: rules
                .iter()
                .map(|rule| compile_route_matcher(rule, inbound_by_logical_id))
                .collect::<Result<Vec<_>, _>>()?,
            invert: *invert,
        }),
    }
}

fn route_action_decision(
    action: &RouteActionConfig,
    outbounds: &[CompiledOutbound],
) -> Result<RouteDecision, ConfigError> {
    match action {
        RouteActionConfig::Outbound(outbound) => outbounds
            .iter()
            .find(|compiled| compiled.logical_id() == outbound)
            .ok_or_else(|| ConfigError::new(format!("unknown outbound `{outbound}`")))
            .map(CompiledOutbound::route_decision),
        RouteActionConfig::Reject(reason) => Ok(RouteDecision::Reject(reason.clone())),
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
