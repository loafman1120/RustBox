//! Clash-compatible YAML document normalization.
//!
//! This module intentionally owns the compatibility model instead of leaking
//! Clash-shaped maps into the format-independent runtime configuration.

use rustbox_config::{
    DialConfig, InboundConfig, InboundConfigKind, OutboundConfig, OutboundConfigKind,
    OutboundTlsConfig, RouteActionConfig, RouteMatchConfig, RouteMatcherConfig, RouteRuleConfig,
    SourceConfig, V2RayTransportConfig,
};
use rustbox_types::{Endpoint, Host, IpCidr, Network, PortRange, RejectReason};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::{ConfigFileError, FileConfig};

/// Reads a Clash YAML file and normalizes it into the shared file result.
pub fn load_clash_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    let path = path.as_ref();
    let input = fs::read_to_string(path).map_err(|error| {
        ConfigFileError::new(format!(
            "failed to read config file `{}`: {error}",
            path.display()
        ))
    })?;
    parse_clash_str(&input)
}

/// Parses Clash YAML and normalizes supported fields into RustBox semantics.
pub fn parse_clash_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    let document: ClashDocument =
        serde_saphyr::from_str(input).map_err(ConfigFileError::parse_clash)?;
    Ok(FileConfig {
        source: document.into_source()?,
        observability: None,
    })
}

/// Reads a Clash YAML file and returns only the shared runtime model.
pub fn load_clash_source(path: impl AsRef<Path>) -> Result<SourceConfig, ConfigFileError> {
    load_clash_file(path).map(FileConfig::into_source)
}

/// Parses Clash YAML and returns only the shared runtime model.
pub fn parse_clash_source(input: &str) -> Result<SourceConfig, ConfigFileError> {
    parse_clash_str(input).map(FileConfig::into_source)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClashDocument {
    #[serde(rename = "mixed-port")]
    mixed_port: Option<u16>,
    port: Option<u16>,
    #[serde(rename = "socks-port")]
    socks_port: Option<u16>,
    #[serde(rename = "bind-address")]
    bind_address: Option<String>,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    authentication: Vec<String>,
    proxies: Vec<ClashProxy>,
    #[serde(rename = "proxy-groups")]
    proxy_groups: Vec<ClashProxyGroup>,
    rules: Vec<String>,
}

impl ClashDocument {
    fn into_source(self) -> Result<SourceConfig, ConfigFileError> {
        let authentication = parse_authentication(&self.authentication)?;
        let listen_host = parse_bind_address(self.bind_address.as_deref(), self.allow_lan)?;
        let mut inbounds = Vec::new();
        if let Some(port) = self.mixed_port {
            inbounds.push(InboundConfig {
                id: "clash-mixed".to_string(),
                kind: InboundConfigKind::Mixed {
                    listen: Endpoint::new(listen_host.clone(), port),
                    username: authentication.0.clone(),
                    password: authentication.1.clone(),
                },
            });
        }
        if let Some(port) = self.port {
            inbounds.push(InboundConfig {
                id: "clash-http".to_string(),
                kind: InboundConfigKind::HttpConnect {
                    listen: Endpoint::new(listen_host.clone(), port),
                    username: authentication.0.clone(),
                    password: authentication.1.clone(),
                },
            });
        }
        if let Some(port) = self.socks_port {
            inbounds.push(InboundConfig {
                id: "clash-socks".to_string(),
                kind: InboundConfigKind::Socks5 {
                    listen: Endpoint::new(listen_host, port),
                    username: authentication.0,
                    password: authentication.1,
                },
            });
        }

        let mut names = HashSet::new();
        let mut outbounds = vec![
            builtin_outbound("DIRECT", OutboundConfigKind::Direct),
            builtin_outbound("REJECT", OutboundConfigKind::Block),
        ];
        names.insert("DIRECT".to_string());
        names.insert("REJECT".to_string());
        for proxy in self.proxies {
            let outbound = proxy.into_outbound()?;
            ensure_unique_name(&mut names, &outbound.id)?;
            outbounds.push(outbound);
        }
        for group in self.proxy_groups {
            let outbound = group.into_outbound()?;
            ensure_unique_name(&mut names, &outbound.id)?;
            outbounds.push(outbound);
        }

        let mut routes = self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| parse_rule(index, rule))
            .collect::<Result<Vec<_>, _>>()?;
        if !routes.iter().any(is_default_rule) {
            routes.push(RouteRuleConfig::Default {
                outbound: "DIRECT".to_string(),
            });
        }

        Ok(SourceConfig {
            inbounds,
            outbounds,
            dns: None,
            route_rule_sets: Vec::new(),
            routes,
        })
    }
}

fn builtin_outbound(id: &str, kind: OutboundConfigKind) -> OutboundConfig {
    OutboundConfig {
        id: id.to_string(),
        dial: DialConfig::default(),
        kind,
    }
}

fn ensure_unique_name(names: &mut HashSet<String>, name: &str) -> Result<(), ConfigFileError> {
    if names.insert(name.to_string()) {
        Ok(())
    } else {
        Err(ConfigFileError::new(format!(
            "duplicate Clash proxy or group name `{name}`"
        )))
    }
}

fn parse_authentication(
    values: &[String],
) -> Result<(Option<String>, Option<String>), ConfigFileError> {
    match values {
        [] => Ok((None, None)),
        [value] => value
            .split_once(':')
            .map(|(username, password)| (Some(username.to_string()), Some(password.to_string())))
            .ok_or_else(|| {
                ConfigFileError::new("Clash authentication must use `username:password`")
            }),
        _ => Err(ConfigFileError::new(
            "multiple Clash authentication users are not supported by RustBox inbounds",
        )),
    }
}

fn parse_bind_address(value: Option<&str>, allow_lan: bool) -> Result<Host, ConfigFileError> {
    match value {
        Some("*") => Ok(Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
        Some(value) if value.eq_ignore_ascii_case("localhost") => {
            Ok(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        }
        Some(value) => value
            .parse::<IpAddr>()
            .map(Host::Ip)
            .map_err(|_| ConfigFileError::new(format!("invalid Clash bind-address `{value}`"))),
        None if allow_lan => Ok(Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
        None => Ok(Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
    }
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    cipher: Option<String>,
    uuid: Option<String>,
    #[serde(rename = "alterId")]
    alter_id: Option<u16>,
    tls: Option<bool>,
    servername: Option<String>,
    sni: Option<String>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    network: Option<String>,
    #[serde(rename = "ws-opts")]
    ws_opts: Option<ClashWebSocketOptions>,
    #[serde(rename = "h2-opts")]
    h2_opts: Option<ClashHttp2Options>,
    #[serde(rename = "grpc-opts")]
    grpc_opts: Option<ClashGrpcOptions>,
    flow: Option<String>,
    auth: Option<String>,
    up: Option<u64>,
    down: Option<u64>,
}

impl ClashProxy {
    fn into_outbound(self) -> Result<OutboundConfig, ConfigFileError> {
        let server = Endpoint::new(
            self.server.parse::<Host>().map_err(ConfigFileError::new)?,
            self.port,
        );
        let transport = self.transport()?;
        let server_name = self.servername.or(self.sni);
        let kind = match self.kind.to_ascii_lowercase().as_str() {
            "ss" => OutboundConfigKind::Shadowsocks {
                server,
                method: required(self.cipher, &self.name, "cipher")?,
                password: required(self.password, &self.name, "password")?,
            },
            "socks" | "socks5" => OutboundConfigKind::Socks5 {
                server,
                username: self.username,
                password: self.password,
            },
            "http" => OutboundConfigKind::Http {
                server,
                username: self.username,
                password: self.password,
            },
            "vmess" => OutboundConfigKind::Vmess {
                server,
                uuid: required(self.uuid, &self.name, "uuid")?,
                security: self.cipher,
                alter_id: self.alter_id,
                tls: self
                    .tls
                    .unwrap_or(false)
                    .then(|| tls_config(server_name, self.skip_cert_verify)),
                transport,
            },
            "vless" => OutboundConfigKind::Vless {
                server,
                uuid: required(self.uuid, &self.name, "uuid")?,
                flow: self.flow,
                tls: self
                    .tls
                    .unwrap_or(false)
                    .then(|| tls_config(server_name, self.skip_cert_verify)),
                transport,
            },
            "trojan" => OutboundConfigKind::Trojan {
                server,
                password: required(self.password, &self.name, "password")?,
                tls: Some(tls_config(server_name, self.skip_cert_verify)),
                transport,
            },
            "hysteria2" | "hy2" => OutboundConfigKind::Hysteria2 {
                server,
                password: self
                    .password
                    .or(self.auth)
                    .ok_or_else(|| missing(&self.name, "password/auth"))?,
                server_name,
                insecure: self.skip_cert_verify,
                up_mbps: self.up.unwrap_or_default(),
                down_mbps: self.down.unwrap_or_default(),
                obfs_password: None,
                hop_ports: None,
                hop_interval: None,
                pin_sha256: None,
                ca_pem: None,
                fast_open: true,
            },
            "anytls" => OutboundConfigKind::AnyTls {
                server,
                password: required(self.password, &self.name, "password")?,
                tls: Some(tls_config(server_name, self.skip_cert_verify)),
            },
            other => {
                return Err(ConfigFileError::new(format!(
                    "unsupported Clash proxy type `{other}` for `{}`",
                    self.name
                )));
            }
        };
        Ok(OutboundConfig {
            id: self.name,
            dial: DialConfig::default(),
            kind,
        })
    }

    fn transport(&self) -> Result<Option<V2RayTransportConfig>, ConfigFileError> {
        let Some(network) = self.network.as_deref() else {
            return Ok(None);
        };
        match network.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Some(V2RayTransportConfig::Tcp)),
            "ws" => {
                let options = self.ws_opts.clone().unwrap_or_default();
                let host = options
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.clone());
                Ok(Some(V2RayTransportConfig::WebSocket {
                    path: options.path.unwrap_or_else(|| "/".to_string()),
                    host,
                    headers: options.headers,
                    max_early_data: options.max_early_data.unwrap_or_default(),
                    early_data_header: options.early_data_header_name,
                }))
            }
            "h2" => {
                let options = self.h2_opts.clone().unwrap_or_default();
                Ok(Some(V2RayTransportConfig::Http2 {
                    path: options.path.unwrap_or_else(|| "/".to_string()),
                    hosts: options.host,
                }))
            }
            "grpc" => {
                let options = self.grpc_opts.clone().unwrap_or_default();
                Ok(Some(V2RayTransportConfig::Grpc {
                    service_name: options.grpc_service_name.unwrap_or_default(),
                    authority: None,
                }))
            }
            other => Err(ConfigFileError::new(format!(
                "unsupported Clash transport `{other}` for `{}`",
                self.name
            ))),
        }
    }
}

fn required(value: Option<String>, proxy: &str, field: &str) -> Result<String, ConfigFileError> {
    value.ok_or_else(|| missing(proxy, field))
}

fn missing(proxy: &str, field: &str) -> ConfigFileError {
    ConfigFileError::new(format!("Clash proxy `{proxy}` requires `{field}`"))
}

fn tls_config(server_name: Option<String>, insecure: bool) -> OutboundTlsConfig {
    OutboundTlsConfig {
        enabled: true,
        server_name,
        insecure,
        alpn: Vec::new(),
        client_certificate_pem: None,
        client_private_key_pem: None,
        certificate_authorities_pem: Vec::new(),
        certificate_public_key_sha256: Vec::new(),
        fingerprint: None,
        ech_config: None,
        reality: None,
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ClashWebSocketOptions {
    path: Option<String>,
    headers: BTreeMap<String, String>,
    #[serde(rename = "max-early-data")]
    max_early_data: Option<usize>,
    #[serde(rename = "early-data-header-name")]
    early_data_header_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ClashHttp2Options {
    path: Option<String>,
    host: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ClashGrpcOptions {
    #[serde(rename = "grpc-service-name")]
    grpc_service_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClashProxyGroup {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    proxies: Vec<String>,
    #[serde(rename = "use")]
    providers: Vec<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

impl ClashProxyGroup {
    fn into_outbound(self) -> Result<OutboundConfig, ConfigFileError> {
        if !self.providers.is_empty() {
            return Err(ConfigFileError::new(format!(
                "Clash proxy group `{}` uses proxy providers, which are not supported yet",
                self.name
            )));
        }
        let kind = match self.kind.to_ascii_lowercase().as_str() {
            "select" => OutboundConfigKind::Selector {
                default: self.proxies.first().cloned(),
                outbounds: self.proxies,
                cache_path: None,
            },
            "url-test" => {
                if self.proxies.is_empty() {
                    return Err(ConfigFileError::new(format!(
                        "Clash url-test group `{}` must contain at least one proxy",
                        self.name
                    )));
                }
                OutboundConfigKind::UrlTest {
                    outbounds: self.proxies,
                    url: self
                        .url
                        .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
                    interval_seconds: self.interval.unwrap_or(300),
                    tolerance_ms: self.tolerance.unwrap_or_default(),
                    timeout_seconds: 10,
                    concurrency: 4,
                    failure_threshold: 2,
                    cache_path: None,
                    interrupt_exist_connections: false,
                }
            }
            other => {
                return Err(ConfigFileError::new(format!(
                    "unsupported Clash proxy group type `{other}` for `{}`; RustBox currently supports select and url-test",
                    self.name
                )));
            }
        };
        Ok(OutboundConfig {
            id: self.name,
            dial: DialConfig::default(),
            kind,
        })
    }
}

fn parse_rule(index: usize, input: &str) -> Result<RouteRuleConfig, ConfigFileError> {
    let fields = input.split(',').map(str::trim).collect::<Vec<_>>();
    let kind = fields
        .first()
        .map(|value| value.to_ascii_uppercase())
        .unwrap_or_default();
    if kind == "MATCH" || kind == "FINAL" {
        let outbound = fields
            .get(1)
            .ok_or_else(|| invalid_rule(index, input, "missing target"))?;
        return Ok(default_rule(outbound));
    }
    if fields.len() < 3 {
        return Err(invalid_rule(index, input, "expected TYPE,VALUE,TARGET"));
    }
    let value = fields[1];
    let outbound = fields[2];
    let mut matcher = RouteMatchConfig::default();
    match kind.as_str() {
        "DOMAIN" => matcher.domain.push(value.to_string()),
        "DOMAIN-SUFFIX" => matcher.domain_suffix.push(value.to_string()),
        "DOMAIN-KEYWORD" => matcher.domain_keyword.push(value.to_string()),
        "DOMAIN-REGEX" => matcher.domain_regex.push(value.to_string()),
        "IP-CIDR" | "IP-CIDR6" => matcher.ip_cidr.push(parse_cidr(index, input, value)?),
        "SRC-IP-CIDR" => matcher
            .source_ip_cidr
            .push(parse_cidr(index, input, value)?),
        "DST-PORT" => matcher.port.push(parse_port(index, input, value)?),
        "SRC-PORT" => matcher.source_port.push(parse_port(index, input, value)?),
        "PROCESS-NAME" => matcher.process_name.push(value.to_string()),
        "PROCESS-PATH" => matcher.process_path.push(value.to_string()),
        "IN-NAME" => matcher.inbound.push(value.to_string()),
        "NETWORK" if value.eq_ignore_ascii_case("tcp") => matcher.network.push(Network::Tcp),
        "NETWORK" if value.eq_ignore_ascii_case("udp") => matcher.network.push(Network::Udp),
        "RULE-SET" => {
            return Err(invalid_rule(
                index,
                input,
                "rule providers are not supported yet",
            ));
        }
        _ => {
            return Err(invalid_rule(
                index,
                input,
                &format!("unsupported rule type `{kind}`"),
            ));
        }
    }
    Ok(RouteRuleConfig::Rule {
        matcher: RouteMatcherConfig::Conditions(Box::new(matcher)),
        action: route_action(outbound),
    })
}

fn parse_cidr(index: usize, rule: &str, value: &str) -> Result<IpCidr, ConfigFileError> {
    value
        .parse::<IpCidr>()
        .map_err(|error| invalid_rule(index, rule, &error))
}

fn parse_port(index: usize, rule: &str, value: &str) -> Result<PortRange, ConfigFileError> {
    value
        .parse::<PortRange>()
        .map_err(|error| invalid_rule(index, rule, &error))
}

fn route_action(outbound: &str) -> RouteActionConfig {
    match outbound.to_ascii_uppercase().as_str() {
        "REJECT" => RouteActionConfig::Reject(RejectReason::Policy),
        "REJECT-DROP" | "DROP" => RouteActionConfig::Reject(RejectReason::Drop),
        _ => RouteActionConfig::Outbound(outbound.to_string()),
    }
}

fn default_rule(outbound: &str) -> RouteRuleConfig {
    match route_action(outbound) {
        RouteActionConfig::Reject(reason) => RouteRuleConfig::RejectDefault { reason },
        RouteActionConfig::Outbound(outbound) => RouteRuleConfig::Default { outbound },
        _ => unreachable!("Clash targets only produce outbound or reject actions"),
    }
}

fn is_default_rule(rule: &RouteRuleConfig) -> bool {
    matches!(
        rule,
        RouteRuleConfig::Default { .. } | RouteRuleConfig::RejectDefault { .. }
    )
}

fn invalid_rule(index: usize, rule: &str, reason: &str) -> ConfigFileError {
    ConfigFileError::new(format!(
        "invalid Clash rule at rules[{index}] `{rule}`: {reason}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_common_clash_document() {
        let source = parse_clash_source(
            r#"
mixed-port: 7890
allow-lan: false
proxies:
  - name: edge
    type: ss
    server: proxy.example.test
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: proxy
    type: select
    proxies: [edge, DIRECT]
rules:
  - DOMAIN-SUFFIX,example.com,proxy
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,proxy
"#,
        )
        .expect("parse Clash config");

        assert_eq!(source.inbounds.len(), 1);
        assert_eq!(source.outbounds.len(), 4);
        assert_eq!(source.routes.len(), 3);
        assert!(matches!(
            source.outbounds[2].kind,
            OutboundConfigKind::Shadowsocks { .. }
        ));
        assert!(matches!(
            source.outbounds[3].kind,
            OutboundConfigKind::Selector { .. }
        ));
        assert!(matches!(
            source.routes[2],
            RouteRuleConfig::Default { ref outbound } if outbound == "proxy"
        ));
    }

    #[test]
    fn reports_unsupported_group_semantics() {
        let error = parse_clash_source(
            r#"
proxy-groups:
  - name: fallback
    type: fallback
    proxies: [DIRECT]
"#,
        )
        .expect_err("fallback is not equivalent to url-test");
        assert!(error.message.contains("fallback"));
    }
}
