//! RustBox 配置文件格式适配器。
//!
//! 本 crate 负责把用户编写的 TOML 等文件形态转换为格式无关的
//! `rustbox-config` 模型。运行时模块和内核不依赖文件解析。

mod observability;

use garde::Validate;
use rustbox_config::{
    DnsConfig, InboundConfig, LogicalModeConfig, OutboundConfig, RouteActionConfig,
    RouteMatchConfig, RouteMatcherConfig, RouteOptionsConfig, RouteResolveConfig, RouteRuleConfig,
    RouteRuleSetConfig, RouteRuleSetFormat, RouteRuleSetSourceConfig, SourceConfig,
};
use rustbox_route::ResolveStrategy;
use rustbox_types::{IpCidr, Network, NetworkType, PortRange, ProtocolHint, RejectReason};
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{ConfigFileError, loader, migration};
pub use observability::FileObservabilityConfig;
use observability::TomlObservabilityConfig;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// User-facing configuration syntax selected from a file extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    Toml,
    Json,
    Clash,
}

impl ConfigFormat {
    fn from_path(path: &Path) -> Result<Self, ConfigFileError> {
        match path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("toml") => Ok(Self::Toml),
            Some("json") => Ok(Self::Json),
            Some("yaml" | "yml") => Ok(Self::Clash),
            extension => Err(ConfigFileError::new(format!(
                "unsupported config file extension `{}`; expected .toml, .json, .yaml, or .yml",
                extension.unwrap_or("<none>")
            ))),
        }
    }
}

/// 文件解析结果：核心 SourceConfig 加上文件侧可选的应用级配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConfig {
    pub source: SourceConfig,
    pub observability: Option<FileObservabilityConfig>,
}

impl FileConfig {
    /// Discards file-only application settings and returns the runtime source model.
    pub fn into_source(self) -> SourceConfig {
        self.source
    }
}

/// Typed configuration loader with optional environment overrides.
///
/// Environment loading is opt-in so existing file-only callers remain fully
/// deterministic. Nested keys use `__`, for example
/// `RUSTBOX_OBSERVABILITY__LEVEL=debug` with the `RUSTBOX_` prefix.
#[derive(Clone, Debug, Default)]
pub struct ConfigLoader {
    env_prefix: Option<String>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = Some(prefix.into());
        self
    }

    pub fn load(&self, path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
        let path = path.as_ref();
        let document = match self.env_prefix.as_deref() {
            Some(prefix) => loader::load_toml_with_env::<ConfigDocument>(path, prefix)?,
            None => loader::load_toml::<ConfigDocument>(path)?,
        };
        document.into_file_config(path.parent())
    }

    pub fn parse(&self, input: &str) -> Result<FileConfig, ConfigFileError> {
        let document = match self.env_prefix.as_deref() {
            Some(prefix) => loader::parse_toml_with_env::<ConfigDocument>(input, prefix)?,
            None => loader::parse_toml::<ConfigDocument>(input)?,
        };
        document.into_file_config(None)
    }

    /// Loads only the format-independent runtime source model.
    pub fn load_source(&self, path: impl AsRef<Path>) -> Result<SourceConfig, ConfigFileError> {
        self.load(path).map(FileConfig::into_source)
    }

    /// Parses only the format-independent runtime source model.
    pub fn parse_source(&self, input: &str) -> Result<SourceConfig, ConfigFileError> {
        self.parse(input).map(FileConfig::into_source)
    }
}

/// 从磁盘读取 TOML 文件并解析为统一配置模型。
pub fn load_toml_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    ConfigLoader::new().load(path)
}

/// 从 TOML 文本解析配置，供 CLI、测试和 Flutter 文本入口复用。
pub fn parse_toml_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    ConfigLoader::new().parse(input)
}

/// 从磁盘读取 TOML 文件并直接返回格式无关的运行配置。
pub fn load_toml_source(path: impl AsRef<Path>) -> Result<SourceConfig, ConfigFileError> {
    ConfigLoader::new().load_source(path)
}

/// 从 TOML 文本直接返回格式无关的运行配置。
pub fn parse_toml_source(input: &str) -> Result<SourceConfig, ConfigFileError> {
    ConfigLoader::new().parse_source(input)
}

/// 从磁盘读取 JSON 文件并解析为统一配置模型。
pub fn load_json_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    let path = path.as_ref();
    let document = loader::load_json::<ConfigDocument>(path)?;
    document.into_file_config(path.parent())
}

/// 从 JSON 文本解析配置；字段及语义与 TOML 入口完全一致。
pub fn parse_json_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    loader::parse_json::<ConfigDocument>(input)?.into_file_config(None)
}

/// 从磁盘读取 JSON 文件并直接返回格式无关的运行配置。
pub fn load_json_source(path: impl AsRef<Path>) -> Result<SourceConfig, ConfigFileError> {
    load_json_file(path).map(FileConfig::into_source)
}

/// 从 JSON 文本直接返回格式无关的运行配置。
pub fn parse_json_source(input: &str) -> Result<SourceConfig, ConfigFileError> {
    parse_json_str(input).map(FileConfig::into_source)
}

/// Loads TOML, native JSON, or Clash YAML according to the file extension.
pub fn load_config_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    let path = path.as_ref();
    match ConfigFormat::from_path(path)? {
        ConfigFormat::Toml => load_toml_file(path),
        ConfigFormat::Json => load_json_file(path),
        ConfigFormat::Clash => crate::clash::load_clash_file(path),
    }
}

/// Loads only the normalized runtime model from any supported file syntax.
pub fn load_config_source(path: impl AsRef<Path>) -> Result<SourceConfig, ConfigFileError> {
    load_config_file(path).map(FileConfig::into_source)
}

pub fn parse_rule_set_source_json(input: &str) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
    loader::parse_json::<SourceRouteRuleSetDocument>(input)?.into_rules()
}

pub fn parse_rule_set_rustbox_toml(
    input: &str,
) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
    loader::parse_toml::<TomlRouteRuleSetDocument>(input)?.into_rules()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRouteRuleSetDocument {
    version: u32,
    rules: Vec<SourceRouteMatcher>,
}

impl SourceRouteRuleSetDocument {
    fn into_rules(self) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
        if !(1..=5).contains(&self.version) {
            return Err(ConfigFileError::new(format!(
                "unsupported sing-box rule-set source version {}",
                self.version
            )));
        }
        self.rules
            .into_iter()
            .map(SourceRouteMatcher::into_source)
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SourceRouteMatcher {
    Logical {
        #[serde(rename = "type")]
        kind: SourceLogicalType,
        mode: TomlLogicalMode,
        rules: Vec<SourceRouteMatcher>,
        #[serde(default)]
        invert: bool,
    },
    Default {
        #[serde(rename = "type", default)]
        kind: Option<SourceDefaultType>,
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SourceLogicalType {
    Logical,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SourceDefaultType {
    Default,
    Rule,
}

impl SourceRouteMatcher {
    fn into_source(self) -> Result<RouteMatcherConfig, ConfigFileError> {
        match self {
            Self::Logical {
                kind,
                mode,
                rules,
                invert,
            } => {
                let _ = kind;
                Ok(RouteMatcherConfig::Logical {
                    mode: mode.into(),
                    rules: rules
                        .into_iter()
                        .map(Self::into_source)
                        .collect::<Result<Vec<_>, _>>()?,
                    invert,
                })
            }
            Self::Default { kind, matcher } => {
                let _ = kind;
                Ok(RouteMatcherConfig::Conditions(Box::new((*matcher).into())))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema_version: u32,
    #[garde(dive)]
    observability: Option<TomlObservabilityConfig>,
    #[serde(default)]
    #[garde(dive)]
    inbounds: Vec<InboundConfig>,
    #[serde(default)]
    #[garde(dive)]
    outbounds: Vec<OutboundConfig>,
    /// Bidirectional network endpoints. They are lowered into the same
    /// route-addressable runtime graph as outbounds; keeping the distinction
    /// in the document avoids duplicating compiler and data-plane machinery.
    #[serde(default)]
    #[garde(dive)]
    endpoints: Vec<OutboundConfig>,
    #[garde(dive)]
    dns: Option<DnsConfig>,
    #[serde(default)]
    rule_sets: Vec<TomlRouteRuleSetConfig>,
    #[serde(default)]
    routes: Vec<TomlRouteRuleConfig>,
}

impl ConfigDocument {
    fn into_file_config(self, base_dir: Option<&Path>) -> Result<FileConfig, ConfigFileError> {
        // Reject unknown document shapes before applying current-schema rules.
        migration::accept_schema_version(self.schema_version)?;
        self.validate().map_err(|error| {
            ConfigFileError::new(format!("configuration validation failed: {error}"))
        })?;

        let mut inbounds = self.inbounds;
        for inbound in &mut inbounds {
            if let rustbox_config::InboundConfigKind::Tun(config) = &mut inbound.kind {
                config.normalize_derived_modes();
            }
        }
        let mut outbounds = self.outbounds;
        for endpoint in self.endpoints {
            if !matches!(
                endpoint.kind,
                rustbox_config::OutboundConfigKind::WireGuard { .. }
            ) {
                return Err(ConfigFileError::new(format!(
                    "endpoint `{}` uses an unsupported endpoint type; currently only `wireguard` is supported",
                    endpoint.id
                )));
            }
            outbounds.push(endpoint);
        }
        let routes = self
            .routes
            .into_iter()
            .map(TomlRouteRuleConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let route_rule_sets = self
            .rule_sets
            .into_iter()
            .map(|rule_set| rule_set.into_source(base_dir))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FileConfig {
            source: SourceConfig {
                inbounds,
                outbounds,
                dns: self.dns,
                route_rule_sets,
                routes,
            },
            observability: self
                .observability
                .map(TomlObservabilityConfig::into_file)
                .transpose()?,
        })
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteRuleConfig {
    Default {
        outbound: String,
    },
    RejectDefault {
        reason: TomlRejectReason,
    },
    Rule {
        outbound: Option<String>,
        reject: Option<TomlRejectReason>,
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    Logical {
        mode: TomlLogicalMode,
        rules: Vec<TomlRouteMatcherConfig>,
        outbound: Option<String>,
        reject: Option<TomlRejectReason>,
        #[serde(default)]
        invert: bool,
    },
    RouteOptions {
        override_address: Option<String>,
        override_port: Option<u16>,
        #[serde(default, with = "humantime_serde::option")]
        udp_timeout: Option<std::time::Duration>,
        udp_connect: Option<bool>,
        udp_disable_domain_unmapping: Option<bool>,
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    Resolve {
        server: Option<String>,
        #[serde(default)]
        strategy: TomlResolveStrategy,
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    HijackDns {
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
}

impl TomlRouteRuleConfig {
    fn into_source(self) -> Result<RouteRuleConfig, ConfigFileError> {
        match self {
            Self::Default { outbound } => Ok(RouteRuleConfig::Default { outbound }),
            Self::RejectDefault { reason } => Ok(RouteRuleConfig::RejectDefault {
                reason: reason.into(),
            }),
            Self::Rule {
                outbound,
                reject,
                matcher,
            } => Ok(RouteRuleConfig::Rule {
                matcher: RouteMatcherConfig::Conditions(Box::new((*matcher).into())),
                action: route_action(outbound, reject)?,
            }),
            Self::Logical {
                mode,
                rules,
                outbound,
                reject,
                invert,
            } => Ok(RouteRuleConfig::Logical {
                mode: mode.into(),
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
                invert,
                action: route_action(outbound, reject)?,
            }),
            Self::RouteOptions {
                override_address,
                override_port,
                udp_timeout,
                udp_connect,
                udp_disable_domain_unmapping,
                matcher,
            } => Ok(RouteRuleConfig::Rule {
                matcher: RouteMatcherConfig::Conditions(Box::new((*matcher).into())),
                action: RouteActionConfig::Options(RouteOptionsConfig {
                    override_address: override_address
                        .map(|value| value.parse())
                        .transpose()
                        .map_err(ConfigFileError::new)?,
                    override_port,
                    udp_timeout,
                    udp_connect,
                    udp_disable_domain_unmapping,
                }),
            }),
            Self::Resolve {
                server,
                strategy,
                matcher,
            } => Ok(RouteRuleConfig::Rule {
                matcher: RouteMatcherConfig::Conditions(Box::new((*matcher).into())),
                action: RouteActionConfig::Resolve(RouteResolveConfig {
                    server,
                    strategy: strategy.into(),
                }),
            }),
            Self::HijackDns { matcher } => Ok(RouteRuleConfig::Rule {
                matcher: RouteMatcherConfig::Conditions(Box::new((*matcher).into())),
                action: RouteActionConfig::HijackDns,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlResolveStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl From<TomlResolveStrategy> for ResolveStrategy {
    fn from(value: TomlResolveStrategy) -> Self {
        match value {
            TomlResolveStrategy::PreferIpv4 => Self::PreferIpv4,
            TomlResolveStrategy::PreferIpv6 => Self::PreferIpv6,
            TomlResolveStrategy::Ipv4Only => Self::Ipv4Only,
            TomlResolveStrategy::Ipv6Only => Self::Ipv6Only,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteMatcherConfig {
    Rule {
        #[serde(flatten)]
        matcher: Box<TomlRouteMatchFields>,
    },
    Logical {
        mode: TomlLogicalMode,
        rules: Vec<TomlRouteMatcherConfig>,
        #[serde(default)]
        invert: bool,
    },
}

impl TomlRouteMatcherConfig {
    fn into_source(self) -> Result<RouteMatcherConfig, ConfigFileError> {
        match self {
            Self::Rule { matcher } => {
                Ok(RouteMatcherConfig::Conditions(Box::new((*matcher).into())))
            }
            Self::Logical {
                mode,
                rules,
                invert,
            } => Ok(RouteMatcherConfig::Logical {
                mode: mode.into(),
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
                invert,
            }),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRouteMatchFields {
    #[serde(default)]
    inbound: Vec<String>,
    #[serde(default)]
    network: Vec<TomlNetwork>,
    #[serde(default)]
    protocol: Vec<TomlProtocol>,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(default)]
    domain_regex: Vec<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    ip_cidr: Vec<IpCidr>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    source_ip_cidr: Vec<IpCidr>,
    #[serde(default)]
    port: Vec<u16>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    port_range: Vec<PortRange>,
    #[serde(default)]
    source_port: Vec<u16>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    source_port_range: Vec<PortRange>,
    #[serde(default)]
    rule_set: Vec<String>,
    #[serde(default)]
    process_name: Vec<String>,
    #[serde(default)]
    process_path: Vec<String>,
    #[serde(default)]
    package_name: Vec<String>,
    #[serde(default)]
    user_id: Vec<u32>,
    #[serde(default)]
    user_name: Vec<String>,
    #[serde(default)]
    interface: Vec<String>,
    #[serde(default)]
    wifi_ssid: Vec<String>,
    #[serde(default)]
    wifi_bssid: Vec<String>,
    #[serde(default)]
    network_type: Vec<NetworkType>,
    #[serde(default)]
    invert: bool,
}

impl From<TomlRouteMatchFields> for RouteMatchConfig {
    fn from(value: TomlRouteMatchFields) -> Self {
        Self {
            inbound: value.inbound,
            network: value.network.into_iter().map(Into::into).collect(),
            protocol: value.protocol.into_iter().map(Into::into).collect(),
            domain: value.domain,
            domain_suffix: value.domain_suffix,
            domain_keyword: value.domain_keyword,
            domain_regex: value.domain_regex,
            ip_cidr: value.ip_cidr,
            source_ip_cidr: value.source_ip_cidr,
            port: value
                .port
                .into_iter()
                .map(PortRange::single)
                .chain(value.port_range)
                .collect(),
            source_port: value
                .source_port
                .into_iter()
                .map(PortRange::single)
                .chain(value.source_port_range)
                .collect(),
            rule_set: value.rule_set,
            process_name: value.process_name,
            process_path: value.process_path,
            package_name: value.package_name,
            user_id: value.user_id,
            user_name: value.user_name,
            interface: value.interface,
            wifi_ssid: value.wifi_ssid,
            wifi_bssid: value.wifi_bssid,
            network_type: value.network_type,
            invert: value.invert,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlNetwork {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlProtocol {
    Http,
    Tls,
    Quic,
    Dns,
    Socks5,
}

impl From<TomlProtocol> for ProtocolHint {
    fn from(value: TomlProtocol) -> Self {
        match value {
            TomlProtocol::Http => Self::Http,
            TomlProtocol::Tls => Self::Tls,
            TomlProtocol::Quic => Self::Quic,
            TomlProtocol::Dns => Self::Dns,
            TomlProtocol::Socks5 => Self::Socks5,
        }
    }
}

impl From<TomlNetwork> for Network {
    fn from(value: TomlNetwork) -> Self {
        match value {
            TomlNetwork::Tcp => Self::Tcp,
            TomlNetwork::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlLogicalMode {
    And,
    Or,
}

impl From<TomlLogicalMode> for LogicalModeConfig {
    fn from(value: TomlLogicalMode) -> Self {
        match value {
            TomlLogicalMode::And => Self::And,
            TomlLogicalMode::Or => Self::Or,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteRuleSetConfig {
    Local {
        id: String,
        path: String,
        #[serde(default)]
        format: TomlRouteRuleSetFormat,
        #[serde(default = "default_rule_set_reload_interval", with = "humantime_serde")]
        reload_interval: std::time::Duration,
    },
    Inline {
        id: String,
        rules: Vec<TomlRouteMatcherConfig>,
    },
    Remote {
        id: String,
        url: String,
        #[serde(default = "default_remote_rule_set_format")]
        format: TomlRouteRuleSetFormat,
        #[serde(default = "default_rule_set_update_interval", with = "humantime_serde")]
        update_interval: std::time::Duration,
        cache_path: Option<String>,
    },
}

impl TomlRouteRuleSetConfig {
    fn into_source(self, base_dir: Option<&Path>) -> Result<RouteRuleSetConfig, ConfigFileError> {
        match self {
            Self::Local {
                id,
                path,
                format,
                reload_interval,
            } => {
                let path = resolve_config_path(base_dir, &path);
                let format = RouteRuleSetFormat::from(format);
                let rules = load_rule_set_rules(&path, format)?;
                Ok(RouteRuleSetConfig {
                    id,
                    rules,
                    source: RouteRuleSetSourceConfig::Local {
                        path: path.to_string_lossy().into_owned(),
                        format,
                        reload_interval,
                    },
                })
            }
            Self::Inline { id, rules } => Ok(RouteRuleSetConfig {
                id,
                rules: rules
                    .into_iter()
                    .map(TomlRouteMatcherConfig::into_source)
                    .collect::<Result<Vec<_>, _>>()?,
                source: RouteRuleSetSourceConfig::Inline,
            }),
            Self::Remote {
                id,
                url,
                format,
                update_interval,
                cache_path,
            } => {
                let format = RouteRuleSetFormat::from(format);
                let cache_path = cache_path
                    .map(|path| resolve_config_path(base_dir, &path))
                    .unwrap_or_else(|| {
                        base_dir
                            .unwrap_or_else(|| Path::new("."))
                            .join(".rustbox")
                            .join("rule-sets")
                            .join(format!("{id}.cache"))
                    });
                let rules = if cache_path.exists() {
                    load_rule_set_rules(&cache_path, format)?
                } else {
                    Vec::new()
                };
                Ok(RouteRuleSetConfig {
                    id,
                    rules,
                    source: RouteRuleSetSourceConfig::Remote {
                        url,
                        format,
                        update_interval,
                        cache_path: cache_path.to_string_lossy().into_owned(),
                    },
                })
            }
        }
    }
}

fn load_rule_set_rules(
    path: &Path,
    format: RouteRuleSetFormat,
) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
    if matches!(format, RouteRuleSetFormat::Binary) {
        let bytes = fs::read(path).map_err(|err| {
            ConfigFileError::new(format!(
                "failed to read route rule-set `{}`: {err}",
                path.display()
            ))
        })?;
        return crate::parse_rule_set_srs(&bytes).map_err(|error| {
            ConfigFileError::new(format!(
                "failed to parse route rule-set `{}`: {error}",
                path.display()
            ))
        });
    }
    let text = fs::read_to_string(path).map_err(|err| {
        ConfigFileError::new(format!(
            "failed to read route rule-set `{}`: {err}",
            path.display()
        ))
    })?;
    let document = match format {
        RouteRuleSetFormat::Rustbox => loader::parse_toml::<TomlRouteRuleSetDocument>(&text),
        RouteRuleSetFormat::Source => loader::parse_json::<TomlRouteRuleSetDocument>(&text),
        RouteRuleSetFormat::Binary => unreachable!(),
    }
    .map_err(|error| {
        ConfigFileError::new(format!(
            "failed to parse route rule-set `{}`: {error}",
            path.display()
        ))
    })?;
    document.into_rules()
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlRouteRuleSetFormat {
    #[default]
    Rustbox,
    Source,
    Binary,
}

fn default_remote_rule_set_format() -> TomlRouteRuleSetFormat {
    TomlRouteRuleSetFormat::Source
}

impl From<TomlRouteRuleSetFormat> for RouteRuleSetFormat {
    fn from(value: TomlRouteRuleSetFormat) -> Self {
        match value {
            TomlRouteRuleSetFormat::Rustbox => Self::Rustbox,
            TomlRouteRuleSetFormat::Source => Self::Source,
            TomlRouteRuleSetFormat::Binary => Self::Binary,
        }
    }
}

fn default_rule_set_reload_interval() -> std::time::Duration {
    std::time::Duration::from_secs(1)
}

fn default_rule_set_update_interval() -> std::time::Duration {
    std::time::Duration::from_secs(86_400)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRouteRuleSetDocument {
    #[serde(default)]
    version: Option<u32>,
    rules: Vec<TomlRouteMatcherConfig>,
}

impl TomlRouteRuleSetDocument {
    fn into_rules(self) -> Result<Vec<RouteMatcherConfig>, ConfigFileError> {
        let _ = self.version;
        self.rules
            .into_iter()
            .map(TomlRouteMatcherConfig::into_source)
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlRejectReason {
    Policy,
    NoRoute,
    UnsupportedNetwork,
    Drop,
    TcpReset,
    IcmpPortUnreachable,
    IcmpHostUnreachable,
}

impl From<TomlRejectReason> for RejectReason {
    fn from(value: TomlRejectReason) -> Self {
        match value {
            TomlRejectReason::Policy => Self::Policy,
            TomlRejectReason::NoRoute => Self::NoRoute,
            TomlRejectReason::UnsupportedNetwork => Self::UnsupportedNetwork,
            TomlRejectReason::Drop => Self::Drop,
            TomlRejectReason::TcpReset => Self::TcpReset,
            TomlRejectReason::IcmpPortUnreachable => Self::IcmpPortUnreachable,
            TomlRejectReason::IcmpHostUnreachable => Self::IcmpHostUnreachable,
        }
    }
}

fn route_action(
    outbound: Option<String>,
    reject: Option<TomlRejectReason>,
) -> Result<RouteActionConfig, ConfigFileError> {
    match (outbound, reject) {
        (Some(outbound), None) => Ok(RouteActionConfig::Outbound(outbound)),
        (None, Some(reason)) => Ok(RouteActionConfig::Reject(reason.into())),
        (None, None) => Err(ConfigFileError::new(
            "route rule must set either outbound or reject",
        )),
        (Some(_), Some(_)) => Err(ConfigFileError::new(
            "route rule must not set outbound and reject together",
        )),
    }
}

fn resolve_config_path(base_dir: Option<&Path>, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        base_dir.unwrap_or_else(|| Path::new(".")).join(path)
    }
}
