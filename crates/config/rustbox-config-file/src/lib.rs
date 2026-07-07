//! RustBox 配置文件格式适配器。
//!
//! 本 crate 负责把用户编写的 TOML 等文件形态转换为格式无关的
//! `rustbox-config` 模型。运行时模块和内核不依赖文件解析。

use rustbox_config::{InboundConfig, OutboundConfig, RouteRuleConfig, SourceConfig};
use rustbox_types::{Endpoint, Host, IpAddress, RejectReason};
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// 文件解析结果：核心 SourceConfig 加上文件侧可选的应用级配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileConfig {
    pub source: SourceConfig,
    pub observability: Option<FileObservabilityConfig>,
}

/// 当前文件格式支持的观测配置，组合根会把它转成具体 sink。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservabilityConfig {
    pub level: Option<String>,
    pub file: Option<String>,
    pub platform: Option<bool>,
    pub remote_endpoint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFileError {
    pub message: String,
}

impl ConfigFileError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 从磁盘读取 TOML 文件并解析为统一配置模型。
pub fn load_toml_file(path: impl AsRef<Path>) -> Result<FileConfig, ConfigFileError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .map_err(|err| ConfigFileError::new(format!("failed to read config file: {err}")))?;
    parse_toml_str(&text)
}

/// 从 TOML 文本解析配置，供 CLI、测试和 FFI 文本入口复用。
pub fn parse_toml_str(input: &str) -> Result<FileConfig, ConfigFileError> {
    let document = toml::from_str::<TomlConfigDocument>(input)
        .map_err(|err| ConfigFileError::new(format!("failed to parse TOML config: {err}")))?;
    document.into_file_config()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfigDocument {
    schema_version: u32,
    observability: Option<TomlObservabilityConfig>,
    #[serde(default)]
    inbounds: Vec<TomlInboundConfig>,
    #[serde(default)]
    outbounds: Vec<TomlOutboundConfig>,
    #[serde(default)]
    routes: Vec<TomlRouteRuleConfig>,
}

impl TomlConfigDocument {
    fn into_file_config(self) -> Result<FileConfig, ConfigFileError> {
        // 文件格式版本在进入 SourceConfig 前校验，避免运行时理解历史格式。
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(ConfigFileError::new(format!(
                "unsupported config schema_version `{}`",
                self.schema_version
            )));
        }

        let inbounds = self
            .inbounds
            .into_iter()
            .map(TomlInboundConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let outbounds = self
            .outbounds
            .into_iter()
            .map(TomlOutboundConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;
        let routes = self
            .routes
            .into_iter()
            .map(TomlRouteRuleConfig::into_source)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FileConfig {
            source: SourceConfig {
                inbounds,
                outbounds,
                routes,
            },
            observability: self
                .observability
                .map(|observability| FileObservabilityConfig {
                    level: observability.level,
                    file: observability.file,
                    platform: observability.platform,
                    remote_endpoint: observability.remote_endpoint,
                }),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlObservabilityConfig {
    level: Option<String>,
    file: Option<String>,
    platform: Option<bool>,
    remote_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlInboundConfig {
    HttpConnect { id: String, listen: String },
    Socks5 { id: String, listen: String },
}

impl TomlInboundConfig {
    fn into_source(self) -> Result<InboundConfig, ConfigFileError> {
        match self {
            Self::HttpConnect { id, listen } => Ok(InboundConfig::HttpConnect {
                id,
                listen: parse_endpoint(&listen)?,
            }),
            Self::Socks5 { id, listen } => Ok(InboundConfig::Socks5 {
                id,
                listen: parse_endpoint(&listen)?,
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlOutboundConfig {
    Direct {
        id: String,
    },
    Block {
        id: String,
    },
    Socks5 {
        id: String,
        server: String,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        id: String,
        server: String,
        username: Option<String>,
        password: Option<String>,
    },
    Shadowsocks {
        id: String,
        server: String,
        method: String,
        password: String,
    },
}

impl TomlOutboundConfig {
    fn into_source(self) -> Result<OutboundConfig, ConfigFileError> {
        match self {
            Self::Direct { id } => Ok(OutboundConfig::Direct { id }),
            Self::Block { id } => Ok(OutboundConfig::Block { id }),
            Self::Socks5 {
                id,
                server,
                username,
                password,
            } => Ok(OutboundConfig::Socks5 {
                id,
                server: parse_endpoint(&server)?,
                username,
                password,
            }),
            Self::Http {
                id,
                server,
                username,
                password,
            } => Ok(OutboundConfig::Http {
                id,
                server: parse_endpoint(&server)?,
                username,
                password,
            }),
            Self::Shadowsocks {
                id,
                server,
                method,
                password,
            } => Ok(OutboundConfig::Shadowsocks {
                id,
                server: parse_endpoint(&server)?,
                method,
                password,
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TomlRouteRuleConfig {
    Default { outbound: String },
    RejectDefault { reason: TomlRejectReason },
}

impl TomlRouteRuleConfig {
    fn into_source(self) -> Result<RouteRuleConfig, ConfigFileError> {
        match self {
            Self::Default { outbound } => Ok(RouteRuleConfig::Default { outbound }),
            Self::RejectDefault { reason } => Ok(RouteRuleConfig::RejectDefault {
                reason: reason.into(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TomlRejectReason {
    Policy,
    NoRoute,
    UnsupportedNetwork,
}

impl From<TomlRejectReason> for RejectReason {
    fn from(value: TomlRejectReason) -> Self {
        match value {
            TomlRejectReason::Policy => Self::Policy,
            TomlRejectReason::NoRoute => Self::NoRoute,
            TomlRejectReason::UnsupportedNetwork => Self::UnsupportedNetwork,
        }
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, ConfigFileError> {
    // 文件层负责把人类可读地址解析成基础层 Endpoint。
    let (host, port) = split_host_port(value)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| ConfigFileError::new(format!("endpoint `{value}` has invalid port")))?;
    Ok(Endpoint::new(parse_host(host), port))
}

fn split_host_port(value: &str) -> Result<(&str, &str), ConfigFileError> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(ConfigFileError::new(format!(
                "endpoint `{value}` has invalid bracketed IPv6 form"
            )));
        };
        return Ok((host, port));
    }

    value.rsplit_once(':').ok_or_else(|| {
        ConfigFileError::new(format!("endpoint `{value}` must include host and port"))
    })
}

fn parse_host(value: &str) -> Host {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Host::Ip(IpAddress::V4(ip.octets())),
        Ok(IpAddr::V6(ip)) => Host::Ip(IpAddress::V6(ip.octets())),
        Err(_) => Host::Domain(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_http_and_socks5_proxy_config() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[observability]
level = "debug"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"

[[outbounds]]
id = "direct"
type = "direct"

[[outbounds]]
id = "socks-out"
type = "socks5"
server = "127.0.0.1:1081"

[[outbounds]]
id = "block"
type = "block"

[[outbounds]]
id = "http-out"
type = "http"
server = "proxy.example.test:8080"
username = "alice"
password = "secret"

[[outbounds]]
id = "ss-out"
type = "shadowsocks"
server = "ss.example.test:8388"
method = "aes-128-gcm"
password = "test-password"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse config");

        assert_eq!(config.source.inbounds.len(), 2);
        assert_eq!(config.source.outbounds.len(), 5);
        assert_eq!(config.source.routes.len(), 1);
        assert!(matches!(
            config.source.outbounds[2],
            OutboundConfig::Block { .. }
        ));
        assert!(matches!(
            config.source.outbounds[3],
            OutboundConfig::Http { .. }
        ));
        assert!(matches!(
            config.source.outbounds[4],
            OutboundConfig::Shadowsocks { .. }
        ));
        assert_eq!(
            config.observability.map(|value| (
                value.level,
                value.file,
                value.platform,
                value.remote_endpoint
            )),
            Some((Some("debug".to_string()), None, None, None))
        );
    }

    #[test]
    fn parses_observability_outputs() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[observability]
level = "info"
file = "target/rustbox.log"
platform = true
remote_endpoint = "https://telemetry.example.test/rustbox"
"#,
        )
        .expect("parse config");

        let observability = config.observability.expect("observability config");
        assert_eq!(observability.file, Some("target/rustbox.log".to_string()));
        assert_eq!(observability.platform, Some(true));
        assert_eq!(
            observability.remote_endpoint,
            Some("https://telemetry.example.test/rustbox".to_string())
        );
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint() {
        let endpoint = parse_endpoint("[::1]:1080").expect("parse endpoint");

        assert_eq!(endpoint.port, 1080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V6(Ipv6Addr::LOCALHOST.octets()))
        );
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let error = parse_toml_str(
            r#"
schema_version = 2
"#,
        )
        .expect_err("unsupported schema");

        assert!(error.message.contains("unsupported config schema_version"));
    }

    #[test]
    fn parses_ipv4_endpoint() {
        let endpoint = parse_endpoint("127.0.0.1:18080").expect("parse endpoint");

        assert_eq!(endpoint.port, 18080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V4(Ipv4Addr::LOCALHOST.octets()))
        );
    }
}
