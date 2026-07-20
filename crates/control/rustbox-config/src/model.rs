use super::*;
use garde::Validate;
use rustbox_types::NetworkType;
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};

/// 格式无关的语义配置，是所有输入前端汇合后的统一模型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub dns: Option<DnsConfig>,
    pub route_rule_sets: Vec<RouteRuleSetConfig>,
    pub routes: Vec<RouteRuleConfig>,
}

impl SourceConfig {
    pub fn default_http_proxy(listen: Endpoint) -> Self {
        Self {
            inbounds: vec![InboundConfig {
                id: "http".to_string(),
                kind: InboundConfigKind::HttpConnect {
                    listen,
                    username: None,
                    password: None,
                },
            }],
            outbounds: vec![OutboundConfig {
                id: "direct".to_string(),
                dial: DialConfig::default(),
                kind: OutboundConfigKind::Direct,
            }],
            dns: None,
            route_rule_sets: Vec::new(),
            routes: vec![RouteRuleConfig::Default {
                outbound: "direct".to_string(),
            }],
        }
    }
}

/// 运行图构造使用的类型化计划，逻辑 ID 已解析为稳定内部 ID。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    pub inbounds: Vec<CompiledInbound>,
    pub outbounds: Vec<CompiledOutbound>,
    pub dns: Option<CompiledDnsConfig>,
    pub route_rule_sets: Vec<CompiledRouteRuleSet>,
    pub route_rules: Vec<CompiledRouteRule>,
}

/// inbound 的源配置，描述用户想暴露的入口类型和监听地址。
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
pub struct InboundConfig {
    pub id: String,
    #[serde(flatten)]
    #[garde(dive)]
    pub kind: InboundConfigKind,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InboundConfigKind {
    /// mixed 入口，在同一 TCP 监听地址上接受 HTTP 代理和 SOCKS5。
    Mixed {
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// HTTP 代理入口，监听本地 TCP 地址并支持 CONNECT 和普通 absolute-form 请求。
    HttpConnect {
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// SOCKS5 入口，监听本地 TCP 地址并支持 CONNECT/UDP ASSOCIATE。
    Socks5 {
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// AnyTLS 服务端入口，同时支持普通 TCP 流与 UOT datagram mode。
    AnyTls {
        #[serde_as(as = "DisplayFromStr")]
        listen: Endpoint,
        password: String,
        tls: AnyTlsInboundTlsConfig,
    },
    /// TUN packet-device inbound. The packet-to-flow stack is composed by the
    /// runtime/platform layer, not by the config model.
    Tun(TunInboundConfig),
    /// Transparent TCP redirect/TPROXY/WFP inbound using platform original-dst.
    Transparent(TransparentInboundConfig),
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct TunInboundConfig {
    pub interface_name: Option<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    #[serde(skip, default = "manual_route_mode")]
    pub route_mode: RouteMode,
    #[serde(skip, default = "no_tun_dns")]
    pub dns_mode: TunDnsMode,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub route_includes: Vec<IpCidr>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub route_excludes: Vec<IpCidr>,
    #[serde(default)]
    pub dns_hijack: Vec<DnsHijackTarget>,
    #[serde(default)]
    pub platform_http_proxy: bool,
    #[serde(default)]
    pub auto_redirect: bool,
}

impl TunInboundConfig {
    pub fn normalize_derived_modes(&mut self) {
        self.route_mode = if self.strict_route {
            RouteMode::Strict
        } else if self.auto_route {
            RouteMode::Auto
        } else {
            RouteMode::Manual
        };
        self.dns_mode = if self.dns_hijack.is_empty() {
            TunDnsMode::None
        } else {
            TunDnsMode::Hijack
        };
    }
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct TransparentInboundConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub listen: Endpoint,
    #[serde(default = "default_transparent_network")]
    pub network: TransparentNetwork,
    #[serde(default = "default_transparent_mode")]
    pub mode: TransparentRedirectMode,
    #[serde(default)]
    pub auto_rules: bool,
    pub mark: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct AnyTlsInboundTlsConfig {
    pub certificate_path: String,
    pub private_key_path: String,
    #[serde(default)]
    pub alpn: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransparentNetwork {
    Tcp,
    Udp,
    TcpUdp,
}

/// outbound 的源配置，描述可被路由引用的出站能力。
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
pub struct OutboundConfig {
    pub id: String,
    #[serde(default)]
    pub dial: DialConfig,
    #[serde(flatten)]
    #[garde(dive)]
    pub kind: OutboundConfigKind,
}

#[serde_as]
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct DialConfig {
    pub detour: Option<String>,
    pub bind_interface: Option<String>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub inet4_bind_address: Option<IpAddr>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub inet6_bind_address: Option<IpAddr>,
    pub routing_mark: Option<u32>,
    #[serde(default, with = "humantime_serde")]
    pub connect_timeout: Option<Duration>,
    #[serde(default)]
    pub disable_tcp_keep_alive: bool,
    #[serde(default, with = "humantime_serde")]
    pub tcp_keep_alive: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    pub tcp_keep_alive_interval: Option<Duration>,
    pub domain_resolver: Option<String>,
    pub multiplex: Option<MultiplexConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct MultiplexConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_multiplex_protocol")]
    pub protocol: MultiplexProtocol,
    #[serde(default = "default_multiplex_streams")]
    pub max_streams: usize,
    #[serde(default = "default_multiplex_connections")]
    pub max_connections: usize,
    #[serde(default = "default_multiplex_buffer")]
    pub buffer_size: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MultiplexProtocol {
    #[default]
    MuxCool,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OutboundConfigKind {
    /// 直连出站，对应 sing-box `direct` outbound。
    Direct,
    /// 阻断出站，对应 sing-box `block` outbound。
    ///
    /// 当前路由编译器会把指向该 ID 的默认路由转成 `Reject(Policy)`，
    /// 避免数据面为“阻断”创建无意义的上游连接。
    Block,
    /// SOCKS5 上游代理，对应 sing-box `socks` outbound 的基础字段。
    Socks5 {
        /// SOCKS5 代理服务器地址和端口。
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        /// SOCKS5 用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// SOCKS5 密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// HTTP CONNECT 上游代理，对应 sing-box `http` outbound 的基础字段。
    Http {
        /// HTTP 代理服务器地址和端口。
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        /// HTTP 代理认证用户名；设置时必须同时设置 `password`。
        username: Option<String>,
        /// HTTP 代理认证密码；设置时必须同时设置 `username`。
        password: Option<String>,
    },
    /// Shadowsocks 上游代理，对应 sing-box `shadowsocks` outbound 的基础字段。
    Shadowsocks {
        /// Shadowsocks 服务器地址和端口。
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        /// Shadowsocks 加密方法名称，例如 `aes-128-gcm`。
        method: String,
        /// Shadowsocks 密码；部分 2022 方法要求这里是 base64 密钥材料。
        password: String,
    },
    /// 手动出站组，对应 sing-box `selector` outbound 的基础字段。
    Selector {
        /// 可被选择的子出站逻辑 ID。
        outbounds: Vec<String>,
        /// 初始选择；未设置时使用 `outbounds` 第一项。
        default: Option<String>,
        /// 可选选择状态文件；成功切换后持久化，启动时恢复。
        #[serde(default)]
        cache_path: Option<String>,
    },
    /// 延迟测试出站组，对应 sing-box `urltest` outbound 的基础字段。
    #[serde(rename = "urltest")]
    UrlTest {
        /// 可参与测试的子出站逻辑 ID。
        #[garde(length(min = 1))]
        outbounds: Vec<String>,
        /// 测试 URL。
        #[serde(default = "default_urltest_url")]
        url: String,
        /// 测试间隔秒数。
        #[serde(default = "default_urltest_interval_seconds")]
        #[garde(range(min = 1))]
        interval_seconds: u64,
        /// 延迟容差毫秒数。
        #[serde(default)]
        tolerance_ms: u16,
        /// 单个探测的总超时秒数。
        #[serde(default = "default_urltest_timeout_seconds")]
        #[garde(range(min = 1))]
        timeout_seconds: u64,
        /// 同一组最多并发探测数。
        #[serde(default = "default_urltest_concurrency")]
        #[garde(range(min = 1))]
        concurrency: usize,
        /// 连续失败达到该值后立即从候选中摘除。
        #[serde(default = "default_urltest_failure_threshold")]
        #[garde(range(min = 1))]
        failure_threshold: u32,
        /// 可选自动选择状态文件。
        #[serde(default)]
        cache_path: Option<String>,
        /// 选择改变时是否中断已有连接（当前平台需支持会话中断）。
        #[serde(default)]
        interrupt_exist_connections: bool,
    },
    /// VMess AEAD 上游代理。
    Vmess {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    /// VLESS 上游代理；当前数据面支持普通 TCP 模式。
    Vless {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    /// Trojan TLS 上游代理。
    Trojan {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    /// Hysteria2 QUIC outbound with TCP streams and native UDP relay.
    Hysteria2 {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        server_name: Option<String>,
        #[serde(default)]
        insecure: bool,
        #[serde(default)]
        up_mbps: u64,
        #[serde(default)]
        down_mbps: u64,
        obfs_password: Option<String>,
        hop_ports: Option<String>,
        #[serde(default, with = "humantime_serde")]
        hop_interval: Option<Duration>,
        pin_sha256: Option<String>,
        ca_pem: Option<String>,
        #[serde(default = "default_true")]
        fast_open: bool,
    },
    /// NaiveProxy over a multiplexed HTTP/2 CONNECT session.
    Naive {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        username: String,
        password: String,
        tls: Option<OutboundTlsConfig>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
    /// TUIC v5 over a shared authenticated QUIC connection.
    Tuic {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        password: String,
        tls: Option<OutboundTlsConfig>,
        #[serde(default = "default_tuic_heartbeat", with = "humantime_serde")]
        heartbeat: Duration,
    },
    /// Userspace WireGuard endpoint exposed to the route graph as an outbound.
    #[serde(rename = "wireguard")]
    WireGuard {
        #[serde(default)]
        #[serde_as(as = "Vec<DisplayFromStr>")]
        addresses: Vec<IpCidr>,
        private_key: String,
        #[serde(default)]
        listen_port: u16,
        peers: Vec<WireGuardPeerConfig>,
        #[serde(default = "default_wireguard_mtu")]
        mtu: usize,
    },
    /// ShadowTLS v3 camouflage transport. Other protocol outbounds can use it
    /// through `dial.detour`.
    #[serde(rename = "shadowtls")]
    ShadowTls {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        #[serde(default = "default_shadowtls_version")]
        version: u8,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
    /// AnyTLS 上游代理；组合根通过 `rustbox-outbound-anytls` 实例化数据面。
    #[serde(rename = "anytls")]
    AnyTls {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct OutboundTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
    /// PEM encoded client certificate chain for mutual TLS.
    pub client_certificate_pem: Option<String>,
    /// PEM encoded client private key for mutual TLS.
    pub client_private_key_pem: Option<String>,
    /// Additional PEM encoded certificate authorities.
    #[serde(default)]
    pub certificate_authorities_pem: Vec<String>,
    /// Base64 encoded SHA-256 hashes of leaf certificate SubjectPublicKeyInfo.
    #[serde(default)]
    pub certificate_public_key_sha256: Vec<String>,
    /// ClientHello profile, for example `chrome` or `firefox`.
    pub fingerprint: Option<String>,
    /// Base64 encoded ECHConfigList.
    pub ech_config: Option<String>,
    /// REALITY authentication parameters.
    pub reality: Option<OutboundRealityConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct OutboundRealityConfig {
    /// URL-safe base64 encoded X25519 public key.
    pub public_key: String,
    /// Hex encoded short id (at most eight bytes; right padded with zeroes).
    pub short_id: String,
    #[serde(default)]
    pub support_x25519_mlkem768: bool,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[garde(allow_unvalidated)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeerConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub server: Endpoint,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub allowed_ips: Vec<IpCidr>,
    #[serde(default, with = "humantime_serde")]
    pub persistent_keepalive: Option<Duration>,
    #[serde(default)]
    pub reserved: [u8; 3],
}

#[derive(Clone, Debug, Eq, PartialEq, Validate)]
#[garde(allow_unvalidated)]
pub enum V2RayTransportConfig {
    Tcp,
    WebSocket {
        path: String,
        host: Option<String>,
        headers: BTreeMap<String, String>,
        max_early_data: usize,
        early_data_header: Option<String>,
    },
    Http2 {
        path: String,
        hosts: Vec<String>,
    },
    Grpc {
        service_name: String,
        authority: Option<String>,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: BTreeMap<String, String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum V2RayTransportRepr {
    Legacy(String),
    Typed(V2RayTransportDocument),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum V2RayTransportDocument {
    Tcp,
    WebSocket {
        #[serde(default = "default_transport_path")]
        path: String,
        host: Option<String>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        max_early_data: usize,
        early_data_header: Option<String>,
    },
    Http2 {
        #[serde(default = "default_transport_path")]
        path: String,
        #[serde(default)]
        hosts: Vec<String>,
    },
    Grpc {
        #[serde(default = "default_grpc_service_name")]
        service_name: String,
        authority: Option<String>,
    },
    HttpUpgrade {
        #[serde(default = "default_transport_path")]
        path: String,
        host: Option<String>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
}

impl<'de> Deserialize<'de> for V2RayTransportConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        match V2RayTransportRepr::deserialize(deserializer)? {
            V2RayTransportRepr::Legacy(value) if value.eq_ignore_ascii_case("tcp") => Ok(Self::Tcp),
            V2RayTransportRepr::Legacy(value) => Err(D::Error::custom(format!(
                "legacy string transport `{value}` is unsupported; use a typed transport table"
            ))),
            V2RayTransportRepr::Typed(value) => Ok(match value {
                V2RayTransportDocument::Tcp => Self::Tcp,
                V2RayTransportDocument::WebSocket {
                    path,
                    host,
                    headers,
                    max_early_data,
                    early_data_header,
                } => Self::WebSocket {
                    path,
                    host,
                    headers,
                    max_early_data,
                    early_data_header,
                },
                V2RayTransportDocument::Http2 { path, hosts } => Self::Http2 { path, hosts },
                V2RayTransportDocument::Grpc {
                    service_name,
                    authority,
                } => Self::Grpc {
                    service_name,
                    authority,
                },
                V2RayTransportDocument::HttpUpgrade {
                    path,
                    host,
                    headers,
                } => Self::HttpUpgrade {
                    path,
                    host,
                    headers,
                },
            }),
        }
    }
}

fn default_transport_path() -> String {
    "/".to_string()
}
fn default_grpc_service_name() -> String {
    "GunService".to_string()
}

fn default_true() -> bool {
    true
}

fn default_urltest_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}

fn default_urltest_interval_seconds() -> u64 {
    300
}

fn default_urltest_timeout_seconds() -> u64 {
    10
}
fn default_urltest_concurrency() -> usize {
    4
}
fn default_urltest_failure_threshold() -> u32 {
    2
}

fn default_tuic_heartbeat() -> Duration {
    Duration::from_secs(3)
}

fn default_wireguard_mtu() -> usize {
    1408
}

fn default_shadowtls_version() -> u8 {
    3
}

fn default_multiplex_protocol() -> MultiplexProtocol {
    MultiplexProtocol::MuxCool
}
fn default_multiplex_streams() -> usize {
    32
}
fn default_multiplex_connections() -> usize {
    4
}
fn default_multiplex_buffer() -> usize {
    64 * 1024
}

fn default_transparent_network() -> TransparentNetwork {
    TransparentNetwork::Tcp
}

fn default_transparent_mode() -> TransparentRedirectMode {
    TransparentRedirectMode::Redirect
}

fn manual_route_mode() -> RouteMode {
    RouteMode::Manual
}

fn no_tun_dns() -> TunDnsMode {
    TunDnsMode::None
}

/// 路由源规则，使用逻辑 ID，尚不直接持有内部 `OutboundId`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteRuleConfig {
    Default {
        outbound: String,
    },
    RejectDefault {
        reason: RejectReason,
    },
    Rule {
        matcher: RouteMatcherConfig,
        action: RouteActionConfig,
    },
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<RouteMatcherConfig>,
        invert: bool,
        action: RouteActionConfig,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRuleSetConfig {
    pub id: String,
    pub rules: Vec<RouteMatcherConfig>,
    pub source: RouteRuleSetSourceConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteRuleSetSourceConfig {
    Inline,
    Local {
        path: String,
        format: RouteRuleSetFormat,
        reload_interval: Duration,
    },
    Remote {
        url: String,
        format: RouteRuleSetFormat,
        update_interval: Duration,
        cache_path: String,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouteRuleSetFormat {
    /// RustBox's legacy TOML rule-set document.
    Rustbox,
    /// sing-box source JSON.
    #[default]
    Source,
    /// sing-box compiled SRS binary.
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteActionConfig {
    Outbound(String),
    Reject(RejectReason),
    HijackDns,
    Options(RouteOptionsConfig),
    Resolve(RouteResolveConfig),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteOptionsConfig {
    pub override_address: Option<Host>,
    pub override_port: Option<u16>,
    pub udp_timeout: Option<Duration>,
    pub udp_connect: Option<bool>,
    pub udp_disable_domain_unmapping: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteResolveConfig {
    pub server: Option<String>,
    pub strategy: ResolveStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalModeConfig {
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMatcherConfig {
    Conditions(Box<RouteMatchConfig>),
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<RouteMatcherConfig>,
        invert: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteMatchConfig {
    pub inbound: Vec<String>,
    pub network: Vec<Network>,
    pub protocol: Vec<ProtocolHint>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Vec<IpCidr>,
    pub source_ip_cidr: Vec<IpCidr>,
    pub port: Vec<PortRange>,
    pub source_port: Vec<PortRange>,
    pub rule_set: Vec<String>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub package_name: Vec<String>,
    pub user_id: Vec<u32>,
    pub user_name: Vec<String>,
    pub interface: Vec<String>,
    pub wifi_ssid: Vec<String>,
    pub wifi_bssid: Vec<String>,
    pub network_type: Vec<NetworkType>,
    pub invert: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledInbound {
    pub id: InboundId,
    pub logical_id: String,
    pub kind: CompiledInboundKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledInboundKind {
    Mixed {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    HttpConnect {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        listen: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    AnyTls {
        listen: Endpoint,
        password: String,
        tls: AnyTlsInboundTlsConfig,
    },
    Tun(TunInboundConfig),
    Transparent(TransparentInboundConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledOutbound {
    pub id: OutboundId,
    pub logical_id: String,
    pub dial: CompiledDialPolicy,
    pub kind: CompiledOutboundKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledDialPolicy {
    pub detour: Option<OutboundId>,
    pub options: rustbox_kernel::DialOptions,
    pub domain_resolver: Option<String>,
    pub multiplex: Option<MultiplexConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledOutboundKind {
    /// 已分配内部 ID 的直连出站，组合根会实例化 direct 数据面模块。
    Direct,
    /// 已分配内部 ID 的阻断出站，路由引用它时会编译成策略拒绝。
    Block,
    /// 已分配内部 ID 的 SOCKS5 上游代理，当前组合根已有运行时模块。
    Socks5 {
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 HTTP CONNECT 上游代理，组合根会实例化 HTTP outbound 模块。
    Http {
        server: Endpoint,
        username: Option<String>,
        password: Option<String>,
    },
    /// 已分配内部 ID 的 Shadowsocks 上游代理，组合根会实例化 Shadowsocks 模块。
    Shadowsocks {
        server: Endpoint,
        method: String,
        password: String,
    },
    /// 已分配内部 ID 的手动出站组。
    Selector {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
        cache_path: Option<String>,
    },
    /// 已分配内部 ID 的自动延迟测试出站组。
    UrlTest {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
        url: String,
        interval_seconds: u64,
        tolerance_ms: u16,
        timeout_seconds: u64,
        concurrency: usize,
        failure_threshold: u32,
        cache_path: Option<String>,
        interrupt_exist_connections: bool,
    },
    Vmess {
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    Vless {
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    Trojan {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<V2RayTransportConfig>,
    },
    Hysteria2 {
        server: Endpoint,
        password: String,
        server_name: Option<String>,
        insecure: bool,
        up_mbps: u64,
        down_mbps: u64,
        obfs_password: Option<String>,
        hop_ports: Option<String>,
        hop_interval: Option<Duration>,
        pin_sha256: Option<String>,
        ca_pem: Option<String>,
        fast_open: bool,
    },
    Naive {
        server: Endpoint,
        username: String,
        password: String,
        tls: Option<OutboundTlsConfig>,
        headers: BTreeMap<String, String>,
    },
    Tuic {
        server: Endpoint,
        uuid: String,
        password: String,
        tls: Option<OutboundTlsConfig>,
        heartbeat: Duration,
    },
    WireGuard {
        addresses: Vec<IpCidr>,
        private_key: String,
        listen_port: u16,
        peers: Vec<WireGuardPeerConfig>,
        mtu: usize,
    },
    ShadowTls {
        server: Endpoint,
        version: u8,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
    AnyTls {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledDnsConfig {
    pub servers: Vec<CompiledDnsServerConfig>,
    pub rules: Vec<DnsRuleConfig>,
    pub final_server: String,
    pub cache: DnsCacheConfig,
    pub fake_ip: Option<FakeIpConfig>,
    pub hijack: Vec<DnsHijackTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledDnsServerConfig {
    pub id: String,
    pub protocol: DnsServerProtocol,
    pub endpoint: Endpoint,
    pub outbound: Option<OutboundId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledRouteRule {
    Default(RouteDecision),
    Rule {
        matcher: CompiledRouteMatcher,
        action: RouteAction,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRouteRuleSet {
    pub id: String,
    pub rules: Vec<CompiledRouteMatcher>,
    pub source: RouteRuleSetSourceConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledRouteMatcher {
    Conditions(Box<CompiledRouteConditions>),
    Logical {
        mode: LogicalModeConfig,
        rules: Vec<CompiledRouteMatcher>,
        invert: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledRouteConditions {
    pub inbounds: Vec<InboundId>,
    pub networks: Vec<Network>,
    pub protocols: Vec<ProtocolHint>,
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ip_cidrs: Vec<IpCidr>,
    pub source_ip_cidrs: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub rule_sets: Vec<String>,
    pub process_names: Vec<String>,
    pub process_paths: Vec<String>,
    pub package_names: Vec<String>,
    pub user_ids: Vec<u32>,
    pub user_names: Vec<String>,
    pub interfaces: Vec<String>,
    pub wifi_ssids: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub network_types: Vec<NetworkType>,
    pub invert: bool,
}
