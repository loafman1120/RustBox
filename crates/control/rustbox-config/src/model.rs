use super::*;
use garde::Validate;
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};

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
    #[serde(flatten)]
    #[garde(dive)]
    pub kind: OutboundConfigKind,
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
    },
    /// VMess AEAD 上游代理。
    Vmess {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    /// VLESS 上游代理；当前数据面支持普通 TCP 模式。
    Vless {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    /// Trojan TLS 上游代理。
    Trojan {
        #[serde_as(as = "DisplayFromStr")]
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteActionConfig {
    Outbound(String),
    Reject(RejectReason),
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
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Vec<IpCidr>,
    pub source_ip_cidr: Vec<IpCidr>,
    pub port: Vec<PortRange>,
    pub source_port: Vec<PortRange>,
    pub rule_set: Vec<String>,
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
    pub kind: CompiledOutboundKind,
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
    /// 已分配内部 ID 的手动出站组。当前编译为静态初始选择。
    Selector {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
    },
    /// 已分配内部 ID 的延迟测试出站组。当前编译为静态首选项。
    UrlTest {
        outbounds: Vec<OutboundId>,
        selected: RouteDecision,
        url: String,
        interval_seconds: u64,
        tolerance_ms: u16,
    },
    Vmess {
        server: Endpoint,
        uuid: String,
        security: Option<String>,
        alter_id: Option<u16>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    Vless {
        server: Endpoint,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
    },
    Trojan {
        server: Endpoint,
        password: String,
        tls: Option<OutboundTlsConfig>,
        transport: Option<String>,
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
        decision: RouteDecision,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRouteRuleSet {
    pub id: String,
    pub rules: Vec<CompiledRouteMatcher>,
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
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ip_cidrs: Vec<IpCidr>,
    pub source_ip_cidrs: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub rule_sets: Vec<String>,
    pub invert: bool,
}
