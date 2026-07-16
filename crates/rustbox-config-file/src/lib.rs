//! TOML and JSON configuration frontends for RustBox.

mod document;
mod error;
mod loader;
mod migration;
mod srs;
mod validation;

pub use document::SUPPORTED_SCHEMA_VERSION;
pub use document::{
    ConfigLoader, FileConfig, FileObservabilityConfig, load_json_file, load_json_source,
    load_toml_file, load_toml_source, parse_json_source, parse_json_str,
    parse_rule_set_rustbox_toml, parse_rule_set_source_json, parse_toml_source, parse_toml_str,
};
pub use error::ConfigFileError;
pub use srs::parse_rule_set_srs;

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_config::{
        DnsRuleAction, DnsServerProtocol, InboundConfigKind, LogicalModeConfig, OutboundConfigKind,
        RouteActionConfig, RouteMatcherConfig, RouteMode, RouteRuleConfig, TransparentNetwork,
        TunDnsMode,
    };
    use rustbox_observability::{LevelFilter, ObservabilityOutput};
    use rustbox_types::Endpoint;
    use rustbox_types::{Host, IpAddress};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::str::FromStr;

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

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"
username = "alice"
password = "secret"

[[outbounds]]
id = "direct"
type = "direct"
dial = { connect_timeout = "5s", tcp_keep_alive = "2m" }

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

[[outbounds]]
id = "select"
type = "selector"
outbounds = ["direct", "block"]
default = "direct"

[[outbounds]]
id = "auto"
type = "urltest"
outbounds = ["direct", "block"]
url = "https://www.gstatic.com/generate_204"
interval_seconds = 300
tolerance_ms = 50

[[outbounds]]
id = "vmess-out"
type = "vmess"
server = "vmess.example.test:443"
uuid = "00000000-0000-0000-0000-000000000001"
security = "auto"
alter_id = 0
transport = "tcp"
tls = { enabled = true, server_name = "vmess.example.test", alpn = ["h2"] }

[[outbounds]]
id = "vless-out"
type = "vless"
server = "vless.example.test:443"
uuid = "00000000-0000-0000-0000-000000000002"
transport = "tcp"
tls = { enabled = true, server_name = "vless.example.test" }

[[outbounds]]
id = "trojan-out"
type = "trojan"
server = "trojan.example.test:443"
password = "test-password"
transport = "tcp"
tls = { enabled = true, server_name = "trojan.example.test" }

[[outbounds]]
id = "anytls-out"
type = "anytls"
server = "anytls.example.test:443"
password = "test-password"
tls = { enabled = true, server_name = "anytls.example.test" }

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse config");

        assert_eq!(config.source.inbounds.len(), 3);
        assert_eq!(config.source.outbounds.len(), 11);
        assert_eq!(
            config.source.outbounds[0].dial.connect_timeout,
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(config.source.routes.len(), 1);
        assert!(matches!(
            &config.source.inbounds[2].kind,
            InboundConfigKind::Mixed {
                username: Some(username),
                password: Some(password),
                ..
            } if username == "alice" && password == "secret"
        ));
        assert!(matches!(
            &config.source.outbounds[2].kind,
            OutboundConfigKind::Block
        ));
        assert!(matches!(
            &config.source.outbounds[3].kind,
            OutboundConfigKind::Http { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[4].kind,
            OutboundConfigKind::Shadowsocks { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[5].kind,
            OutboundConfigKind::Selector { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[6].kind,
            OutboundConfigKind::UrlTest { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[7].kind,
            OutboundConfigKind::Vmess { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[8].kind,
            OutboundConfigKind::Vless { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[9].kind,
            OutboundConfigKind::Trojan { .. }
        ));
        assert!(matches!(
            &config.source.outbounds[10].kind,
            OutboundConfigKind::AnyTls { .. }
        ));
        assert_eq!(
            config.observability.map(|value| (
                value.level,
                value.output,
                value.platform,
                value.remote_endpoint
            )),
            Some((
                Some(LevelFilter::Debug),
                ObservabilityOutput::Console,
                None,
                None
            ))
        );
    }

    #[test]
    fn parses_observability_outputs() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[observability]
level = "info"
output = "console-and-file"
file = "target/rustbox.log"
platform = true
remote_endpoint = "https://telemetry.example.test/rustbox"
"#,
        )
        .expect("parse config");

        let observability = config.observability.expect("observability config");
        assert_eq!(
            observability.output,
            ObservabilityOutput::ConsoleAndFile(PathBuf::from("target/rustbox.log"))
        );
        assert_eq!(observability.platform, Some(true));
        assert_eq!(
            observability.remote_endpoint,
            Some("https://telemetry.example.test/rustbox".to_string())
        );
    }

    #[test]
    fn rejects_invalid_observability_level() {
        let error = parse_toml_str(
            r#"
schema_version = 1
[observability]
level = "loud"
"#,
        )
        .expect_err("invalid level");
        assert!(error.message.contains("invalid observability level"));
    }

    #[test]
    fn garde_rejects_invalid_local_values_with_a_field_path() {
        let error = parse_toml_str(
            r#"
schema_version = 1

[[outbounds]]
id = "auto"
type = "urltest"
outbounds = []
interval_seconds = 0
"#,
        )
        .expect_err("invalid urltest values");

        assert!(error.message.contains("configuration validation failed"));
        assert!(error.message.contains("outbounds[0]"));
        assert!(error.message.contains("interval_seconds"));
    }

    #[test]
    fn figment_reports_the_nested_deserialization_path() {
        let error = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "not-an-endpoint"
"#,
        )
        .expect_err("invalid nested value");

        assert!(error.message.contains("default.inbounds.0"));
        assert!(error.message.contains("not-an-endpoint"));
    }

    #[test]
    fn config_errors_are_miette_diagnostics() {
        fn assert_diagnostic<T: miette::Diagnostic>() {}
        assert_diagnostic::<ConfigFileError>();
    }

    #[test]
    fn validates_observability_output_and_file_as_one_choice() {
        for input in [
            r#"schema_version = 1
[observability]
output = "file"
"#,
            r#"schema_version = 1
[observability]
output = "console"
file = "rustbox.log"
"#,
        ] {
            assert!(parse_toml_str(input).is_err());
        }
    }

    #[test]
    fn parses_route_rules_and_inline_rule_sets() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[outbounds]]
id = "direct"
type = "direct"

[[outbounds]]
id = "block"
type = "block"

[[rule_sets]]
id = "ads"
type = "inline"
rules = [
  { type = "rule", domain_keyword = ["ads"] },
]

[[routes]]
type = "rule"
inbound = ["http"]
network = ["tcp"]
protocol = ["tls", "quic"]
domain_suffix = ["example.test"]
ip_cidr = ["10.0.0.0/8"]
port = [443]
port_range = ["10000-10010"]
rule_set = ["ads"]
outbound = "block"

[[routes]]
type = "logical"
mode = "or"
outbound = "direct"
rules = [
  { type = "rule", domain = ["example.org"] },
  { type = "rule", source_ip_cidr = ["127.0.0.0/8"] },
]
"#,
        )
        .expect("parse route config");

        assert_eq!(config.source.route_rule_sets.len(), 1);
        assert_eq!(config.source.routes.len(), 2);
        assert!(matches!(
            &config.source.routes[0],
            RouteRuleConfig::Rule {
                action: RouteActionConfig::Outbound(outbound),
                matcher: RouteMatcherConfig::Conditions(conditions),
                ..
            } if outbound == "block"
                && conditions.protocol == vec![rustbox_types::ProtocolHint::Tls, rustbox_types::ProtocolHint::Quic]
        ));
        assert!(matches!(
            &config.source.routes[1],
            RouteRuleConfig::Logical {
                mode: LogicalModeConfig::Or,
                ..
            }
        ));
    }

    #[test]
    fn parses_non_final_route_actions() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "route-options"
domain_suffix = ["example.test"]
override_address = "edge.example.test"
override_port = 8443
udp_timeout = "30s"
udp_connect = true

[[routes]]
type = "resolve"
domain_suffix = ["example.test"]
strategy = "prefer-ipv6"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("non-final actions");

        assert!(matches!(
            &config.source.routes[0],
            RouteRuleConfig::Rule {
                action: RouteActionConfig::Options(options),
                ..
            } if options.override_port == Some(8443)
                && options.udp_timeout == Some(std::time::Duration::from_secs(30))
        ));
        assert!(matches!(
            &config.source.routes[1],
            RouteRuleConfig::Rule {
                action: RouteActionConfig::Resolve(_),
                ..
            }
        ));
    }

    #[test]
    fn parses_tun_and_transparent_inbounds() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "tun"
type = "tun"
interface_name = "rustbox0"
addresses = ["172.18.0.1/30"]
mtu = 1500
auto_route = true
route_includes = ["0.0.0.0/0"]
route_excludes = ["127.0.0.0/8"]

[[inbounds]]
id = "transparent"
type = "transparent"
listen = "127.0.0.1:12345"
network = "tcp"
mode = "redirect"
auto_rules = false

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse tun transparent config");

        assert_eq!(config.source.inbounds.len(), 2);
        assert!(matches!(
            &config.source.inbounds[0].kind,
            InboundConfigKind::Tun(value)
                if value.interface_name.as_deref() == Some("rustbox0")
                    && value.auto_route
                    && value.route_mode == RouteMode::Auto
                    && value.dns_mode == TunDnsMode::None
        ));
        assert!(matches!(
            &config.source.inbounds[1].kind,
            InboundConfigKind::Transparent(value)
                if value.listen == Endpoint::localhost_v4(12345)
                    && value.network == TransparentNetwork::Tcp
        ));
    }

    #[test]
    fn parses_dns_config() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"

[[outbounds]]
id = "direct"
type = "direct"

[dns.cache]
enabled = true
max_entries = 256
min_ttl_seconds = 5
max_ttl_seconds = 300

[dns.fake_ip]
enabled = true
ipv4_pool = "198.18.0.0/15"
ttl_seconds = 60

[[dns.servers]]
id = "cf"
protocol = "https"
endpoint = "cloudflare-dns.com:443"
outbound = "direct"

[[dns.rules]]
action = "fake-ip"
domain_suffix = ["example.test"]
record_type = ["a"]

[[dns.hijack]]
network = "udp"
endpoint = "127.0.0.1:53"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse dns config");

        let dns = config.source.dns.expect("dns config");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].protocol, DnsServerProtocol::Https);
        assert_eq!(dns.rules.len(), 1);
        assert!(matches!(dns.rules[0].action(), DnsRuleAction::FakeIp));
        assert_eq!(dns.cache.max_entries, 256);
        assert_eq!(dns.hijack.len(), 1);
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint() {
        let endpoint = Endpoint::from_str("[::1]:1080").expect("parse endpoint");

        assert_eq!(endpoint.port, 1080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V6(Ipv6Addr::LOCALHOST.octets()))
        );
    }

    #[test]
    fn parses_anytls_server_inbound() {
        let config = parse_toml_str(
            r#"
schema_version = 1

[[inbounds]]
id = "anytls-server"
type = "any-tls"
listen = "0.0.0.0:8443"
password = "secret"
tls = { certificate_path = "server.crt", private_key_path = "server.key", alpn = ["h2"] }

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"#,
        )
        .expect("parse AnyTLS inbound");

        assert!(matches!(
            &config.source.inbounds[0].kind,
            InboundConfigKind::AnyTls { password, tls, .. }
                if password == "secret"
                    && tls.certificate_path == "server.crt"
                    && tls.private_key_path == "server.key"
                    && tls.alpn == ["h2"]
        ));
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
        let endpoint = Endpoint::from_str("127.0.0.1:18080").expect("parse endpoint");

        assert_eq!(endpoint.port, 18080);
        assert_eq!(
            endpoint.host,
            Host::Ip(IpAddress::V4(Ipv4Addr::LOCALHOST.octets()))
        );
    }

    #[test]
    fn parses_source_config_without_exposing_file_only_settings() {
        let input = r#"
schema_version = 1

[observability]
level = "debug"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"

[[outbounds]]
id = "direct"
type = "direct"
dial = { connect_timeout = "5s", tcp_keep_alive = "2m" }

[[routes]]
type = "default"
outbound = "direct"
"#;

        let source = parse_toml_source(input).expect("parse source config");
        let file = parse_toml_str(input).expect("parse full file config");

        assert_eq!(source, file.source);
        assert_eq!(source.inbounds.len(), 1);
        assert_eq!(source.outbounds.len(), 1);
    }

    #[test]
    fn parses_json_config_through_serde_entrypoint() {
        let config = parse_json_str(
            r#"{
                "schema_version": 1,
                "inbounds": [
                    {
                        "id": "mixed-in",
                        "type": "mixed",
                        "listen": "127.0.0.1:2080",
                        "username": null,
                        "password": null
                    }
                ],
                "outbounds": [
                    { "id": "direct", "type": "direct" }
                ],
                "routes": [
                    { "type": "default", "outbound": "direct" }
                ]
            }"#,
        )
        .expect("parse JSON config");

        assert!(matches!(
            &config.source.inbounds[0].kind,
            InboundConfigKind::Mixed { listen, .. }
                if *listen == Endpoint::localhost_v4(2080)
        ));
        assert!(matches!(
            &config.source.outbounds[0].kind,
            OutboundConfigKind::Direct
        ));
        assert!(matches!(
            &config.source.routes[0],
            RouteRuleConfig::Default { outbound } if outbound == "direct"
        ));
    }

    #[test]
    fn parses_modern_outbounds_and_shared_multiplex() {
        let config = parse_toml_str(r#"
schema_version = 1

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"

[[outbounds]]
id = "tuic"
type = "tuic"
server = "tuic.example.test:443"
uuid = "00000000-0000-0000-0000-000000000001"
password = "secret"
heartbeat = "5s"
tls = { enabled = true, server_name = "tuic.example.test", alpn = ["h3"] }

[[outbounds]]
id = "wireguard"
type = "wireguard"
addresses = ["10.0.0.2/32"]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
mtu = 1408
peers = [{ server = "192.0.2.1:51820", public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", allowed_ips = ["0.0.0.0/0"], persistent_keepalive = "25s", reserved = [1, 2, 3] }]

[[outbounds]]
id = "shadow"
type = "shadow-tls"
server = "shadow.example.test:443"
version = 3
password = "secret"
tls = { enabled = true, server_name = "www.example.com" }

[[outbounds]]
id = "vmess"
type = "vmess"
server = "vmess.example.test:443"
uuid = "00000000-0000-0000-0000-000000000002"
dial = { multiplex = { enabled = true, protocol = "mux-cool", max_streams = 16, max_connections = 2, buffer_size = 32768 } }

[[routes]]
type = "default"
outbound = "tuic"
"#).expect("parse modern outbounds");

        assert_eq!(config.source.outbounds.len(), 4);
        assert!(matches!(
            config.source.outbounds[0].kind,
            OutboundConfigKind::Tuic { .. }
        ));
        assert!(matches!(
            config.source.outbounds[1].kind,
            OutboundConfigKind::WireGuard { .. }
        ));
        assert!(matches!(
            config.source.outbounds[2].kind,
            OutboundConfigKind::ShadowTls { .. }
        ));
        let multiplex = config.source.outbounds[3]
            .dial
            .multiplex
            .as_ref()
            .expect("multiplex");
        assert_eq!(multiplex.max_streams, 16);
        assert_eq!(multiplex.max_connections, 2);
    }

    #[test]
    fn lowers_wireguard_endpoint_into_the_shared_route_graph() {
        let config = parse_toml_str(r#"
schema_version = 1

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"

[[endpoints]]
id = "wg"
type = "wireguard"
addresses = ["10.0.0.2/32"]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
peers = [{ server = "192.0.2.1:51820", public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", allowed_ips = ["0.0.0.0/0"] }]

[[routes]]
type = "default"
outbound = "wg"
"#).expect("parse endpoint");

        assert_eq!(config.source.outbounds.len(), 1);
        assert_eq!(config.source.outbounds[0].id, "wg");
        assert!(matches!(
            config.source.outbounds[0].kind,
            OutboundConfigKind::WireGuard { .. }
        ));
    }

    #[test]
    fn rejects_outbound_only_protocol_in_endpoint_section() {
        let error = parse_toml_str(
            r#"
schema_version = 1
[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"
[[endpoints]]
id = "direct"
type = "direct"
"#,
        )
        .expect_err("direct is not an endpoint");
        assert!(error.to_string().contains("only `wireguard`"));
    }
}
