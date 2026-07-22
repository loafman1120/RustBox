use rustbox_config::{OutboundConfigKind, RouteRuleConfig};
use rustbox_config_file::load_config_source;

#[test]
fn composes_the_mihomo_reference_fixture_through_format_detection() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mihomo-reference.yaml");
    let source = load_config_source(path).expect("normalize Mihomo reference fixture");

    assert_eq!(source.inbounds.len(), 1);
    assert_eq!(source.outbounds.len(), 5);
    assert_eq!(source.routes.len(), 9);
    assert!(matches!(
        source.outbounds[2].kind,
        OutboundConfigKind::Shadowsocks { .. }
    ));
    assert!(matches!(
        source.outbounds[3].kind,
        OutboundConfigKind::Selector { .. }
    ));
    assert!(matches!(
        source.outbounds[4].kind,
        OutboundConfigKind::UrlTest { .. }
    ));
    assert!(matches!(
        source.routes.last(),
        Some(RouteRuleConfig::Default { outbound }) if outbound == "proxy"
    ));
}
