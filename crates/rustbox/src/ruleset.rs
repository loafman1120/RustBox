use crate::{ComposeError, routing::route_matcher};
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use rustbox_config::{
    CompiledRouteRuleSet, ConfigError, RouteRuleSetFormat, RouteRuleSetSourceConfig,
    compile_headless_route_matcher,
};
use rustbox_config_file::{
    parse_rule_set_rustbox_toml, parse_rule_set_source_json, parse_rule_set_srs,
};
use rustbox_kernel::{BoxFuture, Service, ServiceContext, ServiceError, TaskScope};
use rustbox_route::{RouteRuleSet, RuleSetStore};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub(crate) struct RuleSetService {
    configured: Vec<CompiledRouteRuleSet>,
    store: RuleSetStore,
}

impl RuleSetService {
    pub(crate) fn new(configured: Vec<CompiledRouteRuleSet>, store: RuleSetStore) -> Self {
        Self { configured, store }
    }
}

impl Service for RuleSetService {
    fn start(&mut self, context: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            start_rule_set_lifecycles(&self.configured, self.store.clone(), &context.session_tasks)
                .map_err(|error| ServiceError::new(format!("rule-set lifecycle: {error:?}")))
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async { Ok(()) })
    }
}

fn start_rule_set_lifecycles(
    configured: &[CompiledRouteRuleSet],
    store: RuleSetStore,
    tasks: &TaskScope,
) -> Result<(), ComposeError> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| {
            ComposeError::Config(ConfigError::new(format!(
                "failed to build rule-set HTTP client: {error}"
            )))
        })?;

    for rule_set in configured {
        match &rule_set.source {
            RouteRuleSetSourceConfig::Inline => {}
            RouteRuleSetSourceConfig::Local {
                path,
                format,
                reload_interval,
            } => tasks.spawn(watch_local_rule_set(
                rule_set.id.clone(),
                PathBuf::from(path),
                *format,
                normalized_interval(*reload_interval),
                store.clone(),
            )),
            RouteRuleSetSourceConfig::Remote {
                url,
                format,
                update_interval,
                cache_path,
            } => tasks.spawn(update_remote_rule_set(
                rule_set.id.clone(),
                url.clone(),
                *format,
                normalized_interval(*update_interval),
                PathBuf::from(cache_path),
                client.clone(),
                store.clone(),
            )),
        }
    }
    Ok(())
}

async fn watch_local_rule_set(
    id: String,
    path: PathBuf,
    format: RouteRuleSetFormat,
    interval: Duration,
    store: RuleSetStore,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut loaded_signature = None;
    loop {
        timer.tick().await;
        let signature = file_signature(&path).await;
        if signature == loaded_signature {
            continue;
        }
        if let Ok(rule_set) = load_file(&path, format).await {
            store.replace(id.clone(), rule_set);
            loaded_signature = signature;
        }
    }
}

async fn update_remote_rule_set(
    id: String,
    url: String,
    format: RouteRuleSetFormat,
    interval: Duration,
    cache_path: PathBuf,
    client: reqwest::Client,
    store: RuleSetStore,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut etag = None;
    let mut last_modified = None;
    loop {
        timer.tick().await;
        let mut request = client.get(&url);
        if let Some(value) = etag.as_ref() {
            request = request.header(IF_NONE_MATCH, value);
        }
        if let Some(value) = last_modified.as_ref() {
            request = request.header(IF_MODIFIED_SINCE, value);
        }
        let Ok(response) = request.send().await else {
            continue;
        };
        if response.status() == StatusCode::NOT_MODIFIED {
            continue;
        }
        let Ok(response) = response.error_for_status() else {
            continue;
        };
        let next_etag = response.headers().get(ETAG).cloned();
        let next_last_modified = response.headers().get(LAST_MODIFIED).cloned();
        let Ok(bytes) = response.bytes().await else {
            continue;
        };
        let Ok(rule_set) = parse_rule_set(&bytes, format) else {
            continue;
        };
        store.replace(id.clone(), rule_set);
        etag = next_etag;
        last_modified = next_last_modified;
        // Cache persistence is durability, not publication: a read-only cache
        // directory must not keep a valid downloaded snapshot out of service.
        let _ = persist_cache(&cache_path, &bytes).await;
    }
}

async fn load_file(path: &Path, format: RouteRuleSetFormat) -> Result<RouteRuleSet, String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    parse_rule_set(&bytes, format)
}

fn parse_rule_set(bytes: &[u8], format: RouteRuleSetFormat) -> Result<RouteRuleSet, String> {
    let text = || {
        std::str::from_utf8(bytes).map_err(|error| format!("rule-set is not valid UTF-8: {error}"))
    };
    let matchers = match format {
        RouteRuleSetFormat::Rustbox => parse_rule_set_rustbox_toml(text()?),
        RouteRuleSetFormat::Source => parse_rule_set_source_json(text()?),
        RouteRuleSetFormat::Binary => {
            parse_rule_set_srs(bytes).map_err(rustbox_config_file::ConfigFileError::new)
        }
    }
    .map_err(|error| error.to_string())?;
    let rules = matchers
        .iter()
        .map(compile_headless_route_matcher)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.message)?
        .iter()
        .map(route_matcher)
        .collect();
    Ok(RouteRuleSet::new(rules))
}

async fn persist_cache(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, bytes).await?;
    if tokio::fs::rename(&temporary, path).await.is_err() {
        let _ = tokio::fs::remove_file(path).await;
        tokio::fs::rename(&temporary, path).await?;
    }
    Ok(())
}

async fn file_signature(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

fn normalized_interval(interval: Duration) -> Duration {
    interval.max(Duration::from_millis(100))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use rustbox_types::{Endpoint, FlowId, FlowMeta, Host, InboundId, Network, PlatformMetadata};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parses_sing_box_source_rule_set() {
        let rules = parse_rule_set(
            br#"{"version":1,"rules":[{"domain_suffix":["example.test"]}]}"#,
            RouteRuleSetFormat::Source,
        )
        .expect("source rule-set");
        assert_eq!(rules.rules.len(), 1);
    }

    #[tokio::test]
    async fn local_rule_set_reloads_after_atomic_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("rules.json");
        tokio::fs::write(
            &path,
            br#"{"version":1,"rules":[{"domain_suffix":["first.test"]}]}"#,
        )
        .await
        .expect("initial rule-set");
        let store = RuleSetStore::new();
        let task = tokio::spawn(watch_local_rule_set(
            "dynamic".into(),
            path.clone(),
            RouteRuleSetFormat::Source,
            Duration::from_millis(20),
            store.clone(),
        ));
        wait_for_match(&store, "first.test").await;

        let replacement = directory.path().join("replacement.json");
        tokio::fs::write(
            &replacement,
            br#"{"version":1,"rules":[{"domain_suffix":["second.test"]}]}"#,
        )
        .await
        .expect("replacement rule-set");
        let _ = tokio::fs::remove_file(&path).await;
        tokio::fs::rename(&replacement, &path)
            .await
            .expect("replace rule-set");
        wait_for_match(&store, "second.test").await;
        task.abort();
    }

    #[tokio::test]
    async fn remote_rule_set_updates_cache_and_keeps_last_valid_snapshot() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (body_tx, body_rx) = tokio::sync::watch::channel(
            br#"{"version":1,"rules":[{"domain_suffix":["remote.test"]}]}"#.to_vec(),
        );
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let body = body_rx.borrow().clone();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(headers.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });

        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("cache/rules.json");
        let store = RuleSetStore::new();
        let task = tokio::spawn(update_remote_rule_set(
            "remote".into(),
            format!("http://{address}/rules.json"),
            RouteRuleSetFormat::Source,
            Duration::from_millis(25),
            cache.clone(),
            reqwest::Client::new(),
            store.clone(),
        ));
        wait_for_match_in(&store, "remote", "remote.test").await;
        let cached = tokio::fs::read_to_string(&cache).await.unwrap();
        assert!(cached.contains("remote.test"));

        body_tx.send_replace(b"not valid JSON".to_vec());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches_domain(&store, "remote", "remote.test"));
        assert_eq!(tokio::fs::read_to_string(&cache).await.unwrap(), cached);
        task.abort();
        server.abort();
    }

    async fn wait_for_match(store: &RuleSetStore, domain: &str) {
        wait_for_match_in(store, "dynamic", domain).await;
    }

    async fn wait_for_match_in(store: &RuleSetStore, id: &str, domain: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches_domain(store, id, domain) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rule-set update timeout");
    }

    fn matches_domain(store: &RuleSetStore, id: &str, domain: &str) -> bool {
        let flow = FlowMeta {
            id: FlowId::new(NonZeroU64::new(1).unwrap()),
            network: Network::Tcp,
            source: Endpoint::localhost_v4(1000),
            destination: Endpoint::new(Host::domain(domain), 443),
            inbound: InboundId::new(NonZeroU64::new(1).unwrap()),
            domain: Some(Host::domain(domain)),
            protocol_hint: None,
            platform: PlatformMetadata::default(),
        };
        let snapshot = store.snapshot();
        snapshot
            .get(id)
            .is_some_and(|rules| rules.matches(&flow, &snapshot))
    }
}
