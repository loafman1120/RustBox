use crate::ComposeError;
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use rustbox_config::{
    CompiledRouteRuleSet, ConfigError, RouteRuleSetFormat, RouteRuleSetSourceConfig,
    compile_headless_route_matcher,
};
use rustbox_config_file::{
    parse_rule_set_rustbox_toml, parse_rule_set_source_json, parse_rule_set_srs,
};
use rustbox_control::RuleSetRegistry;
use rustbox_kernel::{BoxFuture, Service, ServiceContext, ServiceError, TaskScope};
use rustbox_route::{RouteRuleSet, RuleSetStore};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub(crate) struct RuleSetService {
    configured: Vec<CompiledRouteRuleSet>,
    store: RuleSetStore,
    controller: RuleSetController,
}

#[derive(Clone, Default)]
pub(crate) struct RuleSetController {
    registry: Arc<RuleSetRegistry>,
    triggers: Arc<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl RuleSetController {
    pub(crate) fn registry(&self) -> Arc<RuleSetRegistry> {
        self.registry.clone()
    }

    pub(crate) fn refresh(&self, tag: &str) -> bool {
        self.triggers.get(tag).is_some_and(|trigger| {
            trigger.notify_one();
            true
        })
    }
}

impl RuleSetService {
    pub(crate) fn new(configured: Vec<CompiledRouteRuleSet>, store: RuleSetStore) -> Self {
        let registry = Arc::new(RuleSetRegistry::default());
        let mut triggers = std::collections::HashMap::new();
        for rule_set in &configured {
            let source = match &rule_set.source {
                RouteRuleSetSourceConfig::Inline => "inline",
                RouteRuleSetSourceConfig::Local { .. } => "local",
                RouteRuleSetSourceConfig::Remote { .. } => "remote",
            };
            registry.configure(rule_set.id.clone(), source);
            if matches!(rule_set.source, RouteRuleSetSourceConfig::Inline) {
                registry.succeeded(&rule_set.id);
            }
            if !matches!(rule_set.source, RouteRuleSetSourceConfig::Inline) {
                triggers.insert(rule_set.id.clone(), Arc::new(tokio::sync::Notify::new()));
            }
        }
        Self {
            configured,
            store,
            controller: RuleSetController {
                registry,
                triggers: Arc::new(triggers),
            },
        }
    }

    pub(crate) fn controller(&self) -> RuleSetController {
        self.controller.clone()
    }
}

impl Service for RuleSetService {
    fn start(&mut self, context: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async move {
            start_rule_set_lifecycles(
                &self.configured,
                self.store.clone(),
                &context.session_tasks,
                &self.controller,
            )
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
    controller: &RuleSetController,
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
                controller.registry.clone(),
                controller
                    .triggers
                    .get(&rule_set.id)
                    .cloned()
                    .expect("local trigger"),
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
                UpdateContext {
                    client: client.clone(),
                    store: store.clone(),
                    registry: controller.registry.clone(),
                    trigger: controller
                        .triggers
                        .get(&rule_set.id)
                        .cloned()
                        .expect("remote trigger"),
                },
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
    registry: Arc<RuleSetRegistry>,
    trigger: Arc<tokio::sync::Notify>,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut loaded_signature = None;
    loop {
        let forced = tokio::select! {
            _ = timer.tick() => false,
            _ = trigger.notified() => true,
        };
        let signature = file_signature(&path).await;
        if !forced && signature == loaded_signature {
            continue;
        }
        registry.updating(&id);
        match load_file(&path, format).await {
            Ok(rule_set) => {
                store.replace(id.clone(), rule_set);
                loaded_signature = signature;
                registry.succeeded(&id);
            }
            Err(error) => registry.failed(&id, error),
        }
    }
}

struct UpdateContext {
    client: reqwest::Client,
    store: RuleSetStore,
    registry: Arc<RuleSetRegistry>,
    trigger: Arc<tokio::sync::Notify>,
}

async fn update_remote_rule_set(
    id: String,
    url: String,
    format: RouteRuleSetFormat,
    interval: Duration,
    cache_path: PathBuf,
    ctx: UpdateContext,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut etag = None;
    let mut last_modified = None;
    loop {
        tokio::select! {
            _ = timer.tick() => {}
            _ = ctx.trigger.notified() => {}
        }
        ctx.registry.updating(&id);
        let mut request = ctx.client.get(&url);
        if let Some(value) = etag.as_ref() {
            request = request.header(IF_NONE_MATCH, value);
        }
        if let Some(value) = last_modified.as_ref() {
            request = request.header(IF_MODIFIED_SINCE, value);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                ctx.registry.failed(&id, error.to_string());
                continue;
            }
        };
        if response.status() == StatusCode::NOT_MODIFIED {
            ctx.registry.succeeded(&id);
            continue;
        }
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                ctx.registry.failed(&id, error.to_string());
                continue;
            }
        };
        let next_etag = response.headers().get(ETAG).cloned();
        let next_last_modified = response.headers().get(LAST_MODIFIED).cloned();
        let bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                ctx.registry.failed(&id, error.to_string());
                continue;
            }
        };
        let rule_set = match parse_rule_set(&bytes, format) {
            Ok(rule_set) => rule_set,
            Err(error) => {
                ctx.registry.failed(&id, error);
                continue;
            }
        };
        ctx.store.replace(id.clone(), rule_set);
        ctx.registry.succeeded(&id);
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
        .map_err(|error| error.message)?;
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
            Arc::new(RuleSetRegistry::default()),
            Arc::new(tokio::sync::Notify::new()),
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
            UpdateContext {
                client: reqwest::Client::new(),
                store: store.clone(),
                registry: Arc::new(RuleSetRegistry::default()),
                trigger: Arc::new(tokio::sync::Notify::new()),
            },
        ));
        wait_for_match_in(&store, "remote", "remote.test").await;
        let cached = wait_for_file_content(&cache, "remote.test").await;
        assert!(cached.contains("remote.test"));

        body_tx.send_replace(b"not valid JSON".to_vec());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches_domain(&store, "remote", "remote.test"));
        assert_eq!(tokio::fs::read_to_string(&cache).await.unwrap(), cached);
        task.abort();
        let _ = task.await;
        server.abort();
        let _ = server.await;
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

    async fn wait_for_file_content(path: &Path, expected: &str) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(content) = tokio::fs::read_to_string(path).await
                    && content.contains(expected)
                {
                    return content;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rule-set cache persistence timeout")
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
