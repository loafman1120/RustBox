use rustbox_config::{CompiledConfig, CompiledOutboundKind};
use rustbox_control::OutboundGroupRegistry;
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, Service, ServiceContext, ServiceError};
use rustbox_transport::{TlsLayerConfig, rustls_client_config};
use rustbox_types::{Endpoint, Host, OutboundId};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsConnector, rustls::pki_types::ServerName};

#[derive(Clone)]
struct GroupProbe {
    id: OutboundId,
    tag: String,
    children: Vec<(OutboundId, String, Arc<dyn Outbound>)>,
    url: String,
    interval: Duration,
    timeout: Duration,
    concurrency: usize,
}

pub(crate) struct UrlTestService {
    groups: Vec<GroupProbe>,
    registry: Arc<OutboundGroupRegistry>,
    controller: UrlTestController,
}

#[derive(Clone, Default)]
pub(crate) struct UrlTestController {
    triggers: Arc<HashMap<String, Arc<tokio::sync::Notify>>>,
    groups: Arc<HashMap<String, GroupProbe>>,
    outbounds: Arc<HashMap<String, Arc<dyn Outbound>>>,
    registry: Arc<OutboundGroupRegistry>,
}

impl UrlTestController {
    pub(crate) fn trigger(&self, tag: &str) -> bool {
        self.triggers.get(tag).is_some_and(|trigger| {
            trigger.notify_one();
            true
        })
    }

    pub(crate) async fn probe(
        &self,
        tag: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<u32, String> {
        let outbound = self
            .outbounds
            .get(tag)
            .cloned()
            .ok_or_else(|| format!("outbound `{tag}` not found"))?;
        let delay = tokio::time::timeout(timeout, probe(outbound, url))
            .await
            .map_err(|_| format!("probe timed out after {} ms", timeout.as_millis()))??;
        Ok(delay.as_millis().min(u32::MAX as u128) as u32)
    }

    pub(crate) async fn probe_group(
        &self,
        tag: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<std::collections::BTreeMap<String, u32>, String> {
        let mut group = self
            .groups
            .get(tag)
            .cloned()
            .ok_or_else(|| format!("URLTest group `{tag}` not found"))?;
        if !url.is_empty() {
            group.url = url.to_string();
        }
        group.timeout = timeout;
        Ok(run_group(&group, &self.registry).await)
    }
}

impl UrlTestService {
    pub(crate) fn from_compiled(
        config: &CompiledConfig,
        outbounds: HashMap<OutboundId, Arc<dyn Outbound>>,
        registry: Arc<OutboundGroupRegistry>,
    ) -> Self {
        let tags = config
            .outbounds
            .iter()
            .map(|outbound| (outbound.id, outbound.logical_id.clone()))
            .collect::<HashMap<_, _>>();
        let groups = config
            .outbounds
            .iter()
            .filter_map(|outbound| {
                let CompiledOutboundKind::UrlTest {
                    outbounds: children,
                    url,
                    interval_seconds,
                    timeout_seconds,
                    concurrency,
                    ..
                } = &outbound.kind
                else {
                    return None;
                };
                Some(GroupProbe {
                    id: outbound.id,
                    tag: outbound.logical_id.clone(),
                    children: children
                        .iter()
                        .filter_map(|id| {
                            Some((*id, tags.get(id)?.clone(), outbounds.get(id)?.clone()))
                        })
                        .collect(),
                    url: url.clone(),
                    interval: Duration::from_secs(*interval_seconds),
                    timeout: Duration::from_secs(*timeout_seconds),
                    concurrency: *concurrency,
                })
            })
            .collect::<Vec<_>>();
        let outbound_by_tag = config
            .outbounds
            .iter()
            .filter_map(|outbound| {
                Some((
                    outbound.logical_id.clone(),
                    outbounds.get(&outbound.id)?.clone(),
                ))
            })
            .collect::<HashMap<_, _>>();
        let triggers = groups
            .iter()
            .map(|group| (group.tag.clone(), Arc::new(tokio::sync::Notify::new())))
            .collect();
        let mut controller_groups = groups
            .iter()
            .cloned()
            .map(|group| (group.tag.clone(), group))
            .collect::<HashMap<_, _>>();
        for outbound in &config.outbounds {
            let CompiledOutboundKind::Selector {
                outbounds: children,
                ..
            } = &outbound.kind
            else {
                continue;
            };
            controller_groups.insert(
                outbound.logical_id.clone(),
                GroupProbe {
                    id: outbound.id,
                    tag: outbound.logical_id.clone(),
                    children: children
                        .iter()
                        .filter_map(|id| {
                            Some((*id, tags.get(id)?.clone(), outbounds.get(id)?.clone()))
                        })
                        .collect(),
                    url: "http://www.gstatic.com/generate_204".to_string(),
                    interval: Duration::from_secs(300),
                    timeout: Duration::from_secs(5),
                    concurrency: 4,
                },
            );
        }
        Self {
            groups,
            registry: registry.clone(),
            controller: UrlTestController {
                triggers: Arc::new(triggers),
                groups: Arc::new(controller_groups),
                outbounds: Arc::new(outbound_by_tag),
                registry: registry.clone(),
            },
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub(crate) fn controller(&self) -> UrlTestController {
        self.controller.clone()
    }
}

impl Service for UrlTestService {
    fn start(&mut self, ctx: ServiceContext) -> BoxFuture<'_, Result<(), ServiceError>> {
        for group in self.groups.drain(..) {
            let registry = self.registry.clone();
            let trigger = self.controller.triggers.get(&group.tag).cloned();
            ctx.accept_tasks.spawn(async move {
                loop {
                    run_group(&group, &registry).await;
                    if let Some(trigger) = &trigger {
                        tokio::select! {
                            _ = tokio::time::sleep(group.interval) => {}
                            _ = trigger.notified() => {}
                        }
                    } else {
                        tokio::time::sleep(group.interval).await;
                    }
                }
            });
        }
        Box::pin(async { Ok(()) })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), ServiceError>> {
        Box::pin(async { Ok(()) })
    }
}

async fn run_group(
    group: &GroupProbe,
    registry: &OutboundGroupRegistry,
) -> std::collections::BTreeMap<String, u32> {
    let semaphore = Arc::new(Semaphore::new(group.concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    for (id, tag, outbound) in &group.children {
        let (id, tag, outbound, url, timeout, semaphore) = (
            *id,
            tag.clone(),
            outbound.clone(),
            group.url.clone(),
            group.timeout,
            semaphore.clone(),
        );
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let result = tokio::time::timeout(timeout, probe(outbound, &url))
                .await
                .map_err(|_| format!("probe timed out after {} ms", timeout.as_millis()))
                .and_then(|value| value);
            (id, tag, result)
        });
    }
    let mut delays = std::collections::BTreeMap::new();
    while let Some(Ok((id, tag, result))) = tasks.join_next().await {
        if let Ok(delay) = &result {
            delays.insert(tag, delay.as_millis().min(u32::MAX as u128) as u32);
        }
        registry.record_urltest_result(group.id, id, result);
    }
    // Registry snapshots contain the user-facing tags, unlike internal IDs.
    if let Some(snapshot) = registry
        .list()
        .into_iter()
        .find(|value| value.tag == group.tag)
    {
        let registry_delays = snapshot
            .items
            .into_iter()
            .filter_map(|item| item.url_test_delay.map(|delay| (item.tag, delay)))
            .collect::<std::collections::BTreeMap<_, _>>();
        if !registry_delays.is_empty() {
            delays = registry_delays;
        }
    }
    delays
}

impl rustbox_control_service::OutboundProbe for UrlTestController {
    fn probe<'a>(
        &'a self,
        tag: &'a str,
        url: &'a str,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32, String>> + Send + 'a>> {
        Box::pin(async move { UrlTestController::probe(self, tag, url, timeout).await })
    }

    fn probe_group<'a>(
        &'a self,
        tag: &'a str,
        url: &'a str,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<std::collections::BTreeMap<String, u32>, String>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { UrlTestController::probe_group(self, tag, url, timeout).await })
    }
}

async fn probe(outbound: Arc<dyn Outbound>, url: &str) -> Result<Duration, String> {
    let url = reqwest::Url::parse(url).map_err(|e| format!("invalid probe URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "probe URL has no host".to_string())?
        .to_string();
    let tls = url.scheme() == "https";
    if !tls && url.scheme() != "http" {
        return Err(format!("unsupported probe URL scheme `{}`", url.scheme()));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "probe URL has no port".to_string())?;
    let endpoint = Endpoint::new(Host::Domain(host.clone()), port);
    let started = Instant::now();
    let stream = outbound
        .open_stream(OutboundContext::background(), endpoint)
        .await
        .map_err(|e| format!("connect failed: {}", e.message))?;
    let mut stream: Box<dyn rustbox_io::ByteStream> = if tls {
        let config = rustls_client_config(&TlsLayerConfig {
            enabled: true,
            server_name: Some(host.clone()),
            ..Default::default()
        })
        .map_err(|e| format!("TLS config failed: {}", e.message))?;
        let name =
            ServerName::try_from(host.clone()).map_err(|e| format!("invalid TLS name: {e}"))?;
        Box::new(
            TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await
                .map_err(|e| format!("TLS handshake failed: {e}"))?,
        )
    } else {
        stream
    };
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: RustBox-URLTest/1\r\n\r\n").as_bytes())
        .await.map_err(|e| format!("request failed: {e}"))?;
    let status = read_status(&mut stream).await?;
    if !(200..400).contains(&status) {
        return Err(format!("HTTP status {status}"));
    }
    Ok(started.elapsed())
}

async fn read_status(stream: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u16, String> {
    let mut buf = [0u8; 1024];
    let count = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("response failed: {e}"))?;
    let line = std::str::from_utf8(&buf[..count])
        .map_err(|_| "response status is not UTF-8".to_string())?
        .lines()
        .next()
        .ok_or_else(|| "empty HTTP response".to_string())?;
    line.split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed HTTP status".to_string())?
        .parse()
        .map_err(|_| "malformed HTTP status code".to_string())
}
