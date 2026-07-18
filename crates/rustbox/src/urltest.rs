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

struct GroupProbe {
    id: OutboundId,
    tag: String,
    children: Vec<(OutboundId, Arc<dyn Outbound>)>,
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
}

impl UrlTestController {
    pub(crate) fn trigger(&self, tag: &str) -> bool {
        self.triggers.get(tag).is_some_and(|trigger| {
            trigger.notify_one();
            true
        })
    }
}

impl UrlTestService {
    pub(crate) fn from_compiled(
        config: &CompiledConfig,
        outbounds: HashMap<OutboundId, Arc<dyn Outbound>>,
        registry: Arc<OutboundGroupRegistry>,
    ) -> Self {
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
                        .filter_map(|id| Some((*id, outbounds.get(id)?.clone())))
                        .collect(),
                    url: url.clone(),
                    interval: Duration::from_secs(*interval_seconds),
                    timeout: Duration::from_secs(*timeout_seconds),
                    concurrency: *concurrency,
                })
            })
            .collect::<Vec<_>>();
        let triggers = groups
            .iter()
            .map(|group| (group.tag.clone(), Arc::new(tokio::sync::Notify::new())))
            .collect();
        Self {
            groups,
            registry,
            controller: UrlTestController {
                triggers: Arc::new(triggers),
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

async fn run_group(group: &GroupProbe, registry: &OutboundGroupRegistry) {
    let semaphore = Arc::new(Semaphore::new(group.concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    for (id, outbound) in &group.children {
        let (id, outbound, url, timeout, semaphore) = (
            *id,
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
            (id, result)
        });
    }
    while let Some(Ok((id, result))) = tasks.join_next().await {
        registry.record_urltest_result(group.id, id, result);
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
