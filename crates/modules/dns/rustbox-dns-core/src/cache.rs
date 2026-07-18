use crate::{DnsCacheConfig, DnsError, DnsQuery, DnsResponse, Resolver};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::time::{Duration, Instant};

pub struct CachingResolver<R> {
    upstream: R,
    enabled: bool,
    max_entries: usize,
    min_ttl_seconds: u32,
    max_ttl_seconds: u32,
    entries: Mutex<HashMap<DnsQuery, CachedResponse>>,
}

impl<R> CachingResolver<R> {
    pub fn new(upstream: R, config: DnsCacheConfig) -> Self {
        Self {
            upstream,
            enabled: config.enabled,
            max_entries: config.max_entries,
            min_ttl_seconds: config.min_ttl_seconds,
            max_ttl_seconds: config.max_ttl_seconds,
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<R: Resolver> Resolver for CachingResolver<R> {
    async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        if !self.enabled {
            return self.upstream.resolve(query).await;
        }
        let now = Instant::now();
        if let Some(hit) = self
            .entries
            .lock()
            .expect("cache lock")
            .get(&query)
            .filter(|hit| hit.expires_at > now)
        {
            return Ok(hit.response.clone());
        }
        let response = self.upstream.resolve(query.clone()).await?;
        let ttl = response
            .answers
            .iter()
            .map(|answer| answer.ttl_seconds)
            .chain(response.records.iter().map(|record| record.ttl()))
            .min()
            .unwrap_or(0)
            .clamp(self.min_ttl_seconds, self.max_ttl_seconds);
        if ttl > 0 && self.max_entries > 0 {
            let mut entries = self.entries.lock().expect("cache lock");
            if entries.len() >= self.max_entries
                && let Some(key) = entries.keys().next().cloned()
            {
                entries.remove(&key);
            }
            entries.insert(
                query,
                CachedResponse {
                    response: response.clone(),
                    expires_at: now + Duration::from_secs(u64::from(ttl)),
                },
            );
        }
        Ok(response)
    }
}

struct CachedResponse {
    response: DnsResponse,
    expires_at: Instant,
}
