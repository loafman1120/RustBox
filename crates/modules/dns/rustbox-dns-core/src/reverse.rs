use crate::{DnsAnswer, DnsError, DnsQuery, DnsResponse, Resolver};
use rustbox_types::{Host, IpAddress};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::time::{Duration, Instant};

pub struct ReverseDns {
    capacity: usize,
    entries: RwLock<HashMap<IpAddress, ReverseEntry>>,
}
struct ReverseEntry {
    domain: String,
    expires_at: Instant,
}

impl ReverseDns {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: RwLock::new(HashMap::new()),
        }
    }
    pub fn lookup(&self, ip: IpAddress) -> Option<String> {
        self.entries
            .read()
            .expect("reverse DNS read lock")
            .get(&ip)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.domain.clone())
    }
    pub fn record(&self, domain: &str, answers: &[(IpAddress, u32)]) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self.entries.write().expect("reverse DNS write lock");
        for &(ip, ttl) in answers.iter().filter(|(_, ttl)| *ttl > 0) {
            if entries.len() >= self.capacity
                && !entries.contains_key(&ip)
                && let Some(key) = entries.keys().next().copied()
            {
                entries.remove(&key);
            }
            entries.insert(
                ip,
                ReverseEntry {
                    domain: domain.to_string(),
                    expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
                },
            );
        }
    }
    pub fn record_answers(&self, domain: &str, answers: &[DnsAnswer]) {
        let addresses = answers
            .iter()
            .filter_map(|answer| match answer.host {
                Host::Ip(ip) => Some((ip, answer.ttl_seconds)),
                Host::Domain(_) => None,
            })
            .collect::<Vec<_>>();
        self.record(domain, &addresses);
    }
}

pub struct RecordingResolver<R> {
    upstream: R,
    reverse: Arc<ReverseDns>,
}
impl<R> RecordingResolver<R> {
    pub fn new(upstream: R, reverse: Arc<ReverseDns>) -> Self {
        Self { upstream, reverse }
    }
}
impl<R: Resolver> Resolver for RecordingResolver<R> {
    async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        let response = self.upstream.resolve(query.clone()).await?;
        self.reverse
            .record_answers(query.name.as_str(), &response.answers);
        Ok(response)
    }
}
