//! Tokio-first DNS subsystem.
//!
//! Configuration, rules, cache, FakeIP, reverse mapping and transports are separate
//! modules. UDP/TCP/DoT/DoH/DoQ are provided by Hickory rather than local protocol code.

mod cache;
mod fake_ip;
mod model;
mod resolver;
mod reverse;
mod subsystem;
mod transport;

pub use cache::CachingResolver;
pub use fake_ip::FakeIpAllocator;
pub use model::*;
pub use resolver::{RuleBasedResolver, StaticResolver};
pub use reverse::{RecordingResolver, ReverseDns};
pub use subsystem::DnsSubsystem;
pub use transport::HickoryTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_types::{Host, IpAddress, IpCidr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn normalizes_dns_names() {
        assert_eq!(
            DnsName::new("Example.TEST.").expect("name").as_str(),
            "example.test"
        );
    }

    #[test]
    fn fake_ip_allocates_stable_answers_and_reverse_mapping() {
        let allocator = FakeIpAllocator::new(FakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddress::V4([198, 18, 0, 0]), 30).expect("cidr"),
            ttl_seconds: 60,
        })
        .expect("allocator");
        let query = DnsQuery {
            name: DnsName::new("example.test").expect("name"),
            record_type: DnsRecordType::A,
        };
        let first = allocator.resolve(query.clone()).expect("first");
        assert_eq!(first, allocator.resolve(query).expect("second"));
        let Host::Ip(address) = first.answers[0].host else {
            panic!("fake ip answer")
        };
        assert_eq!(allocator.lookup(address).as_deref(), Some("example.test"));
    }

    #[test]
    fn dns_rule_matches_suffix_and_record_type() {
        let matcher = DnsRuleMatcher {
            domain_suffixes: vec!["example.test".to_string()],
            record_types: vec![DnsRecordType::A],
            ..DnsRuleMatcher::default()
        };
        assert!(matcher.matches(&DnsQuery {
            name: DnsName::new("www.example.test").expect("name"),
            record_type: DnsRecordType::A
        }));
        assert!(!matcher.matches(&DnsQuery {
            name: DnsName::new("www.example.test").expect("name"),
            record_type: DnsRecordType::Aaaa
        }));
    }

    #[tokio::test]
    async fn cache_resolver_reuses_positive_response() {
        let calls = Arc::new(AtomicUsize::new(0));
        let upstream = CountingResolver::new(calls.clone());
        let cache = CachingResolver::new(
            upstream,
            DnsCacheConfig {
                enabled: true,
                max_entries: 8,
                min_ttl_seconds: 0,
                max_ttl_seconds: 60,
            },
        );
        let query = DnsQuery {
            name: DnsName::new("cache.example").expect("name"),
            record_type: DnsRecordType::A,
        };
        cache.resolve(query.clone()).await.expect("first");
        cache.resolve(query).await.expect("second");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }
    impl CountingResolver {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }
    impl Resolver for CountingResolver {
        async fn resolve(&self, _query: DnsQuery) -> Result<DnsResponse, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(DnsResponse {
                answers: vec![DnsAnswer {
                    host: Host::Ip(IpAddress::V4([203, 0, 113, 1])),
                    ttl_seconds: 30,
                }],
            })
        }
    }
}
