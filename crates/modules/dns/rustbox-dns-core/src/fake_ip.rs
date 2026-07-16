use crate::{DnsAnswer, DnsError, DnsQuery, DnsRecordType, DnsResponse, FakeIpConfig};
use rustbox_types::{Host, IpAddress, IpCidr};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct FakeIpAllocator {
    pool: Ipv4Pool,
    ttl_seconds: u32,
    state: Mutex<FakeIpState>,
}

impl FakeIpAllocator {
    pub fn new(config: FakeIpConfig) -> Result<Self, DnsError> {
        Ok(Self {
            pool: Ipv4Pool::new(config.ipv4_pool)?,
            ttl_seconds: config.ttl_seconds,
            state: Mutex::new(FakeIpState::default()),
        })
    }
    pub fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        if query.record_type != DnsRecordType::A {
            return Ok(DnsResponse::empty());
        }
        let mut state = self.state.lock().expect("fake-ip lock");
        if let Some(address) = state.by_name.get(&query.name).copied() {
            return Ok(response(address, self.ttl_seconds));
        }
        let address = self.pool.address_at(state.next_offset)?;
        state.next_offset = self.pool.next_offset(state.next_offset);
        let name = query.name.as_str().to_string();
        state.by_name.insert(query.name, address);
        state.by_ip.insert(address, name);
        Ok(response(address, self.ttl_seconds))
    }
    pub fn lookup(&self, address: IpAddress) -> Option<String> {
        self.state
            .lock()
            .expect("fake-ip lock")
            .by_ip
            .get(&address)
            .cloned()
    }
}

#[derive(Default, Debug)]
struct FakeIpState {
    by_name: HashMap<crate::DnsName, IpAddress>,
    by_ip: HashMap<IpAddress, String>,
    next_offset: u32,
}

#[derive(Clone, Copy, Debug)]
struct Ipv4Pool {
    base: u32,
    usable: u32,
}
impl Ipv4Pool {
    fn new(cidr: IpCidr) -> Result<Self, DnsError> {
        let IpAddress::V4(octets) = cidr.address else {
            return Err(DnsError::new("fake-ip currently supports only IPv4 pools"));
        };
        if cidr.prefix_len > 30 {
            return Err(DnsError::new(
                "fake-ip IPv4 pool must contain at least two usable addresses",
            ));
        }
        let address = u32::from_be_bytes(octets);
        let mask = u32::MAX << (32 - cidr.prefix_len);
        let total = 1u32 << (32 - cidr.prefix_len);
        Ok(Self {
            base: (address & mask).saturating_add(1),
            usable: total.saturating_sub(2),
        })
    }
    fn address_at(self, offset: u32) -> Result<IpAddress, DnsError> {
        if self.usable == 0 {
            return Err(DnsError::new("fake-ip pool is empty"));
        }
        Ok(IpAddress::V4(
            self.base.saturating_add(offset % self.usable).to_be_bytes(),
        ))
    }
    fn next_offset(self, offset: u32) -> u32 {
        (offset + 1) % self.usable
    }
}
fn response(address: IpAddress, ttl_seconds: u32) -> DnsResponse {
    DnsResponse {
        answers: vec![DnsAnswer {
            host: Host::Ip(address),
            ttl_seconds,
        }],
    }
}
