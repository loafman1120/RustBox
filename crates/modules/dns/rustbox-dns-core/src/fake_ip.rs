use crate::{DnsAnswer, DnsError, DnsQuery, DnsRecordType, DnsResponse, FakeIpConfig};
use rustbox_types::{Host, IpCidr};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::{collections::HashMap, io::Write, path::PathBuf};
use tokio::sync::{Mutex, OnceCell};

#[derive(Debug)]
pub struct FakeIpAllocator {
    ipv4: AddressPool,
    ipv6: Option<AddressPool>,
    ttl_seconds: u32,
    state_file: Option<PathBuf>,
    state: Mutex<FakeIpState>,
    loaded: OnceCell<()>,
}

impl FakeIpAllocator {
    pub fn new(config: FakeIpConfig) -> Result<Self, DnsError> {
        Ok(Self {
            ipv4: AddressPool::new(config.ipv4_pool)?,
            ipv6: config.ipv6_pool.map(AddressPool::new).transpose()?,
            ttl_seconds: config.ttl_seconds,
            state_file: config.state_file,
            state: Mutex::new(FakeIpState::default()),
            loaded: OnceCell::new(),
        })
    }

    pub async fn load(&self) -> Result<(), DnsError> {
        let Some(path) = &self.state_file else {
            return Ok(());
        };
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(DnsError::new(format!("read FakeIP state: {error}"))),
        };
        let saved: PersistedState = serde_json::from_slice(&bytes)
            .map_err(|error| DnsError::new(format!("decode FakeIP state: {error}")))?;
        let mut state = self.state.lock().await;
        state.next_v4 = saved.next_v4;
        state.next_v6 = saved.next_v6;
        for (name, address) in saved.entries {
            if let (Ok(name), Ok(address)) = (crate::DnsName::new(name), address.parse()) {
                state
                    .by_name
                    .insert((name.clone(), family(address)), address);
                state.by_ip.insert(address, name.as_str().to_owned());
            }
        }
        Ok(())
    }

    pub async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        self.loaded
            .get_or_try_init(|| async { self.load().await })
            .await?;
        let (pool, address_family) = match query.record_type {
            DnsRecordType::A => (&self.ipv4, 4),
            DnsRecordType::Aaaa => (
                self.ipv6.as_ref().ok_or_else(|| {
                    DnsError::new("FakeIP AAAA requested but ipv6_pool is not configured")
                })?,
                6,
            ),
            _ => return Ok(DnsResponse::empty()),
        };
        let mut state = self.state.lock().await;
        if let Some(address) = state
            .by_name
            .get(&(query.name.clone(), address_family))
            .copied()
        {
            return Ok(response(address, self.ttl_seconds));
        }
        let offset = if address_family == 4 {
            state.next_v4
        } else {
            state.next_v6
        };
        let address = pool.address_at(offset);
        if address_family == 4 {
            state.next_v4 = pool.next_offset(offset);
        } else {
            state.next_v6 = pool.next_offset(offset);
        }
        let name = query.name.as_str().to_owned();
        state.by_name.insert((query.name, address_family), address);
        state.by_ip.insert(address, name);
        self.persist(&state).await?;
        Ok(response(address, self.ttl_seconds))
    }

    async fn persist(&self, state: &FakeIpState) -> Result<(), DnsError> {
        let Some(path) = &self.state_file else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                DnsError::new(format!("create FakeIP state directory: {error}"))
            })?;
        }
        let saved = PersistedState {
            entries: state
                .by_ip
                .iter()
                .map(|(address, name)| (name.clone(), address.to_string()))
                .collect(),
            next_v4: state.next_v4,
            next_v6: state.next_v6,
        };
        let bytes = serde_json::to_vec(&saved)
            .map_err(|error| DnsError::new(format!("encode FakeIP state: {error}")))?;
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
                .write(|file| file.write_all(&bytes))
        })
        .await
        .map_err(|error| DnsError::new(format!("join FakeIP state write: {error}")))?
        .map_err(|error| DnsError::new(format!("atomically replace FakeIP state: {error}")))
    }

    pub async fn lookup(&self, address: IpAddr) -> Option<String> {
        self.state.lock().await.by_ip.get(&address).cloned()
    }
}

#[derive(Default, Debug)]
struct FakeIpState {
    by_name: HashMap<(crate::DnsName, u8), IpAddr>,
    by_ip: HashMap<IpAddr, String>,
    next_v4: u128,
    next_v6: u128,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    entries: Vec<(String, String)>,
    next_v4: u128,
    next_v6: u128,
}

#[derive(Clone, Copy, Debug)]
struct AddressPool {
    base: u128,
    usable: u128,
    family: u8,
}

impl AddressPool {
    fn new(cidr: IpCidr) -> Result<Self, DnsError> {
        let (address, bits, family) = match cidr.address {
            IpAddr::V4(value) => (u32::from_be_bytes(value.octets()) as u128, 32, 4),
            IpAddr::V6(value) => (u128::from_be_bytes(value.octets()), 128, 6),
        };
        let host_bits = bits - u32::from(cidr.prefix_len);
        if !(2..128).contains(&host_bits) {
            return Err(DnsError::new(
                "FakeIP pool must contain at least two usable addresses",
            ));
        }
        let total = 1u128 << host_bits;
        Ok(Self {
            base: (address & (u128::MAX << host_bits)) + 1,
            usable: total - 2,
            family,
        })
    }
    fn address_at(self, offset: u128) -> IpAddr {
        let value = self.base + offset % self.usable;
        if self.family == 4 {
            IpAddr::V4((value as u32).to_be_bytes().into())
        } else {
            IpAddr::V6(value.to_be_bytes().into())
        }
    }
    fn next_offset(self, offset: u128) -> u128 {
        (offset + 1) % self.usable
    }
}

fn family(address: IpAddr) -> u8 {
    if matches!(address, IpAddr::V4(_)) {
        4
    } else {
        6
    }
}
fn response(address: IpAddr, ttl_seconds: u32) -> DnsResponse {
    DnsResponse {
        answers: vec![DnsAnswer {
            host: Host::Ip(address),
            ttl_seconds,
        }],
        records: Vec::new(),
    }
}
