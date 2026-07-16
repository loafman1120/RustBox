//! Decoder for the public sing-box SRS wire format.
//!
//! This is an independent Rust implementation.  It intentionally recovers the
//! compiled matchers into RustBox's ordinary route model so source and binary
//! rule sets share the same compiler and runtime matcher.

use flate2::read::ZlibDecoder;
use rustbox_config::{LogicalModeConfig, RouteMatchConfig, RouteMatcherConfig};
use rustbox_types::{IpAddress, IpCidr, Network, NetworkType, PortRange};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAGIC: &[u8; 3] = b"SRS";
const FINAL: u8 = 0xff;
const MAX_ITEMS: usize = 16_000_000;

pub fn parse_rule_set_srs(bytes: &[u8]) -> Result<Vec<RouteMatcherConfig>, String> {
    if bytes.len() < 4 || &bytes[..3] != MAGIC {
        return Err("invalid sing-box SRS magic".into());
    }
    let version = bytes[3];
    if version > 5 {
        return Err(format!("unsupported sing-box SRS version {version}"));
    }
    let mut decoder = ZlibDecoder::new(&bytes[4..]);
    let mut payload = Vec::new();
    decoder
        .read_to_end(&mut payload)
        .map_err(|error| format!("invalid SRS zlib payload: {error}"))?;
    let mut reader = BinaryReader::new(&payload);
    let count = reader.length("rule count")?;
    let mut rules = Vec::with_capacity(count.min(4096));
    for index in 0..count {
        rules.push(
            reader
                .rule()
                .map_err(|error| format!("rule[{index}]: {error}"))?,
        );
    }
    if !reader.is_empty() {
        return Err("trailing data after SRS rules".into());
    }
    Ok(rules)
}

struct BinaryReader<'a> {
    inner: Cursor<&'a [u8]>,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: Cursor::new(bytes),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.position() as usize == self.inner.get_ref().len()
    }

    fn byte(&mut self) -> Result<u8, String> {
        let mut byte = [0];
        self.inner.read_exact(&mut byte).map_err(io_error)?;
        Ok(byte[0])
    }

    fn bool(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(format!("invalid boolean byte {value}")),
        }
    }

    fn u16(&mut self) -> Result<u16, String> {
        let mut bytes = [0; 2];
        self.inner.read_exact(&mut bytes).map_err(io_error)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let mut bytes = [0; 8];
        self.inner.read_exact(&mut bytes).map_err(io_error)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            if shift == 63 && byte > 1 {
                return Err("uvarint overflow".into());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("uvarint overflow".into())
    }

    fn length(&mut self, label: &str) -> Result<usize, String> {
        let value = usize::try_from(self.varint()?).map_err(|_| format!("{label} is too large"))?;
        if value > MAX_ITEMS {
            return Err(format!("{label} exceeds safety limit"));
        }
        Ok(value)
    }

    fn bytes(&mut self, label: &str) -> Result<Vec<u8>, String> {
        let length = self.length(label)?;
        let mut bytes = vec![0; length];
        self.inner.read_exact(&mut bytes).map_err(io_error)?;
        Ok(bytes)
    }

    fn strings(&mut self) -> Result<Vec<String>, String> {
        let count = self.length("string count")?;
        (0..count)
            .map(|_| {
                String::from_utf8(self.bytes("string length")?)
                    .map_err(|error| format!("invalid UTF-8 string: {error}"))
            })
            .collect()
    }

    fn u16s(&mut self) -> Result<Vec<u16>, String> {
        let count = self.length("u16 count")?;
        (0..count).map(|_| self.u16()).collect()
    }

    fn u8s(&mut self) -> Result<Vec<u8>, String> {
        let count = self.length("u8 count")?;
        (0..count).map(|_| self.byte()).collect()
    }

    fn rule(&mut self) -> Result<RouteMatcherConfig, String> {
        match self.byte()? {
            0 => self.default_rule(),
            1 => self.logical_rule(),
            value => Err(format!("unknown SRS rule type {value}")),
        }
    }

    fn logical_rule(&mut self) -> Result<RouteMatcherConfig, String> {
        let mode = match self.byte()? {
            0 => LogicalModeConfig::And,
            1 => LogicalModeConfig::Or,
            value => return Err(format!("unknown logical mode {value}")),
        };
        let count = self.length("logical rule count")?;
        let rules = (0..count).map(|_| self.rule()).collect::<Result<_, _>>()?;
        let invert = self.bool()?;
        Ok(RouteMatcherConfig::Logical {
            mode,
            rules,
            invert,
        })
    }

    fn default_rule(&mut self) -> Result<RouteMatcherConfig, String> {
        let mut rule = RouteMatchConfig::default();
        loop {
            match self.byte()? {
                0 => {
                    // DNS query types do not apply to RustBox transport flows, but the
                    // payload still has to be consumed. Rejecting avoids widening rules.
                    let values = self.u16s()?;
                    if !values.is_empty() {
                        return Err(
                            "DNS query_type SRS rules are not valid transport route rules".into(),
                        );
                    }
                }
                1 => {
                    rule.network = self
                        .strings()?
                        .into_iter()
                        .map(parse_network)
                        .collect::<Result<_, _>>()?
                }
                2 => {
                    let (domain, suffix) = self.domain_matcher()?;
                    rule.domain.extend(domain);
                    rule.domain_suffix.extend(suffix);
                }
                3 => rule.domain_keyword = self.strings()?,
                4 => rule.domain_regex = self.strings()?,
                5 => rule.source_ip_cidr = self.ip_set()?,
                6 => rule.ip_cidr = self.ip_set()?,
                7 => rule
                    .source_port
                    .extend(self.u16s()?.into_iter().map(PortRange::single)),
                8 => rule.source_port.extend(parse_port_ranges(self.strings()?)?),
                9 => rule
                    .port
                    .extend(self.u16s()?.into_iter().map(PortRange::single)),
                10 => rule.port.extend(parse_port_ranges(self.strings()?)?),
                11 => rule.process_name = self.strings()?,
                12 => rule.process_path = self.strings()?,
                13 => rule.package_name = self.strings()?,
                14 => rule.wifi_ssid = self.strings()?,
                15 => rule.wifi_bssid = self.strings()?,
                16 => {
                    return Err(
                        "AdGuard-domain SRS matcher is not supported in transport routing".into(),
                    );
                }
                17 => return Err("process_path_regex SRS matcher is not supported".into()),
                18 => {
                    rule.network_type = self
                        .u8s()?
                        .into_iter()
                        .map(parse_network_type)
                        .collect::<Result<_, _>>()?
                }
                19 => {
                    return Err(
                        "network_is_expensive SRS matcher is unsupported by FlowMeta".into(),
                    );
                }
                20 => {
                    return Err(
                        "network_is_constrained SRS matcher is unsupported by FlowMeta".into(),
                    );
                }
                21 => {
                    return Err(
                        "network_interface_address SRS matcher is unsupported by FlowMeta".into(),
                    );
                }
                22 => {
                    return Err(
                        "default_interface_address SRS matcher is unsupported by FlowMeta".into(),
                    );
                }
                23 => return Err("package_name_regex SRS matcher is not supported".into()),
                FINAL => {
                    rule.invert = self.bool()?;
                    return Ok(RouteMatcherConfig::Conditions(Box::new(rule)));
                }
                value => return Err(format!("unknown SRS rule item {value}")),
            }
        }
    }

    fn domain_matcher(&mut self) -> Result<(Vec<String>, Vec<String>), String> {
        if self.byte()? != 0 {
            return Err("unsupported succinct domain matcher version".into());
        }
        let leaves = self.u64s()?;
        let bitmap = self.u64s()?;
        let labels = self.bytes("domain matcher labels")?;
        let keys = succinct_keys(&leaves, &bitmap, &labels)?;
        let mut domains = Vec::new();
        let mut suffixes = Vec::new();
        for mut key in keys {
            key.reverse();
            let value =
                String::from_utf8(key).map_err(|_| "domain matcher contains invalid UTF-8")?;
            if let Some(value) = value.strip_prefix('\r') {
                suffixes.push(value.trim_start_matches('.').to_string());
            } else if let Some(value) = value.strip_prefix('\n') {
                suffixes.push(value.to_string());
            } else {
                domains.push(value);
            }
        }
        Ok((domains, suffixes))
    }

    fn u64s(&mut self) -> Result<Vec<u64>, String> {
        let count = self.length("u64 count")?;
        (0..count).map(|_| self.u64()).collect()
    }

    fn ip_set(&mut self) -> Result<Vec<IpCidr>, String> {
        if self.byte()? != 1 {
            return Err("unsupported SRS IP-set version".into());
        }
        let count = usize::try_from(self.u64()?).map_err(|_| "IP range count is too large")?;
        if count > MAX_ITEMS {
            return Err("IP range count exceeds safety limit".into());
        }
        let mut result = Vec::new();
        for _ in 0..count {
            let start = parse_ip(self.bytes("IP range start")?)?;
            let end = parse_ip(self.bytes("IP range end")?)?;
            result.extend(range_to_cidrs(start, end)?);
        }
        Ok(result)
    }
}

fn get_bit(words: &[u64], index: usize) -> Result<bool, String> {
    words
        .get(index / 64)
        .map(|word| word & (1_u64 << (index % 64)) != 0)
        .ok_or_else(|| "truncated succinct bitmap".into())
}

fn succinct_keys(leaves: &[u64], bitmap: &[u64], labels: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    // LOUDS nodes are in breadth-first order. Every node owns a zero-labelled
    // edge run terminated by one; children therefore receive consecutive IDs.
    let mut child_labels = Vec::<Vec<u8>>::new();
    let mut bit = 0_usize;
    let mut label = 0_usize;
    while label < labels.len() {
        let mut children = Vec::new();
        while !get_bit(bitmap, bit)? {
            children.push(*labels.get(label).ok_or("truncated succinct labels")?);
            label += 1;
            bit += 1;
        }
        bit += 1;
        child_labels.push(children);
    }
    while child_labels.len() <= labels.len() {
        let mut children = Vec::new();
        while !get_bit(bitmap, bit)? {
            children.push(*labels.get(label).ok_or("truncated succinct labels")?);
            label += 1;
            bit += 1;
        }
        bit += 1;
        child_labels.push(children);
    }
    let mut paths = vec![Vec::new(); labels.len() + 1];
    let mut next_child = 1_usize;
    for node in 0..paths.len() {
        let base = paths[node].clone();
        for edge in child_labels.get(node).into_iter().flatten() {
            let target = paths.get_mut(next_child).ok_or("invalid succinct tree")?;
            *target = base.clone();
            target.push(*edge);
            next_child += 1;
        }
    }
    if next_child != paths.len() {
        return Err("invalid succinct tree node count".into());
    }
    paths
        .into_iter()
        .enumerate()
        .filter_map(|(index, path)| match get_bit(leaves, index) {
            Ok(true) => Some(Ok(path)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn parse_ip(bytes: Vec<u8>) -> Result<IpAddr, String> {
    match bytes.as_slice() {
        [a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        value if value.len() == 16 => {
            let octets: [u8; 16] = value.try_into().map_err(|_| "invalid IPv6 length")?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err("SRS IP address must contain 4 or 16 bytes".into()),
    }
}

fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<IpCidr>, String> {
    let (mut current, last, bits, v4) = match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            (u128::from(u32::from(a)), u128::from(u32::from(b)), 32, true)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128, false),
        _ => return Err("SRS IP range mixes address families".into()),
    };
    if current > last {
        return Err("SRS IP range start is after end".into());
    }
    let mut output = Vec::new();
    loop {
        let alignment = if current == 0 {
            bits
        } else {
            current.trailing_zeros().min(bits)
        };
        let remaining = last - current;
        let capacity = if remaining == 0 {
            0
        } else if remaining == u128::MAX {
            128
        } else {
            127 - (remaining + 1).leading_zeros()
        };
        let host_bits = alignment.min(capacity);
        let prefix = bits - host_bits;
        let address = if v4 {
            IpAddress::V4((current as u32).to_be_bytes())
        } else {
            IpAddress::V6(current.to_be_bytes())
        };
        output.push(IpCidr::new(address, prefix as u8).ok_or("invalid generated CIDR")?);
        if host_bits == 128 || (1_u128 << host_bits) > remaining {
            break;
        }
        current += 1_u128 << host_bits;
    }
    Ok(output)
}

fn parse_network(value: String) -> Result<Network, String> {
    match value.as_str() {
        "tcp" => Ok(Network::Tcp),
        "udp" => Ok(Network::Udp),
        _ => Err(format!("unknown SRS network {value:?}")),
    }
}

fn parse_network_type(value: u8) -> Result<NetworkType, String> {
    match value {
        0 => Ok(NetworkType::Other),
        1 => Ok(NetworkType::Ethernet),
        2 => Ok(NetworkType::Wifi),
        3..=8 => Ok(NetworkType::Cellular),
        _ => Err(format!("unknown SRS network type {value}")),
    }
}

fn parse_port_ranges(values: Vec<String>) -> Result<Vec<PortRange>, String> {
    values
        .into_iter()
        .map(|value| value.parse::<PortRange>())
        .collect()
}

fn io_error(error: std::io::Error) -> String {
    format!("truncated SRS payload: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn wrap(payload: &[u8]) -> Vec<u8> {
        let mut output = MAGIC.to_vec();
        output.push(1);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        output.extend(encoder.finish().unwrap());
        output
    }

    #[test]
    fn decodes_network_ports_and_process() {
        // one default rule: network=[tcp], port=[443], process=[browser], final false
        let payload = [
            1, 0, 1, 1, 3, b't', b'c', b'p', 9, 1, 1, 0xbb, 11, 1, 7, b'b', b'r', b'o', b'w', b's',
            b'e', b'r', 0xff, 0,
        ];
        let rules = parse_rule_set_srs(&wrap(&payload)).unwrap();
        let RouteMatcherConfig::Conditions(rule) = &rules[0] else {
            panic!()
        };
        assert_eq!(rule.network, vec![Network::Tcp]);
        assert_eq!(rule.port, vec![PortRange::single(443)]);
        assert_eq!(rule.process_name, vec!["browser"]);
    }

    #[test]
    fn decomposes_ipv4_range() {
        assert_eq!(
            range_to_cidrs("192.0.2.0".parse().unwrap(), "192.0.2.255".parse().unwrap()).unwrap(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
    }
}
