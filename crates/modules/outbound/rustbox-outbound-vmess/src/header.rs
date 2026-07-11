use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use md5::{Digest, Md5};
use rand::RngCore;
use std::net::IpAddr;

use crate::Metadata;

use super::kdf::{kdf12, kdf16};

/// "c48619fe-8f02-49e0-b9e9-edf763e17e21" — historical v2ray constant
const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

const CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
const CMD_UDP: u8 = 0x02;

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

const OPT_STANDARD: u8 = 0x01;

/// Derive the 16-byte cmd_key from a UUID.
///
/// upstream: transport/vmess/user.go — cmd_key = MD5(UUID || MAGIC)
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(VMESS_MAGIC);
    hasher.finalize().into()
}

/// Security cipher identifier in the VMess header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl Security {
    fn to_nibble(self) -> u8 {
        match self {
            Security::Aes128Gcm => 0x03,
            Security::ChaCha20Poly1305 => 0x04,
            Security::None => 0x05,
        }
    }
}

/// Parsed auto cipher: pick AES-GCM on hardware AES, ChaCha20 otherwise.
pub fn auto_security() -> Security {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("aes") {
        return Security::Aes128Gcm;
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Security::Aes128Gcm;
    }
    #[allow(unreachable_code)]
    Security::ChaCha20Poly1305
}

pub struct SealedHeader {
    pub bytes: Vec<u8>,
    pub req_key: [u8; 16],
    pub req_iv: [u8; 16],
    pub resp_v: u8,
}

/// Build and encrypt the full VMess AEAD request header.
///
/// Returns (encrypted_header_bytes, req_key, req_iv, resp_v) for the caller
/// to derive body cipher keys.
pub fn seal_request_header(
    cmd_key: &[u8; 16],
    security: Security,
    metadata: &Metadata,
    is_udp: bool,
) -> Result<SealedHeader, String> {
    let mut rng = rand::rng();

    // Generate per-connection random values
    let mut req_key = [0u8; 16];
    let mut req_iv = [0u8; 16];
    rng.fill_bytes(&mut req_key);
    rng.fill_bytes(&mut req_iv);
    let resp_v: u8 = (rng.next_u32() & 0xFF) as u8;

    // Connection nonce (8 random bytes) used to derive header key/iv
    let mut conn_nonce = [0u8; 8];
    rng.fill_bytes(&mut conn_nonce);

    // 1) Auth ID (16 bytes, AES-128-ECB encrypted)
    let auth_id = build_auth_id(cmd_key, &mut rng);

    // 2) Build plaintext header
    let plaintext = build_header_plaintext(
        &req_key, &req_iv, resp_v, security, metadata, is_udp, &mut rng,
    )?;

    // 3) Derive header encryption keys
    let header_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
    let header_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
    );

    // 4) Derive length encryption keys
    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
    );
    let length_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
    );

    // 5) Encrypt the header. The separately encrypted length describes the
    // plaintext header; the AEAD tag is not part of that value.
    let header_len = u16::try_from(plaintext.len())
        .map_err(|_| "vmess: request header is too large".to_string())?;
    let cipher = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|e| format!("vmess: header cipher init: {e}"))?;
    let encrypted_header = cipher
        .encrypt(
            Nonce::from_slice(&header_iv),
            aes_gcm::aead::Payload {
                msg: plaintext.as_ref(),
                aad: &auth_id,
            },
        )
        .map_err(|e| format!("vmess: header encrypt: {e}"))?;

    // 6) Encrypt the length (2 bytes, big-endian)
    let length_cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| format!("vmess: length cipher init: {e}"))?;
    let encrypted_length = length_cipher
        .encrypt(
            Nonce::from_slice(&length_iv),
            aes_gcm::aead::Payload {
                msg: header_len.to_be_bytes().as_ref(),
                aad: &auth_id,
            },
        )
        .map_err(|e| format!("vmess: length encrypt: {e}"))?;

    // 7) Assemble: auth_id(16) || encrypted_length(18) || conn_nonce(8) || encrypted_header(N+16)
    let mut out = Vec::with_capacity(16 + 8 + encrypted_length.len() + encrypted_header.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted_length);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&encrypted_header);

    Ok(SealedHeader {
        bytes: out,
        req_key,
        req_iv,
        resp_v,
    })
}

fn build_auth_id(cmd_key: &[u8; 16], rng: &mut impl RngCore) -> [u8; 16] {
    let auth_id_key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&now.to_be_bytes());
    rng.fill_bytes(&mut block[8..12]);
    let crc = crc32fast::hash(&block[..12]);
    block[12..16].copy_from_slice(&crc.to_be_bytes());

    let aes = Aes128::new_from_slice(&auth_id_key).expect("AES-128 key is 16 bytes");
    aes.encrypt_block(aes::Block::from_mut_slice(&mut block));

    block
}

fn build_header_plaintext(
    req_key: &[u8; 16],
    req_iv: &[u8; 16],
    resp_v: u8,
    security: Security,
    metadata: &Metadata,
    is_udp: bool,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, String> {
    let padding_len = (rng.next_u32() % 16) as u8;
    let cmd = if is_udp { CMD_UDP } else { CMD_TCP };

    let mut buf = Vec::with_capacity(64);
    buf.push(0x01); // version
    buf.extend_from_slice(req_iv);
    buf.extend_from_slice(req_key);
    buf.push(resp_v);
    buf.push(OPT_STANDARD); // opts: S=1
    buf.push((padding_len << 4) | security.to_nibble()); // p(4) || sec(4)
    buf.push(0x00); // reserved
    buf.push(cmd);

    // Port (big-endian, BEFORE addr_type)
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());

    // Address encoding
    encode_address(&mut buf, metadata)?;

    // Padding
    if padding_len > 0 {
        let mut pad = [0u8; 15];
        rng.fill_bytes(&mut pad[..padding_len as usize]);
        buf.extend_from_slice(&pad[..padding_len as usize]);
    }

    // FNV-1a hash of everything so far
    let hash = fnv1a32(&buf);
    buf.extend_from_slice(&hash.to_be_bytes());

    Ok(buf)
}

fn encode_address(buf: &mut Vec<u8>, metadata: &Metadata) -> Result<(), String> {
    if !metadata.host.is_empty() {
        let host = metadata.host.as_bytes();
        if host.len() > 255 {
            return Err(format!(
                "vmess: domain too long ({} bytes, max 255)",
                host.len()
            ));
        }
        buf.push(ADDR_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host);
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(ADDR_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(ADDR_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        return Err("vmess: no destination address".into());
    }
    Ok(())
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_key_is_deterministic() {
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let k1 = cmd_key(&uuid);
        let k2 = cmd_key(&uuid);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 16]);
    }

    #[test]
    fn fnv1a_known_value() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
    }

    #[test]
    fn address_encode_ipv4() {
        let meta = Metadata {
            dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            dst_port: 443,
            ..Default::default()
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf, vec![0x01, 127, 0, 0, 1]);
    }

    #[test]
    fn address_encode_domain() {
        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 80,
            ..Default::default()
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..], b"example.com");
    }

    #[test]
    fn address_encode_domain_too_long() {
        let long = "a".repeat(256);
        let meta = Metadata {
            host: long,
            dst_port: 80,
            ..Default::default()
        };
        let mut buf = Vec::new();
        assert!(encode_address(&mut buf, &meta).is_err());
    }

    #[test]
    fn security_nibble_values() {
        assert_eq!(Security::Aes128Gcm.to_nibble(), 0x03);
        assert_eq!(Security::ChaCha20Poly1305.to_nibble(), 0x04);
        assert_eq!(Security::None.to_nibble(), 0x05);
    }

    #[test]
    fn address_encode_ipv6() {
        let meta = Metadata {
            dst_ip: Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            dst_port: 443,
            ..Default::default()
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf[0], ADDR_IPV6);
        assert_eq!(buf.len(), 1 + 16);
    }

    #[test]
    fn address_encode_domain_max_255_ok() {
        let domain = "a".repeat(255);
        let meta = Metadata {
            host: domain,
            dst_port: 80,
            ..Default::default()
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf[0], ADDR_DOMAIN);
        assert_eq!(buf[1], 255);
        assert_eq!(buf.len(), 2 + 255);
    }

    #[test]
    fn address_encode_no_destination_errors() {
        let meta = Metadata {
            dst_port: 80,
            ..Default::default()
        };
        let mut buf = Vec::new();
        assert!(encode_address(&mut buf, &meta).is_err());
    }

    #[test]
    fn address_encode_domain_idn_not_punycoded() {
        // upstream: passes raw UTF-8, no punycode conversion
        let meta = Metadata {
            host: "例え.jp".into(),
            dst_port: 80,
            ..Default::default()
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf[0], ADDR_DOMAIN);
        assert_eq!(&buf[2..], "例え.jp".as_bytes());
    }

    #[test]
    fn address_domain_prefers_host_over_ip() {
        let meta = Metadata {
            host: "example.com".into(),
            dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 443,
        };
        let mut buf = Vec::new();
        encode_address(&mut buf, &meta).unwrap();
        assert_eq!(buf[0], ADDR_DOMAIN, "domain must take priority over IP");
    }

    #[test]
    fn seal_request_header_produces_valid_structure() {
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let ck = cmd_key(&uuid);
        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let sealed = seal_request_header(&ck, Security::Aes128Gcm, &meta, false).unwrap();

        // auth_id(16) + conn_nonce(8) + encrypted_length(2+16=18) + encrypted_header(N+16)
        assert!(sealed.bytes.len() >= 16 + 8 + 18 + 16, "header too short");
        assert_ne!(sealed.req_key, [0u8; 16], "req_key must be random");
        assert_ne!(sealed.req_iv, [0u8; 16], "req_iv must be random");

        let auth_id: [u8; 16] = sealed.bytes[..16].try_into().unwrap();
        let conn_nonce: [u8; 8] = sealed.bytes[34..42].try_into().unwrap();
        let length_key = kdf16(
            &ck,
            &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
        );
        let length_iv = kdf12(
            &ck,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
        );
        let length_cipher = Aes128Gcm::new_from_slice(&length_key).unwrap();
        let encoded_length = length_cipher
            .decrypt(
                Nonce::from_slice(&length_iv),
                aes_gcm::aead::Payload {
                    msg: &sealed.bytes[16..34],
                    aad: &auth_id,
                },
            )
            .unwrap();
        let plaintext_length = u16::from_be_bytes(encoded_length.try_into().unwrap()) as usize;
        let encrypted_header_length = sealed.bytes.len() - 42;
        assert_eq!(plaintext_length + 16, encrypted_header_length);
    }

    #[test]
    fn seal_request_header_unique_per_call() {
        let uuid: [u8; 16] = [0x01; 16];
        let ck = cmd_key(&uuid);
        let meta = Metadata {
            host: "test.com".into(),
            dst_port: 80,
            ..Default::default()
        };
        let h1 = seal_request_header(&ck, Security::Aes128Gcm, &meta, false).unwrap();
        let h2 = seal_request_header(&ck, Security::Aes128Gcm, &meta, false).unwrap();
        assert_ne!(h1.bytes, h2.bytes, "each header must use fresh randomness");
        assert_ne!(h1.req_key, h2.req_key);
    }

    #[test]
    fn header_plaintext_port_before_addr_type() {
        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let mut rng = rand::rng();
        let req_key = [0u8; 16];
        let req_iv = [0u8; 16];
        let pt = build_header_plaintext(
            &req_key,
            &req_iv,
            0x42,
            Security::Aes128Gcm,
            &meta,
            false,
            &mut rng,
        )
        .unwrap();
        // version(1) + req_iv(16) + req_key(16) + resp_v(1) + opts(1) + p_sec(1) + reserved(1) + cmd(1) = 38
        // Then port(2) then addr_type(1)
        let port_offset = 38;
        let port = u16::from_be_bytes([pt[port_offset], pt[port_offset + 1]]);
        assert_eq!(port, 443, "port must be at offset 38 (before addr_type)");
        assert_eq!(
            pt[port_offset + 2],
            ADDR_DOMAIN,
            "addr_type must follow port"
        );
    }

    #[test]
    fn header_plaintext_ends_with_fnv1a() {
        let meta = Metadata {
            dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 80,
            ..Default::default()
        };
        let mut rng = FakeRng(0);
        let pt = build_header_plaintext(
            &[0u8; 16],
            &[0u8; 16],
            0x42,
            Security::Aes128Gcm,
            &meta,
            false,
            &mut rng,
        )
        .unwrap();
        let body = &pt[..pt.len() - 4];
        let expected_hash = fnv1a32(body);
        let actual_hash = u32::from_be_bytes([
            pt[pt.len() - 4],
            pt[pt.len() - 3],
            pt[pt.len() - 2],
            pt[pt.len() - 1],
        ]);
        assert_eq!(
            actual_hash, expected_hash,
            "FNV-1a must cover all preceding bytes"
        );
    }

    #[test]
    fn auto_security_returns_valid_cipher() {
        let s = super::auto_security();
        assert!(
            s == Security::Aes128Gcm || s == Security::ChaCha20Poly1305,
            "auto must pick aes or chacha"
        );
    }

    struct FakeRng(u64);
    impl rand::RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            self.0 as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
    }
}
