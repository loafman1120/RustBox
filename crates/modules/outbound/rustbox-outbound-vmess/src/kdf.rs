use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// VMess KDF — HMAC-SHA256 cascade keyed by label and path segments.
///
/// upstream: transport/vmess/aead/encrypt.go::KDF
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    nested_hmac(path, key)
}

fn nested_hmac(path: &[&[u8]], data: &[u8]) -> [u8; 32] {
    let Some((key, parent)) = path.split_last() else {
        let mut mac =
            HmacSha256::new_from_slice(b"VMess AEAD KDF").expect("HMAC accepts any key length");
        mac.update(data);
        return mac.finalize().into_bytes().into();
    };

    let mut normalized = [0_u8; 64];
    if key.len() > normalized.len() {
        normalized[..32].copy_from_slice(&nested_hmac(parent, key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let inner = normalized.map(|byte| byte ^ 0x36);
    let mut inner_input = Vec::with_capacity(inner.len() + data.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(data);
    let inner_digest = nested_hmac(parent, &inner_input);

    let outer = normalized.map(|byte| byte ^ 0x5c);
    let mut outer_input = Vec::with_capacity(outer.len() + inner_digest.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_digest);
    nested_hmac(parent, &outer_input)
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let full = kdf(key, path);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}
