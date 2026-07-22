//! Runtime-ready, portable configuration values shared by the compiler and
//! data-plane modules.
//!
//! Values in this crate have already crossed their textual parsing boundary.
//! The crate deliberately contains no I/O, executor, platform, or protocol
//! implementation dependencies.

use base64::Engine as _;
use rustbox_types::{Endpoint, IpCidr};
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsClientConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub client_certificate_pem: Option<Vec<u8>>,
    pub client_private_key_pem: Option<Vec<u8>>,
    pub certificate_authorities_der: Vec<Vec<u8>>,
    pub fingerprint: Option<String>,
    pub ech_config: Option<Vec<u8>>,
    pub reality: Option<RealityConfig>,
    pub public_key_pins: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub support_x25519_mlkem768: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2RayTransportPlan {
    WebSocket {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
        max_early_data: usize,
        early_data_header: Option<String>,
    },
    Http2 {
        path: String,
        hosts: Vec<String>,
    },
    Grpc {
        service_name: String,
        authority: String,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireGuardKey([u8; 32]);

impl WireGuardKey {
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl FromStr for WireGuardKey {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|error| format!("invalid base64 key: {error}"))?;
        let bytes = bytes
            .try_into()
            .map_err(|_| "key must decode to exactly 32 bytes".to_string())?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPeerPlan {
    pub server: Endpoint,
    pub public_key: WireGuardKey,
    pub pre_shared_key: Option<WireGuardKey>,
    pub allowed_ips: Vec<IpCidr>,
    pub persistent_keepalive: Option<Duration>,
    pub reserved: [u8; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPlan {
    pub addresses: Vec<IpCidr>,
    pub private_key: WireGuardKey,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeerPlan>,
    pub mtu: usize,
}

#[cfg(test)]
mod tests {
    use super::WireGuardKey;

    #[test]
    fn rejects_wrong_wireguard_key_length() {
        let error = "AA==".parse::<WireGuardKey>().expect_err("invalid key");
        assert!(error.contains("32 bytes"));
    }
}
