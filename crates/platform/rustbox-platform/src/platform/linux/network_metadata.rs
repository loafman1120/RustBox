use super::*;
use rustbox_kernel::{NetworkMetadataError, NetworkMetadataInfo};
use rustbox_types::{Host, NetworkType};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct NetworkMetadataProvider {
    cache: tokio::sync::Mutex<Option<(Instant, NetworkMetadataInfo)>>,
}

impl NetworkMetadataLookup for NetworkMetadataProvider {
    fn lookup_network(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<NetworkMetadataInfo, NetworkMetadataError>> {
        Box::pin(async move {
            let mut cache = self.cache.lock().await;
            if let Some((at, value)) = cache.as_ref()
                && at.elapsed() < Duration::from_secs(2)
            {
                return Ok(value.clone());
            }
            let destination = match key.remote.host {
                Host::Ip(address) => address.to_string(),
                Host::Domain(_) => "1.1.1.1".to_owned(),
            };
            let output = tokio::process::Command::new("ip")
                .args(["route", "get", &destination])
                .output()
                .await
                .map_err(|error| NetworkMetadataError::new(format!("run ip route get: {error}")))?;
            let text = String::from_utf8_lossy(&output.stdout);
            let tokens = text.split_ascii_whitespace().collect::<Vec<_>>();
            let interface = tokens
                .windows(2)
                .find_map(|pair| (pair[0] == "dev").then(|| pair[1].to_owned()));
            let wireless = tokio::fs::read_to_string("/proc/net/wireless")
                .await
                .unwrap_or_default();
            let is_wifi = interface.as_deref().is_some_and(|name| {
                wireless
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{name}:")))
                    || name.starts_with("wl")
            });
            let network_type = interface.as_deref().map(|name| {
                if is_wifi {
                    NetworkType::Wifi
                } else if name.starts_with("rmnet")
                    || name.starts_with("wwan")
                    || name.starts_with("ccmni")
                {
                    NetworkType::Cellular
                } else {
                    NetworkType::Ethernet
                }
            });
            let (wifi_ssid, wifi_bssid) = if is_wifi {
                let name = interface.as_deref().unwrap_or_default();
                let (ssid, bssid) =
                    tokio::join!(iwgetid(name, &["--raw"]), iwgetid(name, &["--ap", "--raw"]));
                (ssid, bssid)
            } else {
                (None, None)
            };
            let value = NetworkMetadataInfo {
                interface,
                wifi_ssid,
                wifi_bssid,
                network_type,
            };
            *cache = Some((Instant::now(), value.clone()));
            Ok(value)
        })
    }
}

async fn iwgetid(interface: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new("iwgetid")
        .arg(interface)
        .args(args)
        .output()
        .await
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}
