use super::*;
use rustbox_kernel::{NetworkMetadataError, NetworkMetadataInfo};
use rustbox_types::NetworkType;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct NetworkMetadataProvider {
    cache: tokio::sync::Mutex<Option<(Instant, NetworkMetadataInfo)>>,
}

impl NetworkMetadataLookup for NetworkMetadataProvider {
    fn lookup_network(
        &self,
        _key: ConnectionKey,
    ) -> BoxFuture<'_, Result<NetworkMetadataInfo, NetworkMetadataError>> {
        Box::pin(async move {
            let mut cache = self.cache.lock().await;
            if let Some((at, value)) = cache.as_ref()
                && at.elapsed() < Duration::from_secs(2)
            {
                return Ok(value.clone());
            }
            let script = "$c=Get-NetIPConfiguration|Where-Object {$_.IPv4DefaultGateway -or $_.IPv6DefaultGateway}|Select-Object -First 1; if($c){$a=Get-NetAdapter -InterfaceIndex $c.InterfaceIndex; Write-Output ($c.InterfaceAlias+'|'+$a.NdisPhysicalMedium)}";
            let output = tokio::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .output()
                .await
                .map_err(|error| {
                    NetworkMetadataError::new(format!("query Windows network: {error}"))
                })?;
            let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let (interface, medium) = line
                .split_once('|')
                .map(|(name, medium)| {
                    (
                        Some(name.trim().to_owned()),
                        medium.trim().to_ascii_lowercase(),
                    )
                })
                .unwrap_or((None, String::new()));
            let is_wifi =
                medium.contains("802.11") || medium.contains("wireless lan") || medium == "9";
            let network_type = interface.as_ref().map(|_| {
                if is_wifi {
                    NetworkType::Wifi
                } else if medium.contains("wireless wan") || medium == "14" {
                    NetworkType::Cellular
                } else {
                    NetworkType::Ethernet
                }
            });
            let (wifi_ssid, wifi_bssid) = if is_wifi {
                wlan_details().await
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

async fn wlan_details() -> (Option<String>, Option<String>) {
    let Ok(output) = tokio::process::Command::new("netsh.exe")
        .args(["wlan", "show", "interfaces"])
        .output()
        .await
    else {
        return (None, None);
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
            })
            .filter(|value| !value.is_empty())
    };
    (field("SSID"), field("BSSID"))
}
