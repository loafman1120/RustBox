use super::*;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use rustbox_types::Host;
use std::net::IpAddr;
use sysinfo::{Pid, ProcessesToUpdate, System};

impl ProcessLookup for WindowsPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessMetadata>, ProcessLookupError>> {
        let cache = self.process_cache.clone();
        Box::pin(async move { lookup_windows_process(cache, key).await })
    }
}

async fn lookup_windows_process(
    cache: Arc<Mutex<WindowsProcessCache>>,
    key: ConnectionKey,
) -> Result<Option<ProcessMetadata>, ProcessLookupError> {
    tokio::task::spawn_blocking(move || lookup_process_cached(&cache, &key))
        .await
        .map_err(|error| ProcessLookupError::new(format!("join process table lookup: {error}")))?
}

fn lookup_process_cached(
    cache: &Mutex<WindowsProcessCache>,
    key: &ConnectionKey,
) -> Result<Option<ProcessMetadata>, ProcessLookupError> {
    const SOCKET_TTL: std::time::Duration = std::time::Duration::from_millis(250);
    const PROCESS_TTL: std::time::Duration = std::time::Duration::from_secs(5);

    let now = std::time::Instant::now();
    let mut cache = cache.lock().expect("Windows process cache lock");
    let sockets_are_stale = cache
        .sockets_updated_at
        .is_none_or(|updated| now.duration_since(updated) >= SOCKET_TTL);
    if sockets_are_stale {
        cache.sockets = netstat2::get_sockets_info(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        )
        .map_err(|error| {
            ProcessLookupError::new(format!("query native Windows socket tables: {error}"))
        })?;
        cache.sockets_updated_at = Some(now);
        cache
            .process_paths
            .retain(|_, (updated, _)| now.duration_since(*updated) < PROCESS_TTL);
    }
    let Some(pid) = lookup_pid(&cache.sockets, key) else {
        return Ok(None);
    };
    let path = match cache.process_paths.get(&pid) {
        Some((updated, path)) if now.duration_since(*updated) < PROCESS_TTL => path.clone(),
        _ => {
            let path = process_path(pid);
            cache.process_paths.insert(pid, (now, path.clone()));
            path
        }
    };
    let name = path.as_deref().and_then(|path| {
        std::path::Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    Ok(Some(ProcessMetadata {
        pid: Some(pid),
        name,
        path,
        package_name: None,
        user_id: None,
        user_name: None,
    }))
}

fn lookup_pid(sockets: &[netstat2::SocketInfo], key: &ConnectionKey) -> Option<u32> {
    let local_ip = endpoint_ip(&key.local);
    let remote_ip = endpoint_ip(&key.remote);
    let exact = sockets.iter().find(
        |socket| match (&key.network, &socket.protocol_socket_info) {
            (rustbox_types::Network::Tcp, ProtocolSocketInfo::Tcp(tcp)) => {
                tcp.local_port == key.local.port
                    && local_ip.is_none_or(|ip| ip_matches(ip, tcp.local_addr))
                    && tcp.remote_port == key.remote.port
                    && remote_ip.is_none_or(|ip| ip_matches(ip, tcp.remote_addr))
            }
            (rustbox_types::Network::Udp, ProtocolSocketInfo::Udp(udp)) => {
                udp.local_port == key.local.port
                    && local_ip.is_none_or(|ip| ip_matches(ip, udp.local_addr))
            }
            _ => false,
        },
    );
    exact.and_then(|socket| socket.associated_pids.first().copied())
}

fn endpoint_ip(endpoint: &rustbox_types::Endpoint) -> Option<IpAddr> {
    match endpoint.host {
        Host::Ip(ip) => Some(ip),
        Host::Domain(_) => None,
    }
}

fn ip_matches(expected: IpAddr, actual: IpAddr) -> bool {
    expected == actual || actual.is_unspecified()
}

fn process_path(pid: u32) -> Option<String> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system
        .process(pid)
        .and_then(|process| process.exe())
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netstat2::{SocketInfo, TcpSocketInfo, TcpState};
    use rustbox_kernel::FlowDirection;
    use rustbox_types::{Endpoint, Network};

    #[test]
    fn tcp_owner_lookup_uses_the_complete_connection_key() {
        let local: IpAddr = "10.0.0.2".parse().expect("local IP");
        let first_remote: IpAddr = "198.51.100.10".parse().expect("remote IP");
        let second_remote: IpAddr = "203.0.113.20".parse().expect("remote IP");
        let sockets = vec![
            tcp_socket(local, 50000, first_remote, 443, 10),
            tcp_socket(local, 50000, second_remote, 443, 20),
        ];
        let key = ConnectionKey {
            network: Network::Tcp,
            local: "10.0.0.2:50000"
                .parse::<Endpoint>()
                .expect("local endpoint"),
            remote: "203.0.113.20:443"
                .parse::<Endpoint>()
                .expect("remote endpoint"),
            direction: FlowDirection::Inbound,
        };

        assert_eq!(lookup_pid(&sockets, &key), Some(20));
    }

    fn tcp_socket(
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        pid: u32,
    ) -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state: TcpState::Established,
            }),
            associated_pids: vec![pid],
        }
    }
}
