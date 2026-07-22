use super::*;
use std::net::IpAddr;

impl NetworkControl for WindowsPlatform {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(apply_windows_network_transaction(self, transaction))
    }

    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
        Box::pin(release_windows_network_lease(self, lease))
    }
}

async fn apply_windows_network_transaction(
    platform: &WindowsPlatform,
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    if transaction.operations.is_empty() {
        return Ok(NetworkLease {
            id: 0,
            operations: transaction.operations,
            undo_operations: Vec::new(),
            active: false,
        });
    }

    if transaction
        .operations
        .iter()
        .any(|operation| matches!(operation, NetworkOperation::EnforceDnsLeakProtection { .. }))
    {
        ensure_network_watchdog(platform)?;
    }

    apply_windows_route_transaction(platform, transaction).await
}

fn ensure_network_watchdog(platform: &WindowsPlatform) -> Result<(), NetworkControlError> {
    use std::os::windows::process::CommandExt;

    let mut watchdog = platform
        .watchdog
        .lock()
        .expect("Windows watchdog process lock");
    if let Some(child) = watchdog.as_mut() {
        match child.try_wait() {
            Ok(None) => return Ok(()),
            Ok(Some(_)) => *watchdog = None,
            Err(error) => {
                return Err(NetworkControlError::new(format!(
                    "inspect RustBox watchdog process: {error}"
                )));
            }
        }
    }

    let executable = if let Some(path) = std::env::var_os("RUSTBOX_WATCHDOG_EXE") {
        PathBuf::from(path)
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.parent()
                    .map(|parent| parent.join("rustbox-watchdog.exe"))
            })
            .ok_or_else(|| NetworkControlError::new("resolve RustBox watchdog location"))?
    };
    if !executable.is_file() {
        return Err(NetworkControlError::new(format!(
            "strict route requires `{}`; rebuild or reinstall the Windows client package",
            executable.display()
        )));
    }
    let pid = std::process::id();
    let mut system = sysinfo::System::new();
    system.refresh_processes(
        sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
        true,
    );
    let start_time = system
        .process(sysinfo::Pid::from_u32(pid))
        .map(sysinfo::Process::start_time)
        .ok_or_else(|| NetworkControlError::new("inspect RustBox parent process"))?;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let child = Command::new(&executable)
        .args([
            "--parent-pid",
            &pid.to_string(),
            "--parent-start-time",
            &start_time.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| {
            NetworkControlError::new(format!("start RustBox network watchdog: {error}"))
        })?;
    *watchdog = Some(child);
    Ok(())
}

static NEXT_NETWORK_LEASE_ID: AtomicU64 = AtomicU64::new(1);

const NETWORK_JOURNAL_VERSION: u32 = 1;
const NETWORK_JOURNAL_FILE: &str = "network-lease.json";

#[derive(Debug, Serialize, Deserialize)]
struct NetworkJournal {
    version: u32,
    process_id: u32,
    lease_id: u64,
    undo: Vec<JournalUndo>,
    checksum: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalUndo {
    DeleteRoute {
        destination: String,
        gateway: Option<String>,
        interface_index: u32,
        metric: Option<u32>,
    },
    RestorePlatformState {
        namespace: String,
        payload: String,
    },
}

async fn apply_windows_route_transaction(
    platform: &WindowsPlatform,
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    let lease_id = NEXT_NETWORK_LEASE_ID.fetch_add(1, Ordering::Relaxed);
    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
    recover_stale_network_journal(platform, &handle).await?;
    let existing = handle
        .list()
        .await
        .map_err(|err| network_control_io_error("list routes", err))?;
    let mut routes = Vec::with_capacity(transaction.operations.len());
    let mut route_operations = Vec::with_capacity(transaction.operations.len());
    let mut preserved_routes = Vec::new();
    let mut preserved_operations = Vec::new();
    let mut guards = Vec::new();
    let mut deferred = Vec::new();
    for operation in &transaction.operations {
        match operation {
            NetworkOperation::AddRoute {
                destination,
                gateway,
                interface,
                metric,
            } => {
                routes.push(route_from_add_route(
                    *destination,
                    *gateway,
                    interface,
                    *metric,
                )?);
                route_operations.push(operation.clone());
            }
            NetworkOperation::PreserveRoute { destination } => {
                if !has_exact_route(*destination, &existing) {
                    preserved_routes.push(preserved_route(*destination, &existing)?);
                    preserved_operations.push(operation.clone());
                }
            }
            NetworkOperation::EnforceDnsLeakProtection { .. } => guards.push(operation.clone()),
            NetworkOperation::SetInterfaceDns { .. }
            | NetworkOperation::SetPlatformHttpProxy(_) => deferred.push(operation.clone()),
        }
    }
    // Endpoint/LAN exclusions must exist before the broader TUN routes become
    // reachable, otherwise bootstrap traffic can briefly loop into the TUN.
    preserved_routes.append(&mut routes);
    routes = preserved_routes;
    preserved_operations.append(&mut route_operations);
    route_operations = preserved_operations;

    let mut undo_operations = Vec::new();
    for operation in &guards {
        undo_operations.push(snapshot_windows_non_route_operation(operation, lease_id)?);
    }
    undo_operations.extend(
        routes
            .iter()
            .map(route_delete_undo)
            .collect::<Result<Vec<_>, _>>()?,
    );
    for operation in &deferred {
        undo_operations.push(snapshot_windows_non_route_operation(operation, lease_id)?);
    }
    write_network_journal(lease_id, &undo_operations)?;

    let mut applied_guards = 0usize;
    for (index, operation) in guards.iter().enumerate() {
        if let Err(error) = apply_windows_non_route_operation(platform, lease_id, operation) {
            let mut recovered = true;
            for undo in undo_operations.iter().take(index + 1).rev() {
                recovered &= apply_windows_undo(platform, undo).is_ok();
            }
            if recovered {
                let _ = remove_network_journal(lease_id);
            }
            return Err(error);
        }
        applied_guards += 1;
    }

    let mut applied = Vec::new();
    for route in &routes {
        if let Err(err) = handle.add(route).await {
            let mut recovered = true;
            if transaction.rollback_policy == RollbackPolicy::Required {
                recovered = rollback_routes(&handle, &applied).await;
            }
            for undo in undo_operations.iter().take(applied_guards).rev() {
                recovered &= apply_windows_undo(platform, undo).is_ok();
            }
            if recovered {
                let _ = remove_network_journal(lease_id);
            }
            return Err(network_control_io_error("add route", err));
        }
        applied.push(route.clone());
    }
    let mut applied_deferred = Vec::new();
    let deferred_undo_offset = guards.len() + routes.len();
    for (index, operation) in deferred.iter().enumerate() {
        if let Err(err) = apply_windows_non_route_operation(platform, lease_id, operation) {
            let mut recovered = rollback_routes(&handle, &applied).await;
            for undo in undo_operations
                .iter()
                .skip(deferred_undo_offset)
                .take(index + 1)
                .rev()
            {
                recovered &= apply_windows_undo(platform, undo).is_ok();
            }
            for undo in undo_operations.iter().take(applied_guards).rev() {
                recovered &= apply_windows_undo(platform, undo).is_ok();
            }
            if recovered {
                let _ = remove_network_journal(lease_id);
            }
            return Err(err);
        }
        applied_deferred.push(operation.clone());
    }

    let mut applied_operations = guards;
    applied_operations.extend(route_operations);
    applied_operations.extend(applied_deferred);
    Ok(NetworkLease {
        id: lease_id,
        operations: applied_operations,
        undo_operations,
        active: true,
    })
}

fn preserved_route(
    destination: rustbox_types::IpCidr,
    routes: &[Route],
) -> Result<Route, NetworkControlError> {
    let address = destination.address;
    let best = routes
        .iter()
        .filter(|route| route_contains(route, address))
        .max_by_key(|route| route.prefix)
        .ok_or_else(|| {
            NetworkControlError::new(format!(
                "no existing Windows route can preserve exclusion {destination}"
            ))
        })?;
    let mut route = Route::new(address, destination.prefix_len);
    if let Some(index) = best.ifindex {
        route = route.with_ifindex(index);
    }
    if let Some(gateway) = best.gateway {
        route = route.with_gateway(gateway);
    }
    if let Some(metric) = best.metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

fn route_contains(route: &Route, address: std::net::IpAddr) -> bool {
    match (route.destination, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) => {
            let prefix = route.prefix.min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) => {
            let prefix = route.prefix.min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

pub(crate) fn has_exact_route(destination: rustbox_types::IpCidr, routes: &[Route]) -> bool {
    let address = destination.address;
    routes
        .iter()
        .any(|route| route.prefix == destination.prefix_len && route_contains(route, address))
}

async fn release_windows_network_lease(
    platform: &WindowsPlatform,
    lease: NetworkLease,
) -> Result<(), NetworkControlError> {
    if !lease.active || lease.operations.is_empty() {
        return Ok(());
    }

    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
    let mut errors = Vec::new();
    for undo in lease.undo_operations.iter().rev() {
        match undo {
            NetworkUndo::DeleteRoute {
                destination,
                gateway,
                interface,
                metric,
            } => {
                let route = route_from_add_route(*destination, *gateway, interface, *metric)?;
                match handle.list().await {
                    Ok(routes)
                        if routes
                            .iter()
                            .any(|candidate| routes_are_equal(candidate, &route)) =>
                    {
                        if let Err(err) = handle.delete(&route).await {
                            errors.push(err.to_string());
                        }
                    }
                    Ok(_) => {}
                    Err(err) => errors.push(err.to_string()),
                }
            }
            NetworkUndo::RestorePlatformState { .. } => {
                if let Err(err) = apply_windows_undo(platform, undo) {
                    errors.push(err.message);
                }
            }
        }
    }
    if errors.is_empty() {
        remove_network_journal(lease.id)?;
        Ok(())
    } else {
        Err(NetworkControlError::new(format!(
            "release Windows network lease {} failed: {}",
            lease.id,
            errors.join("; ")
        )))
    }
}

fn apply_windows_non_route_operation(
    platform: &WindowsPlatform,
    lease_id: u64,
    operation: &NetworkOperation,
) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, servers } => {
            if servers.is_empty() {
                return Err(NetworkControlError::new(
                    "Windows DNS server list cannot be empty",
                ));
            }
            let selector = match interface {
                InterfaceRef::Index(index) => format!("-InterfaceIndex {index}"),
                InterfaceRef::Name(name) => format!("-InterfaceAlias '{}'", ps_quote(name)),
            };
            let servers = servers
                .iter()
                .map(|server| format!("'{server}'"))
                .collect::<Vec<_>>()
                .join(",");
            run_powershell(&format!(
                "Set-DnsClientServerAddress {selector} -ServerAddresses @({servers}) -ErrorAction Stop"
            ))
        }
        NetworkOperation::SetPlatformHttpProxy(proxy) => {
            let server = proxy.listen.to_string();
            let bypass = proxy.bypass.join(";");
            run_powershell_with_env(
                "$path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty $path ProxyEnable 1 -Type DWord; Set-ItemProperty $path ProxyServer $env:RUSTBOX_PROXY; Set-ItemProperty $path ProxyOverride $env:RUSTBOX_BYPASS",
                &[("RUSTBOX_PROXY", server), ("RUSTBOX_BYPASS", bypass)],
            )
        }
        NetworkOperation::EnforceDnsLeakProtection {
            tunnel_interface_alias,
        } => {
            let engine = install_dns_leak_protection(tunnel_interface_alias)?;
            platform
                .wfp_sessions
                .lock()
                .expect("Windows WFP session lock")
                .insert(lease_id, engine);
            Ok(())
        }
        other => Err(NetworkControlError::new(format!(
            "not a Windows non-route operation: {other:?}"
        ))),
    }
}

fn snapshot_windows_non_route_operation(
    operation: &NetworkOperation,
    lease_id: u64,
) -> Result<NetworkUndo, NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, .. } => {
            let selector = match interface {
                InterfaceRef::Index(index) => format!("-InterfaceIndex {index}"),
                InterfaceRef::Name(name) => format!("-InterfaceAlias '{}'", ps_quote(name)),
            };
            let payload = run_powershell_capture(
                &format!(
                    r#"$r=Get-DnsClientServerAddress {selector} -ErrorAction Stop; $idx=($r|Select-Object -First 1).InterfaceIndex; $a=Get-NetAdapter -InterfaceIndex $idx -ErrorAction Stop; $g=$a.InterfaceGuid.ToString('B'); function IsAutomatic($f){{$p="HKLM:\SYSTEM\CurrentControlSet\Services\$f\Parameters\Interfaces\$g"; if(-not (Test-Path $p)){{return $true}}; $v=(Get-ItemProperty $p -Name NameServer -ErrorAction SilentlyContinue).NameServer; return ($null -eq $v -or "$v".Length -eq 0)}}; $v4=@($r|Where-Object AddressFamily -eq 2|ForEach-Object {{$_.ServerAddresses}}|Where-Object {{$_}}); $v6=@($r|Where-Object AddressFamily -eq 23|ForEach-Object {{$_.ServerAddresses}}|Where-Object {{$_}}); @{{version=2;interface_index=$idx;ipv4=@{{automatic=(IsAutomatic 'Tcpip');servers=$v4}};ipv6=@{{automatic=(IsAutomatic 'Tcpip6');servers=$v6}}}}|ConvertTo-Json -Depth 4 -Compress"#
                ),
                &[],
            )?;
            Ok(NetworkUndo::RestorePlatformState {
                namespace: "windows.dns.v1".into(),
                payload,
            })
        }
        NetworkOperation::SetPlatformHttpProxy(_) => {
            let payload = run_powershell_capture(
                r#"$path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $p=Get-ItemProperty $path; $n=@($p.PSObject.Properties.Name); @{version=1;enabled_exists=($n -contains 'ProxyEnable');enabled=$p.ProxyEnable;server_exists=($n -contains 'ProxyServer');server=$p.ProxyServer;bypass_exists=($n -contains 'ProxyOverride');bypass=$p.ProxyOverride}|ConvertTo-Json -Compress"#,
                &[],
            )?;
            Ok(NetworkUndo::RestorePlatformState {
                namespace: "windows.proxy.v1".into(),
                payload,
            })
        }
        NetworkOperation::EnforceDnsLeakProtection { .. } => {
            Ok(NetworkUndo::RestorePlatformState {
                namespace: "windows.wfp.dynamic.v1".into(),
                payload: lease_id.to_string(),
            })
        }
        other => Err(NetworkControlError::new(format!(
            "cannot snapshot Windows non-route operation: {other:?}"
        ))),
    }
}

fn network_journal_path() -> PathBuf {
    if let Some(directory) = std::env::var_os("RUSTBOX_NETWORK_STATE_DIR") {
        return PathBuf::from(directory).join(NETWORK_JOURNAL_FILE);
    }
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("RustBox").join(NETWORK_JOURNAL_FILE)
}

fn write_network_journal(lease_id: u64, undo: &[NetworkUndo]) -> Result<(), NetworkControlError> {
    let path = network_journal_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            NetworkControlError::new(format!("create Windows recovery directory: {error}"))
        })?;
    }
    let process_id = std::process::id();
    let undo = undo
        .iter()
        .map(journal_undo)
        .collect::<Result<Vec<_>, _>>()?;
    let checksum = network_journal_checksum(NETWORK_JOURNAL_VERSION, process_id, lease_id, &undo)?;
    let journal = NetworkJournal {
        version: NETWORK_JOURNAL_VERSION,
        process_id,
        lease_id,
        undo,
        checksum,
    };
    let bytes = serde_json::to_vec_pretty(&journal).map_err(|error| {
        NetworkControlError::new(format!("serialize Windows recovery journal: {error}"))
    })?;
    let temporary = path.with_extension(format!("tmp-{process_id}-{lease_id}"));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| {
            NetworkControlError::new(format!("open Windows recovery journal: {error}"))
        })?;
    file.write_all(&bytes).map_err(|error| {
        NetworkControlError::new(format!("write Windows recovery journal: {error}"))
    })?;
    file.sync_all().map_err(|error| {
        NetworkControlError::new(format!("flush Windows recovery journal: {error}"))
    })?;
    drop(file);
    fs::rename(&temporary, &path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        NetworkControlError::new(format!("publish Windows recovery journal: {error}"))
    })
}

pub(super) async fn recover_stale_network_journal(
    platform: &WindowsPlatform,
    handle: &RouteHandle,
) -> Result<(), NetworkControlError> {
    let path = network_journal_path();
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(NetworkControlError::new(format!(
                "read Windows recovery journal: {error}"
            )));
        }
    };
    let journal: NetworkJournal = serde_json::from_slice(&bytes).map_err(|error| {
        NetworkControlError::new(format!("parse Windows recovery journal: {error}"))
    })?;
    if journal.version != NETWORK_JOURNAL_VERSION {
        return Err(NetworkControlError::new(format!(
            "unsupported Windows recovery journal version {}",
            journal.version
        )));
    }
    verify_network_journal(&journal)?;
    let system = sysinfo::System::new_all();
    if system
        .process(sysinfo::Pid::from_u32(journal.process_id))
        .is_some()
    {
        return Err(NetworkControlError::new(format!(
            "Windows network lease {} is still owned by process {}",
            journal.lease_id, journal.process_id
        )));
    }

    for undo in journal.undo.iter().rev() {
        apply_journal_undo(platform, handle, undo).await?;
    }
    fs::remove_file(&path).map_err(|error| {
        NetworkControlError::new(format!("remove recovered Windows journal: {error}"))
    })
}

fn network_journal_checksum(
    version: u32,
    process_id: u32,
    lease_id: u64,
    undo: &[JournalUndo],
) -> Result<Vec<u8>, NetworkControlError> {
    let payload = serde_json::to_vec(&(version, process_id, lease_id, undo)).map_err(|error| {
        NetworkControlError::new(format!("serialize Windows journal checksum input: {error}"))
    })?;
    Ok(Sha256::digest(payload).to_vec())
}

fn verify_network_journal(journal: &NetworkJournal) -> Result<(), NetworkControlError> {
    let expected = network_journal_checksum(
        journal.version,
        journal.process_id,
        journal.lease_id,
        &journal.undo,
    )?;
    if expected == journal.checksum {
        Ok(())
    } else {
        Err(NetworkControlError::new(
            "Windows recovery journal checksum mismatch",
        ))
    }
}

async fn apply_journal_undo(
    platform: &WindowsPlatform,
    handle: &RouteHandle,
    undo: &JournalUndo,
) -> Result<(), NetworkControlError> {
    match undo {
        JournalUndo::DeleteRoute {
            destination,
            gateway,
            interface_index,
            metric,
        } => {
            let destination = destination.parse::<IpCidr>().map_err(|error| {
                NetworkControlError::new(format!("invalid route in recovery journal: {error}"))
            })?;
            let gateway = gateway.as_deref().map(parse_ip_address).transpose()?;
            let route = route_from_add_route(
                destination,
                gateway,
                &InterfaceRef::Index(*interface_index),
                *metric,
            )?;
            let routes = handle
                .list()
                .await
                .map_err(|error| network_control_io_error("list routes for recovery", error))?;
            if routes
                .iter()
                .any(|candidate| routes_are_equal(candidate, &route))
            {
                handle
                    .delete(&route)
                    .await
                    .map_err(|error| network_control_io_error("recover route", error))?;
            }
            Ok(())
        }
        JournalUndo::RestorePlatformState { namespace, payload } => apply_windows_undo(
            platform,
            &NetworkUndo::RestorePlatformState {
                namespace: namespace.clone(),
                payload: payload.clone(),
            },
        ),
    }
}

fn routes_are_equal(left: &Route, right: &Route) -> bool {
    left.destination == right.destination
        && left.prefix == right.prefix
        && left.gateway == right.gateway
        && left.ifindex == right.ifindex
        && left.metric == right.metric
}

fn parse_ip_address(value: &str) -> Result<IpAddr, NetworkControlError> {
    value.parse::<std::net::IpAddr>().map_err(|error| {
        NetworkControlError::new(format!("invalid IP in recovery journal: {error}"))
    })
}

fn remove_network_journal(lease_id: u64) -> Result<(), NetworkControlError> {
    let path = network_journal_path();
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(NetworkControlError::new(format!(
                "read Windows recovery journal before removal: {error}"
            )));
        }
    };
    let journal: NetworkJournal = serde_json::from_slice(&bytes).map_err(|error| {
        NetworkControlError::new(format!(
            "parse Windows recovery journal before removal: {error}"
        ))
    })?;
    verify_network_journal(&journal)?;
    if journal.lease_id != lease_id {
        return Err(NetworkControlError::new(format!(
            "refusing to remove Windows recovery journal for lease {}; it belongs to lease {}",
            lease_id, journal.lease_id
        )));
    }
    fs::remove_file(path).map_err(|error| {
        NetworkControlError::new(format!("remove Windows recovery journal: {error}"))
    })
}

fn journal_undo(value: &NetworkUndo) -> Result<JournalUndo, NetworkControlError> {
    Ok(match value {
        NetworkUndo::DeleteRoute {
            destination,
            gateway,
            interface,
            metric,
        } => JournalUndo::DeleteRoute {
            destination: destination.to_string(),
            gateway: gateway.map(|value| value.to_string()),
            interface_index: match interface {
                InterfaceRef::Index(index) => *index,
                InterfaceRef::Name(name) => {
                    return Err(NetworkControlError::new(format!(
                        "cannot journal Windows route with interface name `{name}`"
                    )));
                }
            },
            metric: *metric,
        },
        NetworkUndo::RestorePlatformState { namespace, payload } => {
            JournalUndo::RestorePlatformState {
                namespace: namespace.clone(),
                payload: payload.clone(),
            }
        }
    })
}

fn apply_windows_undo(
    platform: &WindowsPlatform,
    undo: &NetworkUndo,
) -> Result<(), NetworkControlError> {
    let NetworkUndo::RestorePlatformState { namespace, payload } = undo else {
        return Err(NetworkControlError::new(
            "route undo requires the async route handle",
        ));
    };
    match namespace.as_str() {
        "windows.dns.v1" => run_powershell_with_env(
            r#"$s=$env:RUSTBOX_SNAPSHOT|ConvertFrom-Json; if($s.version -eq 1){if($s.automatic){Set-DnsClientServerAddress -InterfaceIndex $s.interface_index -ResetServerAddresses -ErrorAction Stop}else{Set-DnsClientServerAddress -InterfaceIndex $s.interface_index -ServerAddresses @($s.servers) -ErrorAction Stop}; exit 0}; foreach($entry in @(@{family='IPv4';state=$s.ipv4},@{family='IPv6';state=$s.ipv6})){$input=Get-DnsClientServerAddress -InterfaceIndex $s.interface_index -AddressFamily $entry.family -ErrorAction Stop; if($entry.state.automatic){$input|Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop}else{$input|Set-DnsClientServerAddress -ServerAddresses @($entry.state.servers) -ErrorAction Stop}}"#,
            &[("RUSTBOX_SNAPSHOT", payload.clone())],
        ),
        "windows.proxy.v1" => run_powershell_with_env(
            r#"$s=$env:RUSTBOX_SNAPSHOT|ConvertFrom-Json; $p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; if($s.enabled_exists){Set-ItemProperty $p ProxyEnable ([int]$s.enabled) -Type DWord}else{Remove-ItemProperty $p ProxyEnable -ErrorAction SilentlyContinue}; if($s.server_exists){Set-ItemProperty $p ProxyServer ([string]$s.server)}else{Remove-ItemProperty $p ProxyServer -ErrorAction SilentlyContinue}; if($s.bypass_exists){Set-ItemProperty $p ProxyOverride ([string]$s.bypass)}else{Remove-ItemProperty $p ProxyOverride -ErrorAction SilentlyContinue}"#,
            &[("RUSTBOX_SNAPSHOT", payload.clone())],
        ),
        "windows.wfp.dynamic.v1" => {
            let lease_id = payload.parse::<u64>().map_err(|error| {
                NetworkControlError::new(format!("invalid WFP lease id: {error}"))
            })?;
            platform
                .wfp_sessions
                .lock()
                .expect("Windows WFP session lock")
                .remove(&lease_id);
            Ok(())
        }
        other => Err(NetworkControlError::new(format!(
            "unknown Windows undo namespace `{other}`"
        ))),
    }
}

fn install_dns_leak_protection(
    tunnel_interface_alias: &str,
) -> Result<wfp::FilterEngine, NetworkControlError> {
    use wfp::{
        ActionType, AppIdConditionBuilder, FilterBuilder, FilterEngineBuilder, FilterWeight,
        InterfaceConditionBuilder, IpAddressConditionBuilder, Layer, PortConditionBuilder,
        ProtocolConditionBuilder, SubLayerBuilder, Transaction,
    };

    const SUBLAYER: wfp::GUID = wfp::GUID::from_u128(0x758a20d7_7e75_4d42_a673_23d277af83d1);
    let app = std::env::current_exe().map_err(|error| {
        NetworkControlError::new(format!("resolve RustBox executable for WFP: {error}"))
    })?;
    let tun = InterfaceConditionBuilder::local()
        .alias(tunnel_interface_alias)
        .map_err(|error| {
            NetworkControlError::new(format!("resolve TUN interface for WFP: {error}"))
        })?
        .build();
    let app = AppIdConditionBuilder::new()
        .equal(app)
        .map_err(|error| {
            NetworkControlError::new(format!("resolve RustBox AppID for WFP: {error}"))
        })?
        .build();
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .map_err(|error| NetworkControlError::new(format!("open WFP engine: {error}")))?;
    let transaction = Transaction::new(&mut engine)
        .map_err(|error| NetworkControlError::new(format!("begin WFP transaction: {error}")))?;
    SubLayerBuilder::default()
        .name("RustBox strict route")
        .description("RustBox dynamic DNS leak protection")
        .guid(SUBLAYER)
        .weight(u16::MAX)
        .add(&transaction)
        .map_err(|error| NetworkControlError::new(format!("add WFP sublayer: {error}")))?;

    for layer in [Layer::ConnectV4, Layer::ConnectV6] {
        FilterBuilder::default()
            .name("RustBox permit TUN")
            .description("Permit traffic selected onto the RustBox TUN")
            .action(ActionType::Permit)
            .layer(layer)
            .sublayer(SUBLAYER)
            .weight(FilterWeight::Exact(u64::MAX))
            .condition(tun.clone())
            .add(&transaction)
            .map_err(|error| NetworkControlError::new(format!("add WFP TUN permit: {error}")))?;
        FilterBuilder::default()
            .name("RustBox permit engine")
            .description("Permit RustBox bootstrap and upstream sockets")
            .action(ActionType::Permit)
            .layer(layer)
            .sublayer(SUBLAYER)
            .weight(FilterWeight::Exact(u64::MAX - 1))
            .condition(app.clone())
            .add(&transaction)
            .map_err(|error| NetworkControlError::new(format!("add WFP AppID permit: {error}")))?;
        let essential_subnets = match layer {
            Layer::ConnectV4 => vec![
                IpAddressConditionBuilder::remote()
                    .subnet_v4(std::net::Ipv4Addr::LOCALHOST, 8)
                    .build(),
                IpAddressConditionBuilder::remote()
                    .subnet_v4(std::net::Ipv4Addr::new(169, 254, 0, 0), 16)
                    .build(),
            ],
            Layer::ConnectV6 => vec![
                IpAddressConditionBuilder::remote()
                    .subnet_v6(std::net::Ipv6Addr::LOCALHOST, 128)
                    .build(),
                IpAddressConditionBuilder::remote()
                    .subnet_v6("fe80::".parse().expect("static IPv6 subnet"), 10)
                    .build(),
            ],
            _ => unreachable!("strict route only installs connect-layer filters"),
        };
        for subnet in essential_subnets {
            FilterBuilder::default()
                .name("RustBox permit local network control")
                .description("Permit loopback and link-local control traffic")
                .action(ActionType::Permit)
                .layer(layer)
                .sublayer(SUBLAYER)
                .weight(FilterWeight::Exact(u64::MAX - 2))
                .condition(subnet)
                .add(&transaction)
                .map_err(|error| {
                    NetworkControlError::new(format!("add WFP local-network permit: {error}"))
                })?;
        }
        for port in [67, 68, 546, 547] {
            FilterBuilder::default()
                .name("RustBox permit DHCP")
                .description("Permit DHCP lease acquisition while fail-closed")
                .action(ActionType::Permit)
                .layer(layer)
                .sublayer(SUBLAYER)
                .weight(FilterWeight::Exact(u64::MAX - 2))
                .condition(ProtocolConditionBuilder::udp().build())
                .condition(PortConditionBuilder::remote().equal(port).build())
                .add(&transaction)
                .map_err(|error| {
                    NetworkControlError::new(format!("add WFP DHCP permit: {error}"))
                })?;
        }
        for (name, protocol) in [
            ("TCP", ProtocolConditionBuilder::tcp().build()),
            ("UDP", ProtocolConditionBuilder::udp().build()),
        ] {
            FilterBuilder::default()
                .name(format!("RustBox block plaintext DNS over {name}"))
                .description("Block port 53 outside RustBox and its TUN")
                .action(ActionType::Block)
                .layer(layer)
                .sublayer(SUBLAYER)
                .weight(FilterWeight::Exact(u64::MAX - 3))
                .condition(protocol)
                .condition(PortConditionBuilder::remote().equal(53).build())
                .add(&transaction)
                .map_err(|error| NetworkControlError::new(format!("add WFP DNS block: {error}")))?;
        }
        FilterBuilder::default()
            .name("RustBox strict-route fail closed")
            .description("Block traffic that bypasses the RustBox TUN")
            .action(ActionType::Block)
            .layer(layer)
            .sublayer(SUBLAYER)
            .weight(FilterWeight::Exact(u64::MAX - 4))
            .add(&transaction)
            .map_err(|error| {
                NetworkControlError::new(format!("add WFP strict-route block: {error}"))
            })?;
    }
    transaction
        .commit()
        .map_err(|error| NetworkControlError::new(format!("commit WFP transaction: {error}")))?;
    Ok(engine)
}

fn route_delete_undo(route: &Route) -> Result<NetworkUndo, NetworkControlError> {
    Ok(NetworkUndo::DeleteRoute {
        destination: IpCidr::new(route.destination, route.prefix)
            .ok_or_else(|| NetworkControlError::new("applied Windows route has invalid prefix"))?,
        gateway: route.gateway,
        interface: InterfaceRef::Index(route.ifindex.ok_or_else(|| {
            NetworkControlError::new("applied Windows route has no interface index")
        })?),
        metric: route.metric,
    })
}

fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn run_powershell(script: &str) -> Result<(), NetworkControlError> {
    run_powershell_with_env(script, &[])
}

fn run_powershell_with_env(
    script: &str,
    env: &[(&str, String)],
) -> Result<(), NetworkControlError> {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().map_err(|err| {
        NetworkControlError::new(format!("start PowerShell network command: {err}"))
    })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NetworkControlError::new(format!(
            "PowerShell network command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn run_powershell_capture(
    script: &str,
    env: &[(&str, String)],
) -> Result<String, NetworkControlError> {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().map_err(|err| {
        NetworkControlError::new(format!("start PowerShell snapshot command: {err}"))
    })?;
    if !output.status.success() {
        return Err(NetworkControlError::new(format!(
            "PowerShell snapshot command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() {
        Err(NetworkControlError::new(
            "PowerShell snapshot returned no state",
        ))
    } else {
        Ok(value)
    }
}

pub(crate) fn route_from_add_route(
    destination: rustbox_types::IpCidr,
    gateway: Option<IpAddr>,
    interface: &InterfaceRef,
    metric: Option<u32>,
) -> Result<Route, NetworkControlError> {
    let max_prefix_len = if destination.address.is_ipv4() {
        32
    } else {
        128
    };
    if destination.prefix_len > max_prefix_len {
        return Err(NetworkControlError::new(format!(
            "invalid route prefix `{}` for destination {}",
            destination.prefix_len, destination.address
        )));
    }

    let mut route = Route::new(destination.address, destination.prefix_len)
        .with_ifindex(interface_index(interface)?);
    if let Some(gateway) = gateway {
        route = route.with_gateway(gateway);
    }
    if let Some(metric) = metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

fn interface_index(interface: &InterfaceRef) -> Result<u32, NetworkControlError> {
    match interface {
        InterfaceRef::Index(index) => Ok(*index),
        InterfaceRef::Name(name) => Err(NetworkControlError::new(format!(
            "net-route AddRoute requires interface index on Windows; got name `{name}`"
        ))),
    }
}

async fn rollback_routes(handle: &RouteHandle, routes: &[Route]) -> bool {
    let mut recovered = true;
    for route in routes.iter().rev() {
        recovered &= handle.delete(route).await.is_ok();
    }
    recovered
}

fn network_control_io_error(action: &str, err: std::io::Error) -> NetworkControlError {
    NetworkControlError::new(format!("{action} failed: {err}"))
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    #[test]
    fn recovery_journal_detects_tampering() {
        let undo = vec![JournalUndo::RestorePlatformState {
            namespace: "windows.dns.v1".into(),
            payload: "snapshot".into(),
        }];
        let mut journal = NetworkJournal {
            version: NETWORK_JOURNAL_VERSION,
            process_id: 42,
            lease_id: 7,
            checksum: network_journal_checksum(NETWORK_JOURNAL_VERSION, 42, 7, &undo)
                .expect("checksum"),
            undo,
        };

        verify_network_journal(&journal).expect("valid journal");
        journal.undo[0] = JournalUndo::RestorePlatformState {
            namespace: "windows.proxy.v1".into(),
            payload: "changed".into(),
        };
        assert!(verify_network_journal(&journal).is_err());
    }
}
