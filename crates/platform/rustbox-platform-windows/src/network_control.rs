use super::*;

impl NetworkControl for WindowsPlatform {
    fn apply(
        &self,
        transaction: NetworkTransaction,
    ) -> BoxFuture<'_, Result<NetworkLease, NetworkControlError>> {
        Box::pin(apply_windows_network_transaction(transaction))
    }

    fn release(&self, lease: NetworkLease) -> BoxFuture<'_, Result<(), NetworkControlError>> {
        Box::pin(release_windows_network_lease(lease))
    }
}

async fn apply_windows_network_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    if transaction.operations.is_empty() {
        return Ok(NetworkLease {
            id: 0,
            operations: transaction.operations,
            active: false,
        });
    }

    #[cfg(target_os = "windows")]
    {
        apply_windows_route_transaction(transaction).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(NetworkControlError::new(format!(
            "{}; reason={:?} operations={}",
            network_control_status_message(),
            transaction.reason,
            transaction.operations.len()
        )))
    }
}

#[cfg(target_os = "windows")]
static NEXT_NETWORK_LEASE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "windows")]
async fn apply_windows_route_transaction(
    transaction: NetworkTransaction,
) -> Result<NetworkLease, NetworkControlError> {
    let handle = RouteHandle::new()
        .map_err(|err| network_control_io_error("initialize route handle", err))?;
    let existing = handle
        .list()
        .await
        .map_err(|err| network_control_io_error("list routes", err))?;
    let mut routes = Vec::with_capacity(transaction.operations.len());
    let mut route_operations = Vec::with_capacity(transaction.operations.len());
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
                    routes.push(preserved_route(*destination, &existing)?);
                    route_operations.push(operation.clone());
                }
            }
            NetworkOperation::SetInterfaceDns { .. }
            | NetworkOperation::SetPlatformHttpProxy(_) => deferred.push(operation.clone()),
        }
    }

    let mut applied = Vec::new();
    for route in &routes {
        if let Err(err) = handle.add(route).await {
            if transaction.rollback_policy == RollbackPolicy::Required {
                rollback_routes(&handle, &applied).await;
            }
            return Err(network_control_io_error("add route", err));
        }
        applied.push(route.clone());
    }
    let mut applied_deferred = Vec::new();
    for operation in &deferred {
        if let Err(err) = apply_windows_non_route_operation(operation) {
            rollback_routes(&handle, &applied).await;
            for applied_operation in applied_deferred.iter().rev() {
                let _ = undo_windows_non_route_operation(applied_operation);
            }
            return Err(err);
        }
        applied_deferred.push(operation.clone());
    }

    route_operations.extend(applied_deferred);
    Ok(NetworkLease {
        id: NEXT_NETWORK_LEASE_ID.fetch_add(1, Ordering::Relaxed),
        operations: route_operations,
        active: true,
    })
}

#[cfg(target_os = "windows")]
fn preserved_route(
    destination: rustbox_types::IpCidr,
    routes: &[Route],
) -> Result<Route, NetworkControlError> {
    let address = std_ip_address(destination.address);
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
pub(crate) fn has_exact_route(destination: rustbox_types::IpCidr, routes: &[Route]) -> bool {
    let address = std_ip_address(destination.address);
    routes
        .iter()
        .any(|route| route.prefix == destination.prefix_len && route_contains(route, address))
}

async fn release_windows_network_lease(lease: NetworkLease) -> Result<(), NetworkControlError> {
    if !lease.active || lease.operations.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let handle = RouteHandle::new()
            .map_err(|err| network_control_io_error("initialize route handle", err))?;
        let existing = handle
            .list()
            .await
            .map_err(|err| network_control_io_error("list routes", err))?;
        let mut errors = Vec::new();
        for operation in lease.operations.iter().rev() {
            let route = match operation {
                NetworkOperation::AddRoute {
                    destination,
                    gateway,
                    interface,
                    metric,
                } => route_from_add_route(*destination, *gateway, interface, *metric)?,
                NetworkOperation::PreserveRoute { destination } => {
                    preserved_route(*destination, &existing)?
                }
                NetworkOperation::SetInterfaceDns { .. }
                | NetworkOperation::SetPlatformHttpProxy(_) => {
                    if let Err(err) = undo_windows_non_route_operation(operation) {
                        errors.push(err.message);
                    }
                    continue;
                }
            };
            if let Err(err) = handle.delete(&route).await {
                errors.push(err.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(NetworkControlError::new(format!(
                "release Windows network lease {} failed: {}",
                lease.id,
                errors.join("; ")
            )))
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(NetworkControlError::new(network_control_status_message()))
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_non_route_operation(
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
                .map(|server| format!("'{}'", std_ip_address(*server)))
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
        other => Err(NetworkControlError::new(format!(
            "not a Windows non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn undo_windows_non_route_operation(
    operation: &NetworkOperation,
) -> Result<(), NetworkControlError> {
    match operation {
        NetworkOperation::SetInterfaceDns { interface, .. } => {
            let selector = match interface {
                InterfaceRef::Index(index) => format!("-InterfaceIndex {index}"),
                InterfaceRef::Name(name) => format!("-InterfaceAlias '{}'", ps_quote(name)),
            };
            run_powershell(&format!(
                "Set-DnsClientServerAddress {selector} -ResetServerAddresses -ErrorAction Stop"
            ))
        }
        NetworkOperation::SetPlatformHttpProxy(_) => run_powershell(
            "$path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty $path ProxyEnable 0 -Type DWord",
        ),
        other => Err(NetworkControlError::new(format!(
            "not a Windows non-route operation: {other:?}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<(), NetworkControlError> {
    run_powershell_with_env(script, &[])
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
pub(crate) fn route_from_add_route(
    destination: rustbox_types::IpCidr,
    gateway: Option<IpAddress>,
    interface: &InterfaceRef,
    metric: Option<u32>,
) -> Result<Route, NetworkControlError> {
    if destination.prefix_len > destination.address.max_prefix_len() {
        return Err(NetworkControlError::new(format!(
            "invalid route prefix `{}` for destination {}",
            destination.prefix_len, destination.address
        )));
    }

    let mut route = Route::new(std_ip_address(destination.address), destination.prefix_len)
        .with_ifindex(interface_index(interface)?);
    if let Some(gateway) = gateway {
        route = route.with_gateway(std_ip_address(gateway));
    }
    if let Some(metric) = metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

#[cfg(target_os = "windows")]
fn interface_index(interface: &InterfaceRef) -> Result<u32, NetworkControlError> {
    match interface {
        InterfaceRef::Index(index) => Ok(*index),
        InterfaceRef::Name(name) => Err(NetworkControlError::new(format!(
            "net-route AddRoute requires interface index on Windows; got name `{name}`"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn std_ip_address(address: IpAddress) -> std::net::IpAddr {
    match address {
        IpAddress::V4(octets) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
    }
}

#[cfg(target_os = "windows")]
async fn rollback_routes(handle: &RouteHandle, routes: &[Route]) {
    for route in routes.iter().rev() {
        let _ = handle.delete(route).await;
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
fn network_control_io_error(action: &str, err: std::io::Error) -> NetworkControlError {
    NetworkControlError::new(format!("{action} failed: {err}"))
}
