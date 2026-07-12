use super::*;

impl ProcessLookup for WindowsPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>> {
        Box::pin(async move { lookup_windows_process(key) })
    }
}

#[cfg(target_os = "windows")]
fn lookup_windows_process(key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    let command = match key.network {
        rustbox_types::Network::Tcp => "Get-NetTCPConnection",
        rustbox_types::Network::Udp => "Get-NetUDPEndpoint",
    };
    let script = format!(
        "$c={command} -LocalPort {} -ErrorAction SilentlyContinue | Select-Object -First 1; if($null -ne $c){{$p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; Write-Output $c.OwningProcess; Write-Output $p.Path}}",
        key.local.port
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|err| ProcessLookupError::new(format!("start process lookup: {err}")))?;
    if !output.status.success() {
        return Err(ProcessLookupError::new(format!(
            "{}: {}",
            process_lookup_status_message(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let Some(pid) = lines
        .next()
        .and_then(|line| line.trim().parse::<u32>().ok())
    else {
        return Ok(None);
    };
    let path = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(Some(ProcessInfo {
        pid: Some(pid),
        executable_path: path,
        package_name: None,
        user_id: None,
    }))
}

#[cfg(not(target_os = "windows"))]
fn lookup_windows_process(_key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    Err(ProcessLookupError::new(process_lookup_status_message()))
}

#[cfg(not(target_os = "windows"))]
fn process_lookup_status_message() -> &'static str {
    "Windows process lookup is unavailable on this target"
}
