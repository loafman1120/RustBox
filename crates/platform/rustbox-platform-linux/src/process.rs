use super::*;

impl ProcessLookup for LinuxPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessInfo>, ProcessLookupError>> {
        Box::pin(async move { lookup_linux_process(key) })
    }
}

#[cfg(target_os = "linux")]
fn lookup_linux_process(key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    let protocol = match key.network {
        rustbox_types::Network::Tcp => "-tanp",
        rustbox_types::Network::Udp => "-uanp",
    };
    let output = Command::new("ss")
        .args(["-H", protocol])
        .output()
        .map_err(|err| ProcessLookupError::new(format!("start ss process lookup: {err}")))?;
    if !output.status.success() {
        return Err(ProcessLookupError::new(format!(
            "{}: {}",
            process_lookup_status_message(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let port_marker = format!(":{}", key.local.port);
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains(&port_marker) && line.contains("pid="))
        .map(str::to_owned);
    let Some(line) = line else {
        return Ok(None);
    };
    let Some(pid) = line
        .split("pid=")
        .nth(1)
        .and_then(|tail| {
            tail.split(|character: char| !character.is_ascii_digit())
                .next()
        })
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(None);
    };
    let executable_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    Ok(Some(ProcessInfo {
        pid: Some(pid),
        executable_path,
        package_name: None,
        user_id: None,
    }))
}

#[cfg(not(target_os = "linux"))]
fn lookup_linux_process(_key: ConnectionKey) -> Result<Option<ProcessInfo>, ProcessLookupError> {
    Err(ProcessLookupError::new(process_lookup_status_message()))
}

#[cfg(not(target_os = "linux"))]
fn process_lookup_status_message() -> &'static str {
    "Linux process lookup is unavailable on this target"
}
