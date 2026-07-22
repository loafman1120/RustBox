use super::*;

impl ProcessLookup for LinuxPlatform {
    fn lookup(
        &self,
        key: ConnectionKey,
    ) -> BoxFuture<'_, Result<Option<ProcessMetadata>, ProcessLookupError>> {
        Box::pin(async move { lookup_linux_process(key).await })
    }
}

async fn lookup_linux_process(
    key: ConnectionKey,
) -> Result<Option<ProcessMetadata>, ProcessLookupError> {
    let protocol = match key.network {
        rustbox_types::Network::Tcp => "-tanp",
        rustbox_types::Network::Udp => "-uanp",
    };
    let output = tokio::process::Command::new("ss")
        .args(["-H", protocol])
        .output()
        .await
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
    let executable_path = tokio::fs::read_link(format!("/proc/{pid}/exe"))
        .await
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let name = executable_path.as_deref().and_then(|path| {
        std::path::Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    Ok(Some(ProcessMetadata {
        pid: Some(pid),
        name,
        path: executable_path,
        package_name: None,
        user_id: None,
        user_name: None,
    }))
}
