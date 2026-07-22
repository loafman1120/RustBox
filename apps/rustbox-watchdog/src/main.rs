use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let Some((parent_pid, parent_start_time)) = parse_parent_identity() else {
        eprintln!("usage: rustbox-watchdog --parent-pid <pid> --parent-start-time <seconds>");
        std::process::exit(2);
    };

    while process_instance_is_alive(parent_pid, parent_start_time) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if let Err(error) = rustbox_platform::recover_stale_network_state().await {
        eprintln!("RustBox crash recovery failed: {error}");
        std::process::exit(1);
    }
}

fn parse_parent_identity() -> Option<(u32, u64)> {
    let mut arguments = std::env::args().skip(1);
    let mut pid = None;
    let mut start_time = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--parent-pid" => pid = arguments.next()?.parse().ok(),
            "--parent-start-time" => start_time = arguments.next()?.parse().ok(),
            _ => return None,
        }
    }
    Some((pid?, start_time?))
}

fn process_instance_is_alive(pid: u32, expected_start_time: u64) -> bool {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system
        .process(pid)
        .is_some_and(|process| process.start_time() == expected_start_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_the_current_process_instance_from_a_reused_pid() {
        let pid = std::process::id();
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
        let start_time = system
            .process(Pid::from_u32(pid))
            .expect("current process")
            .start_time();

        assert!(process_instance_is_alive(pid, start_time));
        assert!(!process_instance_is_alive(
            pid,
            start_time.saturating_add(1)
        ));
    }
}
