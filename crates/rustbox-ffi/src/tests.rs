use super::*;
use std::ffi::CStr;
use std::ptr;

unsafe extern "C" {
    fn rustbox_ffi_c_snapshot_size() -> usize;
    fn rustbox_ffi_c_metrics_size() -> usize;
    fn rustbox_ffi_c_call_abi_version() -> u32;
    fn rustbox_ffi_c_lifecycle_smoke() -> u32;
}

fn diagnostic_message(diagnostic: &RustBoxFfiDiagnostic) -> String {
    if diagnostic.message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(diagnostic.message) }
            .to_string_lossy()
            .into_owned()
    }
}

fn clear(diagnostic: &mut RustBoxFfiDiagnostic) {
    unsafe { rustbox_diagnostic_clear(diagnostic) };
}

#[test]
fn owns_the_complete_engine_lifecycle() {
    let mut diagnostic = RustBoxFfiDiagnostic::default();
    let mut handle = RustBoxEngineHandle(0);
    assert_eq!(
        rustbox_engine_create_default_http_proxy(0, &mut handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    assert!(diagnostic.message.is_null());

    assert_eq!(
        rustbox_engine_start(handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    let mut snapshot = RustBoxFfiEngineSnapshot {
        state: RustBoxEngineStateCode::Failed,
        generation: 0,
        inbound_count: 0,
        outbound_count: 0,
    };
    assert_eq!(
        rustbox_engine_snapshot(handle, &mut snapshot, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    assert_eq!(snapshot.state, RustBoxEngineStateCode::Running);
    let mut metrics = RustBoxFfiMetricsSnapshot::default();
    assert_eq!(
        rustbox_engine_metrics(handle, &mut metrics, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    assert_eq!(metrics.services_started, 1);

    assert_eq!(
        rustbox_engine_stop(handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    assert_eq!(
        rustbox_engine_destroy(handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
}

#[test]
fn creates_and_reloads_toml() {
    let config = br#"
schema_version = 1
[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:0"
[[outbounds]]
id = "direct"
type = "direct"
[[routes]]
type = "default"
outbound = "direct"
"#;
    let mut diagnostic = RustBoxFfiDiagnostic::default();
    let mut handle = RustBoxEngineHandle(0);
    assert_eq!(
        rustbox_engine_create_from_config_toml(
            config.as_ptr(),
            config.len(),
            &mut handle,
            &mut diagnostic,
        ),
        RustBoxStatusCode::Ok
    );
    assert_eq!(
        rustbox_engine_reload_config_toml(handle, config.as_ptr(), config.len(), &mut diagnostic,),
        RustBoxStatusCode::Ok
    );
    assert_eq!(
        rustbox_engine_destroy(handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
}

#[test]
fn reports_pointer_and_handle_errors() {
    let mut diagnostic = RustBoxFfiDiagnostic::default();
    assert_eq!(
        rustbox_engine_create_default_http_proxy(0, ptr::null_mut(), &mut diagnostic),
        RustBoxStatusCode::InvalidArgument
    );
    assert_eq!(
        diagnostic_message(&diagnostic),
        "output pointer must not be null"
    );
    clear(&mut diagnostic);

    let mut snapshot = RustBoxFfiEngineSnapshot {
        state: RustBoxEngineStateCode::Created,
        generation: 0,
        inbound_count: 0,
        outbound_count: 0,
    };
    assert_eq!(
        rustbox_engine_snapshot(
            RustBoxEngineHandle(u64::MAX),
            &mut snapshot,
            &mut diagnostic,
        ),
        RustBoxStatusCode::NotFound
    );
    assert_eq!(diagnostic_message(&diagnostic), "unknown handle");
    clear(&mut diagnostic);
}

#[test]
fn exposes_expected_abi_layout() {
    assert_eq!(rustbox_ffi_abi_version(), 1);
    assert_eq!(std::mem::size_of::<RustBoxEngineHandle>(), 8);
    assert_eq!(std::mem::size_of::<RustBoxStatusCode>(), 4);
    assert_eq!(std::mem::size_of::<RustBoxEngineStateCode>(), 4);
    assert_eq!(std::mem::size_of::<RustBoxFfiEngineSnapshot>(), 32);
    assert_eq!(std::mem::size_of::<RustBoxFfiMetricsSnapshot>(), 112);
    assert_eq!(unsafe { rustbox_ffi_c_snapshot_size() }, 32);
    assert_eq!(unsafe { rustbox_ffi_c_metrics_size() }, 112);
    assert_eq!(unsafe { rustbox_ffi_c_call_abi_version() }, 1);
}

#[test]
fn c_binding_owns_the_complete_engine_lifecycle() {
    assert_eq!(unsafe { rustbox_ffi_c_lifecycle_smoke() }, 0);
}
