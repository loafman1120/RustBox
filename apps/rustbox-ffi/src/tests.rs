use super::*;
use std::ffi::CStr;
use std::ptr;

unsafe extern "C" {
    fn rustbox_ffi_c_snapshot_size() -> usize;
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

const HTTP_CONFIG: &[u8] = br#"
schema_version = 1
[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:0"
[[outbounds]]
id = "direct"
type = "direct"
[[routes]]
type = "default"
outbound = "direct"
"#;

#[test]
fn submits_lifecycle_without_blocking_the_caller() {
    let mut diagnostic = RustBoxFfiDiagnostic::default();
    let mut handle = RustBoxEngineHandle(0);
    assert_eq!(
        rustbox_engine_create(
            HTTP_CONFIG.as_ptr(),
            HTTP_CONFIG.len(),
            &mut handle,
            &mut diagnostic,
        ),
        RustBoxStatusCode::Ok
    );

    let mut request = RustBoxRequestHandle(0);
    assert_eq!(
        rustbox_engine_start(handle, &mut request, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    assert_ne!(request.0, 0);

    let mut state = RustBoxRequestStateCode::Pending;
    loop {
        assert_eq!(
            rustbox_engine_request_poll(handle, request, &mut state, &mut diagnostic),
            RustBoxStatusCode::Ok
        );
        if state == RustBoxRequestStateCode::Succeeded {
            break;
        }
        assert_eq!(state, RustBoxRequestStateCode::Pending);
        std::thread::yield_now();
    }

    let mut stop = RustBoxRequestHandle(0);
    assert_eq!(
        rustbox_engine_stop(handle, &mut stop, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
    loop {
        assert_eq!(
            rustbox_engine_request_poll(handle, stop, &mut state, &mut diagnostic),
            RustBoxStatusCode::Ok
        );
        if state == RustBoxRequestStateCode::Succeeded {
            break;
        }
        std::thread::yield_now();
    }
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
        rustbox_engine_create(config.as_ptr(), config.len(), &mut handle, &mut diagnostic,),
        RustBoxStatusCode::Ok
    );
    let mut request = RustBoxRequestHandle(0);
    assert_eq!(
        rustbox_engine_reload(
            handle,
            config.as_ptr(),
            config.len(),
            &mut request,
            &mut diagnostic,
        ),
        RustBoxStatusCode::Ok
    );
    let mut state = RustBoxRequestStateCode::Pending;
    while state == RustBoxRequestStateCode::Pending {
        assert_eq!(
            rustbox_engine_request_poll(handle, request, &mut state, &mut diagnostic),
            RustBoxStatusCode::Ok
        );
    }
    assert_eq!(state, RustBoxRequestStateCode::Succeeded);
    assert_eq!(
        rustbox_engine_destroy(handle, &mut diagnostic),
        RustBoxStatusCode::Ok
    );
}

#[test]
fn reports_pointer_and_handle_errors() {
    let mut diagnostic = RustBoxFfiDiagnostic::default();
    assert_eq!(
        rustbox_engine_create(
            HTTP_CONFIG.as_ptr(),
            HTTP_CONFIG.len(),
            ptr::null_mut(),
            &mut diagnostic,
        ),
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
    assert_eq!(rustbox_ffi_abi_version(), 2);
    assert_eq!(std::mem::size_of::<RustBoxEngineHandle>(), 8);
    assert_eq!(std::mem::size_of::<RustBoxStatusCode>(), 4);
    assert_eq!(std::mem::size_of::<RustBoxEngineStateCode>(), 4);
    assert_eq!(std::mem::size_of::<RustBoxFfiEngineSnapshot>(), 32);
    assert_eq!(unsafe { rustbox_ffi_c_snapshot_size() }, 32);
    assert_eq!(unsafe { rustbox_ffi_c_call_abi_version() }, 2);
}

#[test]
fn c_binding_owns_the_complete_engine_lifecycle() {
    assert_eq!(unsafe { rustbox_ffi_c_lifecycle_smoke() }, 0);
}
