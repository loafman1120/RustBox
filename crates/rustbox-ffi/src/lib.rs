//! 基于不透明句柄的粗粒度 FFI 边界。
//!
//! 本 crate 只把共享的 `RustBox` 接口翻译成 C ABI：句柄、状态码和字节串。
//! 配置、装配和生命周期语义不在 FFI 层重复实现。

use rustbox::{RustBox, RustBoxError};
use rustbox_config::SourceConfig;
use rustbox_config_file::{ConfigFileError, parse_toml_str};
use rustbox_control::{EngineSnapshot, EngineState};
use rustbox_types::Endpoint;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};
use tokio::runtime::{Builder, Runtime};

const RUSTBOX_FFI_ABI_VERSION: u32 = 1;

/// C ABI 暴露的引擎句柄。宿主只能传回该值，不能解引用内部对象。
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustBoxEngineHandle(pub u64);

/// C ABI 稳定状态码，用于跨语言调用时替代 Rust error/enum。
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxStatusCode {
    Ok = 0,
    InvalidConfig = 1,
    NotFound = 2,
    AlreadyRunning = 3,
    RuntimeError = 4,
    InvalidArgument = 5,
    LockPoisoned = 6,
}

/// C ABI 可见的引擎状态镜像。
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustBoxEngineStateCode {
    Created = 0,
    Prepared = 1,
    Running = 2,
    Stopping = 3,
    Stopped = 4,
    Failed = 5,
}

/// C ABI 快照结构，只包含值类型字段，避免暴露 Rust 所有权。
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustBoxFfiEngineSnapshot {
    pub state: RustBoxEngineStateCode,
    pub generation: u64,
    pub inbound_count: u64,
    pub outbound_count: u64,
}

/// Rust 分配的诊断字符串由调用方通过 `rustbox_diagnostic_message_free` 释放。
#[repr(C)]
#[derive(Debug)]
pub struct RustBoxFfiDiagnostic {
    pub code: RustBoxStatusCode,
    pub message: *mut c_char,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustBoxFfiError {
    pub code: RustBoxStatusCode,
    pub diagnostic: String,
}

impl RustBoxFfiError {
    pub fn new(code: RustBoxStatusCode, diagnostic: impl Into<String>) -> Self {
        Self {
            code,
            diagnostic: diagnostic.into(),
        }
    }
}

/// Rust 侧维护的引擎句柄表，是 FFI 和真实运行图之间的隔离层。
pub struct FfiEngineTable {
    next: u64,
    engines: HashMap<RustBoxEngineHandle, ManagedEngine>,
}

impl FfiEngineTable {
    pub fn new() -> Self {
        Self {
            next: 1,
            engines: HashMap::new(),
        }
    }

    pub fn validate(source: SourceConfig) -> Result<(), RustBoxFfiError> {
        RustBox::new(source).map_err(compose_error)?;
        Ok(())
    }

    pub fn create_default_http_proxy(
        &mut self,
        listen: Endpoint,
    ) -> Result<RustBoxEngineHandle, RustBoxFfiError> {
        self.create_with_source(SourceConfig::default_http_proxy(listen))
    }

    pub fn create_default_socks5_proxy(
        &mut self,
        listen: Endpoint,
    ) -> Result<RustBoxEngineHandle, RustBoxFfiError> {
        self.create_with_source(SourceConfig::default_socks5_proxy(listen))
    }

    pub fn create_from_source(
        &mut self,
        source: SourceConfig,
    ) -> Result<RustBoxEngineHandle, RustBoxFfiError> {
        self.create_with_source(source)
    }

    fn create_with_source(
        &mut self,
        source: SourceConfig,
    ) -> Result<RustBoxEngineHandle, RustBoxFfiError> {
        let engine = RustBox::new(source).map_err(compose_error)?;
        let handle = RustBoxEngineHandle(self.next);
        self.next = self.next.saturating_add(1);
        self.engines.insert(
            handle,
            ManagedEngine {
                engine,
                runtime: None,
            },
        );
        Ok(handle)
    }

    pub fn snapshot(&self, handle: RustBoxEngineHandle) -> Result<EngineSnapshot, RustBoxFfiError> {
        self.engines
            .get(&handle)
            .map(|managed| managed.engine.snapshot().clone())
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))
    }

    pub fn destroy(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        let Some(mut managed) = self.engines.remove(&handle) else {
            return Err(RustBoxFfiError::new(
                RustBoxStatusCode::NotFound,
                "unknown handle",
            ));
        };
        if let Some(runtime) = managed.runtime.take() {
            runtime
                .block_on(managed.engine.stop())
                .map_err(compose_error)?;
        }
        Ok(())
    }

    pub fn start_blocking(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        let managed = self
            .engines
            .get_mut(&handle)
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))?;
        if managed.engine.snapshot().state == EngineState::Running {
            return Err(RustBoxFfiError::new(
                RustBoxStatusCode::AlreadyRunning,
                "engine is already running",
            ));
        }

        let runtime = new_runtime()?;
        runtime
            .block_on(managed.engine.start())
            .map_err(compose_error)?;
        managed.runtime = Some(runtime);
        Ok(())
    }

    pub fn stop_blocking(&mut self, handle: RustBoxEngineHandle) -> Result<(), RustBoxFfiError> {
        let managed = self
            .engines
            .get_mut(&handle)
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))?;
        if let Some(runtime) = managed.runtime.take() {
            runtime
                .block_on(managed.engine.stop())
                .map_err(compose_error)?;
        }
        Ok(())
    }

    pub fn reload_default_http_proxy_blocking(
        &mut self,
        handle: RustBoxEngineHandle,
        listen: Endpoint,
    ) -> Result<(), RustBoxFfiError> {
        self.reload_source_blocking(handle, SourceConfig::default_http_proxy(listen))
    }

    pub fn reload_default_socks5_proxy_blocking(
        &mut self,
        handle: RustBoxEngineHandle,
        listen: Endpoint,
    ) -> Result<(), RustBoxFfiError> {
        self.reload_source_blocking(handle, SourceConfig::default_socks5_proxy(listen))
    }

    fn reload_source_blocking(
        &mut self,
        handle: RustBoxEngineHandle,
        next_source: SourceConfig,
    ) -> Result<(), RustBoxFfiError> {
        let managed = self
            .engines
            .get_mut(&handle)
            .ok_or_else(|| RustBoxFfiError::new(RustBoxStatusCode::NotFound, "unknown handle"))?;

        let owned_runtime = managed.runtime.take();
        let runtime = match owned_runtime {
            Some(runtime) => runtime,
            None => new_runtime()?,
        };
        let result = runtime
            .block_on(managed.engine.reload(next_source))
            .map_err(compose_error);
        if managed.engine.snapshot().state == EngineState::Running {
            managed.runtime = Some(runtime);
        }
        result
    }
}

impl Default for FfiEngineTable {
    fn default() -> Self {
        Self::new()
    }
}

struct ManagedEngine {
    engine: RustBox,
    runtime: Option<Runtime>,
}

fn parse_toml_source(bytes: *const u8, len: usize) -> Result<SourceConfig, RustBoxFfiError> {
    // FFI 指针入口只负责边界检查和文本转换，随后立即进入统一配置流水线。
    if bytes.is_null() {
        return Err(RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            "config bytes pointer must not be null",
        ));
    }

    let bytes = unsafe { slice::from_raw_parts(bytes, len) };
    let text = std::str::from_utf8(bytes).map_err(|err| {
        RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            format!("config bytes must be UTF-8: {err}"),
        )
    })?;
    parse_toml_str(text)
        .map(|config| config.source)
        .map_err(config_file_error)
}

fn new_runtime() -> Result<Runtime, RustBoxFfiError> {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, err.to_string()))
}

fn config_file_error(err: ConfigFileError) -> RustBoxFfiError {
    RustBoxFfiError::new(RustBoxStatusCode::InvalidConfig, err.message)
}

fn compose_error(err: RustBoxError) -> RustBoxFfiError {
    RustBoxFfiError::new(RustBoxStatusCode::RuntimeError, format!("{err:?}"))
}

fn ffi_table() -> &'static Mutex<FfiEngineTable> {
    static TABLE: OnceLock<Mutex<FfiEngineTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(FfiEngineTable::new()))
}

fn ffi_result(
    result: Result<(), RustBoxFfiError>,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match result {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(err) => {
            let code = err.code;
            write_diagnostic(diagnostic, err.code, &err.diagnostic);
            code
        }
    }
}

fn with_table<T>(
    diagnostic: *mut RustBoxFfiDiagnostic,
    f: impl FnOnce(&mut FfiEngineTable) -> Result<T, RustBoxFfiError>,
) -> Result<T, RustBoxStatusCode> {
    match ffi_table().lock() {
        Ok(mut table) => f(&mut table).map_err(|err| {
            let code = err.code;
            write_diagnostic(diagnostic, err.code, &err.diagnostic);
            code
        }),
        Err(_) => {
            write_diagnostic(
                diagnostic,
                RustBoxStatusCode::LockPoisoned,
                "FFI engine table lock is poisoned",
            );
            Err(RustBoxStatusCode::LockPoisoned)
        }
    }
}

fn write_out<T>(out: *mut T, value: T) -> Result<(), RustBoxFfiError> {
    if out.is_null() {
        return Err(RustBoxFfiError::new(
            RustBoxStatusCode::InvalidArgument,
            "output pointer must not be null",
        ));
    }
    unsafe {
        out.write(value);
    }
    Ok(())
}

fn write_diagnostic(diagnostic: *mut RustBoxFfiDiagnostic, code: RustBoxStatusCode, message: &str) {
    // 诊断内存由 Rust 分配，保证嵌套字符串所有权规则集中在一个释放函数里。
    if diagnostic.is_null() {
        return;
    }
    let message = diagnostic_c_string(message).into_raw();
    unsafe {
        diagnostic.write(RustBoxFfiDiagnostic { code, message });
    }
}

fn diagnostic_c_string(message: &str) -> CString {
    match CString::new(message) {
        Ok(message) => message,
        Err(err) => {
            let bytes = err
                .into_vec()
                .into_iter()
                .map(|byte| if byte == 0 { b'?' } else { byte })
                .collect::<Vec<_>>();
            CString::new(bytes).expect("nul bytes were replaced")
        }
    }
}

impl From<EngineSnapshot> for RustBoxFfiEngineSnapshot {
    fn from(snapshot: EngineSnapshot) -> Self {
        Self {
            state: snapshot.state.into(),
            generation: snapshot.generation,
            inbound_count: snapshot.inbound_count as u64,
            outbound_count: snapshot.outbound_count as u64,
        }
    }
}

impl From<EngineState> for RustBoxEngineStateCode {
    fn from(state: EngineState) -> Self {
        match state {
            EngineState::Created => Self::Created,
            EngineState::Prepared => Self::Prepared,
            EngineState::Running => Self::Running,
            EngineState::Stopping => Self::Stopping,
            EngineState::Stopped => Self::Stopped,
            EngineState::Failed => Self::Failed,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_ffi_abi_version() -> u32 {
    RUSTBOX_FFI_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_default_http_proxy(
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    ffi_result(
        FfiEngineTable::validate(SourceConfig::default_http_proxy(Endpoint::localhost_v4(
            listen_port,
        ))),
        diagnostic,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_default_socks5_proxy(
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    ffi_result(
        FfiEngineTable::validate(SourceConfig::default_socks5_proxy(Endpoint::localhost_v4(
            listen_port,
        ))),
        diagnostic,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_validate_config_toml(
    bytes: *const u8,
    len: usize,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    let result = parse_toml_source(bytes, len).and_then(FfiEngineTable::validate);
    ffi_result(result, diagnostic)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create_default_http_proxy(
    listen_port: u16,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        let handle = table.create_default_http_proxy(Endpoint::localhost_v4(listen_port))?;
        write_out(out_handle, handle)?;
        Ok(())
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create_from_config_toml(
    bytes: *const u8,
    len: usize,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        let source = parse_toml_source(bytes, len)?;
        let handle = table.create_from_source(source)?;
        write_out(out_handle, handle)?;
        Ok(())
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_create_default_socks5_proxy(
    listen_port: u16,
    out_handle: *mut RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        let handle = table.create_default_socks5_proxy(Endpoint::localhost_v4(listen_port))?;
        write_out(out_handle, handle)?;
        Ok(())
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_start(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| table.start_blocking(handle)) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_default_http_proxy(
    handle: RustBoxEngineHandle,
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        table.reload_default_http_proxy_blocking(handle, Endpoint::localhost_v4(listen_port))
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_config_toml(
    handle: RustBoxEngineHandle,
    bytes: *const u8,
    len: usize,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        let source = parse_toml_source(bytes, len)?;
        table.reload_source_blocking(handle, source)
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_reload_default_socks5_proxy(
    handle: RustBoxEngineHandle,
    listen_port: u16,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        table.reload_default_socks5_proxy_blocking(handle, Endpoint::localhost_v4(listen_port))
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_snapshot(
    handle: RustBoxEngineHandle,
    out_snapshot: *mut RustBoxFfiEngineSnapshot,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| {
        let snapshot = table.snapshot(handle)?;
        write_out(out_snapshot, snapshot.into())?;
        Ok(())
    }) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_stop(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| table.stop_blocking(handle)) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustbox_engine_destroy(
    handle: RustBoxEngineHandle,
    diagnostic: *mut RustBoxFfiDiagnostic,
) -> RustBoxStatusCode {
    match with_table(diagnostic, |table| table.destroy(handle)) {
        Ok(()) => {
            write_diagnostic(diagnostic, RustBoxStatusCode::Ok, "");
            RustBoxStatusCode::Ok
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
/// Frees a diagnostic message returned by RustBox FFI functions.
///
/// # Safety
///
/// `message` must be either null or a pointer previously returned in
/// `RustBoxFfiDiagnostic.message` by this library. Passing any other pointer,
/// or freeing the same pointer more than once, is undefined behavior.
pub unsafe extern "C" fn rustbox_diagnostic_message_free(message: *mut c_char) {
    if message.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(message));
    }
}

impl Default for RustBoxFfiDiagnostic {
    fn default() -> Self {
        Self {
            code: RustBoxStatusCode::Ok,
            message: ptr::null_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn creates_snapshots_reloads_and_destroys_through_c_abi() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();
        let mut handle = RustBoxEngineHandle(0);

        let create = rustbox_engine_create_default_http_proxy(0, &mut handle, &mut diagnostic);
        assert_eq!(create, RustBoxStatusCode::Ok);
        assert_ne!(handle.0, 0);
        free_diagnostic(&mut diagnostic);

        let reload = rustbox_engine_reload_default_http_proxy(handle, 0, &mut diagnostic);
        assert_eq!(reload, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let mut snapshot = RustBoxFfiEngineSnapshot {
            state: RustBoxEngineStateCode::Failed,
            generation: 0,
            inbound_count: 0,
            outbound_count: 0,
        };
        let snapshot_code = rustbox_engine_snapshot(handle, &mut snapshot, &mut diagnostic);
        assert_eq!(snapshot_code, RustBoxStatusCode::Ok);
        assert_eq!(snapshot.state, RustBoxEngineStateCode::Prepared);
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.inbound_count, 1);
        assert_eq!(snapshot.outbound_count, 1);
        free_diagnostic(&mut diagnostic);

        let destroy = rustbox_engine_destroy(handle, &mut diagnostic);
        assert_eq!(destroy, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);
    }

    #[test]
    fn starts_and_stops_runtime_through_c_abi() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();
        let mut handle = RustBoxEngineHandle(0);

        let create = rustbox_engine_create_default_http_proxy(0, &mut handle, &mut diagnostic);
        assert_eq!(create, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let start = rustbox_engine_start(handle, &mut diagnostic);
        assert_eq!(start, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let mut snapshot = RustBoxFfiEngineSnapshot {
            state: RustBoxEngineStateCode::Failed,
            generation: 0,
            inbound_count: 0,
            outbound_count: 0,
        };
        let snapshot_code = rustbox_engine_snapshot(handle, &mut snapshot, &mut diagnostic);
        assert_eq!(snapshot_code, RustBoxStatusCode::Ok);
        assert_eq!(snapshot.state, RustBoxEngineStateCode::Running);
        assert_eq!(snapshot.inbound_count, 1);
        assert_eq!(snapshot.outbound_count, 1);
        free_diagnostic(&mut diagnostic);

        let stop = rustbox_engine_stop(handle, &mut diagnostic);
        assert_eq!(stop, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let snapshot_code = rustbox_engine_snapshot(handle, &mut snapshot, &mut diagnostic);
        assert_eq!(snapshot_code, RustBoxStatusCode::Ok);
        assert_eq!(snapshot.state, RustBoxEngineStateCode::Stopped);
        free_diagnostic(&mut diagnostic);

        let restart = rustbox_engine_start(handle, &mut diagnostic);
        assert_eq!(restart, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);
        let stop = rustbox_engine_stop(handle, &mut diagnostic);
        assert_eq!(stop, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let destroy = rustbox_engine_destroy(handle, &mut diagnostic);
        assert_eq!(destroy, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);
    }

    #[test]
    fn creates_reloads_and_destroys_toml_config_through_c_abi() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();
        let mut handle = RustBoxEngineHandle(0);
        let config = sample_toml_config();

        let create = rustbox_engine_create_from_config_toml(
            config.as_ptr(),
            config.len(),
            &mut handle,
            &mut diagnostic,
        );
        assert_eq!(create, RustBoxStatusCode::Ok);
        assert_ne!(handle.0, 0);
        free_diagnostic(&mut diagnostic);

        let reload = rustbox_engine_reload_config_toml(
            handle,
            config.as_ptr(),
            config.len(),
            &mut diagnostic,
        );
        assert_eq!(reload, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);

        let destroy = rustbox_engine_destroy(handle, &mut diagnostic);
        assert_eq!(destroy, RustBoxStatusCode::Ok);
        free_diagnostic(&mut diagnostic);
    }

    #[test]
    fn not_found_error_returns_utf8_diagnostic() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();
        let mut snapshot = RustBoxFfiEngineSnapshot {
            state: RustBoxEngineStateCode::Created,
            generation: 0,
            inbound_count: 0,
            outbound_count: 0,
        };

        let code = rustbox_engine_snapshot(
            RustBoxEngineHandle(u64::MAX),
            &mut snapshot,
            &mut diagnostic,
        );

        assert_eq!(code, RustBoxStatusCode::NotFound);
        assert_eq!(diagnostic_message(&diagnostic), "unknown handle");
        free_diagnostic(&mut diagnostic);
    }

    #[test]
    fn null_output_pointer_is_invalid_argument() {
        let mut diagnostic = RustBoxFfiDiagnostic::default();

        let code = rustbox_engine_create_default_http_proxy(0, ptr::null_mut(), &mut diagnostic);

        assert_eq!(code, RustBoxStatusCode::InvalidArgument);
        assert_eq!(
            diagnostic_message(&diagnostic),
            "output pointer must not be null"
        );
        free_diagnostic(&mut diagnostic);
    }

    fn diagnostic_message(diagnostic: &RustBoxFfiDiagnostic) -> String {
        if diagnostic.message.is_null() {
            return String::new();
        }
        unsafe {
            CStr::from_ptr(diagnostic.message)
                .to_string_lossy()
                .into_owned()
        }
    }

    fn free_diagnostic(diagnostic: &mut RustBoxFfiDiagnostic) {
        unsafe {
            rustbox_diagnostic_message_free(diagnostic.message);
        }
        diagnostic.message = ptr::null_mut();
    }

    fn sample_toml_config() -> Vec<u8> {
        br#"
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
"#
        .to_vec()
    }
}
