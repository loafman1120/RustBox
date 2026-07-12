#include "rustbox.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RustBoxEngineHandle) == 8, "engine handle must be 64-bit");
_Static_assert(sizeof(RustBoxStatusCode) == 4, "status code must match repr(C)");
_Static_assert(sizeof(RustBoxEngineStateCode) == 4, "state code must match repr(C)");
_Static_assert(sizeof(RustBoxFfiEngineSnapshot) == 32, "snapshot layout changed");
_Static_assert(sizeof(RustBoxFfiMetricsSnapshot) == 112, "metrics layout changed");
#endif

size_t rustbox_ffi_c_snapshot_size(void) {
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle handle = 0;
    RustBoxFfiEngineSnapshot snapshot = { RUSTBOX_ENGINE_CREATED, 0, 0, 0 };
    (void)diagnostic;
    (void)handle;
    (void)snapshot;
    return sizeof(RustBoxFfiEngineSnapshot);
}

size_t rustbox_ffi_c_metrics_size(void) {
    return sizeof(RustBoxFfiMetricsSnapshot);
}

uint32_t rustbox_ffi_c_call_abi_version(void) {
    return rustbox_ffi_abi_version();
}
