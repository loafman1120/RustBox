#include "rustbox.h"

/* Executed by the Rust test binary after this file has been compiled by the
 * platform C compiler and linked against the Rust exports. */
uint32_t rustbox_ffi_c_lifecycle_smoke(void) {
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle engine = 0;
    RustBoxFfiEngineSnapshot snapshot = { RUSTBOX_ENGINE_CREATED, 0, 0, 0 };
    RustBoxFfiMetricsSnapshot metrics = { 0 };
    RustBoxStatusCode status;

    status = rustbox_engine_create_default_http_proxy(0, &engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || engine == 0) {
        rustbox_diagnostic_clear(&diagnostic);
        return 1;
    }

    status = rustbox_engine_start(engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK) {
        rustbox_diagnostic_clear(&diagnostic);
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
        return 2;
    }

    status = rustbox_engine_snapshot(engine, &snapshot, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || snapshot.state != RUSTBOX_ENGINE_RUNNING) {
        rustbox_diagnostic_clear(&diagnostic);
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
        return 3;
    }

    status = rustbox_engine_metrics(engine, &metrics, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || metrics.services_started == 0) {
        rustbox_diagnostic_clear(&diagnostic);
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
        return 4;
    }

    status = rustbox_engine_stop(engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK) {
        rustbox_diagnostic_clear(&diagnostic);
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
        return 5;
    }

    status = rustbox_engine_destroy(engine, &diagnostic);
    rustbox_diagnostic_clear(&diagnostic);
    return status == RUSTBOX_STATUS_OK ? 0 : 6;
}
