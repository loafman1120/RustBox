#include "rustbox.h"

static RustBoxStatusCode await_request(
    RustBoxEngineHandle engine,
    RustBoxRequestHandle request,
    RustBoxFfiDiagnostic *diagnostic) {
    RustBoxRequestStateCode state = RUSTBOX_REQUEST_PENDING;
    RustBoxStatusCode status;
    while (state == RUSTBOX_REQUEST_PENDING) {
        status = rustbox_engine_request_poll(engine, request, &state, diagnostic);
        if (status != RUSTBOX_STATUS_OK) return status;
    }
    return state == RUSTBOX_REQUEST_SUCCEEDED
        ? RUSTBOX_STATUS_OK : RUSTBOX_STATUS_RUNTIME_ERROR;
}

/* Executed by the Rust test binary after this file has been compiled by the
 * platform C compiler and linked against the Rust exports. */
uint32_t rustbox_ffi_c_lifecycle_smoke(void) {
    static const char config[] =
        "schema_version = 1\n"
        "[[inbounds]]\nid = \"http\"\ntype = \"http-connect\"\n"
        "listen = \"127.0.0.1:0\"\n"
        "[[outbounds]]\nid = \"direct\"\ntype = \"direct\"\n"
        "[[routes]]\ntype = \"default\"\noutbound = \"direct\"\n";
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle engine = 0;
    RustBoxFfiEngineSnapshot snapshot = { RUSTBOX_ENGINE_CREATED, 0, 0, 0 };
    RustBoxStatusCode status;
    RustBoxRequestHandle request = 0;

    status = rustbox_engine_create(
        (const uint8_t *)config, sizeof(config) - 1, &engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || engine == 0) {
        rustbox_diagnostic_clear(&diagnostic);
        return 1;
    }

    status = rustbox_engine_start(engine, &request, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = await_request(engine, request, &diagnostic);
    }
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

    status = rustbox_engine_stop(engine, &request, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = await_request(engine, request, &diagnostic);
    }
    if (status != RUSTBOX_STATUS_OK) {
        rustbox_diagnostic_clear(&diagnostic);
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
        return 4;
    }

    status = rustbox_engine_destroy(engine, &diagnostic);
    rustbox_diagnostic_clear(&diagnostic);
    return status == RUSTBOX_STATUS_OK ? 0 : 5;
}
