#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rustbox.h"

static int await_request(RustBoxEngineHandle engine,
                         RustBoxRequestHandle request,
                         RustBoxFfiDiagnostic *diagnostic) {
    RustBoxRequestStateCode state = RUSTBOX_REQUEST_PENDING;
    while (state == RUSTBOX_REQUEST_PENDING) {
        RustBoxStatusCode status = rustbox_engine_request_poll(
            engine, request, &state, diagnostic);
        if (status != RUSTBOX_STATUS_OK) return 0;
    }
    return state == RUSTBOX_REQUEST_SUCCEEDED;
}

static int fail(const char *step, RustBoxFfiDiagnostic *diagnostic) {
    fprintf(stderr, "mobile FFI lifecycle failed at %s: %s\n", step,
            diagnostic->message ? diagnostic->message : "no diagnostic");
    rustbox_diagnostic_clear(diagnostic);
    return 1;
}

int main(void) {
    static const char config[] =
        "schema_version = 1\n"
        "[[inbounds]]\nid = \"http\"\ntype = \"http-connect\"\n"
        "listen = \"127.0.0.1:0\"\n"
        "[[outbounds]]\nid = \"direct\"\ntype = \"direct\"\n"
        "[[routes]]\ntype = \"default\"\noutbound = \"direct\"\n";
    RustBoxFfiDiagnostic diagnostic = {RUSTBOX_STATUS_OK, NULL};
    RustBoxFfiEngineSnapshot snapshot = {RUSTBOX_ENGINE_CREATED, 0, 0, 0};
    RustBoxEngineHandle engine = 0;
    RustBoxRequestHandle request = 0;

    if (rustbox_ffi_abi_version() != 2) return fail("abi_version", &diagnostic);
    if (rustbox_engine_create((const uint8_t *)config, strlen(config),
                              &engine, &diagnostic) != RUSTBOX_STATUS_OK)
        return fail("create", &diagnostic);
    if (rustbox_engine_start(engine, &request, &diagnostic) != RUSTBOX_STATUS_OK ||
        !await_request(engine, request, &diagnostic))
        return fail("start", &diagnostic);
    if (rustbox_engine_snapshot(engine, &snapshot, &diagnostic) != RUSTBOX_STATUS_OK ||
        snapshot.state != RUSTBOX_ENGINE_RUNNING || snapshot.inbound_count != 1 ||
        snapshot.outbound_count != 1)
        return fail("snapshot", &diagnostic);
    if (rustbox_engine_reload(engine, (const uint8_t *)config, strlen(config),
                              &request, &diagnostic) != RUSTBOX_STATUS_OK ||
        !await_request(engine, request, &diagnostic))
        return fail("reload", &diagnostic);
    if (rustbox_engine_stop(engine, &request, &diagnostic) != RUSTBOX_STATUS_OK ||
        !await_request(engine, request, &diagnostic))
        return fail("stop", &diagnostic);
    if (rustbox_engine_destroy(engine, &diagnostic) != RUSTBOX_STATUS_OK)
        return fail("destroy", &diagnostic);

    rustbox_diagnostic_clear(&diagnostic);
    puts("RustBox mobile FFI lifecycle passed");
    return 0;
}
