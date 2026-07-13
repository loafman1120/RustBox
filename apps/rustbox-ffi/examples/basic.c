#include <stdio.h>
#include "rustbox.h"

static RustBoxStatusCode await_request(
        RustBoxEngineHandle engine, RustBoxRequestHandle request,
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

int main(void) {
    static const char config[] =
        "schema_version = 1\n"
        "[[inbounds]]\nid = \"socks\"\ntype = \"socks5\"\n"
        "listen = \"127.0.0.1:1080\"\n"
        "[[outbounds]]\nid = \"direct\"\ntype = \"direct\"\n"
        "[[routes]]\ntype = \"default\"\noutbound = \"direct\"\n";
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle engine = 0;
    RustBoxRequestHandle request = 0;

    RustBoxStatusCode status = rustbox_engine_create(
        (const uint8_t *)config, sizeof(config) - 1, &engine, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = rustbox_engine_start(engine, &request, &diagnostic);
    }
    if (status == RUSTBOX_STATUS_OK) {
        status = await_request(engine, request, &diagnostic);
    }
    if (status != RUSTBOX_STATUS_OK) {
        fprintf(stderr, "RustBox error: %s\n",
                diagnostic.message ? diagnostic.message : "unknown error");
    }

    rustbox_diagnostic_clear(&diagnostic);
    if (engine != 0) {
        (void)rustbox_engine_destroy(engine, &diagnostic);
        rustbox_diagnostic_clear(&diagnostic);
    }
    return status == RUSTBOX_STATUS_OK ? 0 : 1;
}
