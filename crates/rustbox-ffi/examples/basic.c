#include <stdio.h>
#include "rustbox.h"

int main(void) {
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle engine = 0;

    RustBoxStatusCode status = rustbox_engine_create_default_socks5_proxy(
        1080, &engine, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = rustbox_engine_start(engine, &diagnostic);
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
