#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rustbox.h"

static int fail(int code, const char *operation,
                RustBoxFfiDiagnostic *diagnostic) {
    fprintf(stderr, "%s failed: %s\n", operation,
            diagnostic->message ? diagnostic->message : "no diagnostic");
    rustbox_diagnostic_clear(diagnostic);
    return code;
}

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

/* This is a standalone native consumer. CI compiles it separately and links it
 * against the produced RustBox shared library, exercising the public ABI in the
 * same way as an application embedding RustBox. */
int main(int argc, char **argv) {
    RustBoxFfiDiagnostic diagnostic = { RUSTBOX_STATUS_OK, NULL };
    RustBoxEngineHandle engine = 0;
    RustBoxFfiEngineSnapshot snapshot = { RUSTBOX_ENGINE_CREATED, 0, 0, 0 };
    RustBoxStatusCode status;
    RustBoxRequestHandle request = 0;
    unsigned long proxy_port;
    char curl_command[2048];
    char response[256];
    char config[1024];
    FILE *response_file;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <proxy-port> <target-url> <response-file>\n",
                argv[0]);
        return 1;
    }
    proxy_port = strtoul(argv[1], NULL, 10);
    if (proxy_port == 0 || proxy_port > 65535) {
        fprintf(stderr, "invalid proxy port\n");
        return 1;
    }

    if (rustbox_ffi_abi_version() != 2) {
        fprintf(stderr, "unexpected RustBox FFI ABI version\n");
        return 1;
    }

    if (snprintf(config, sizeof(config),
                 "schema_version = 1\n"
                 "[[inbounds]]\nid = \"http\"\ntype = \"http-connect\"\n"
                 "listen = \"127.0.0.1:%lu\"\n"
                 "[[outbounds]]\nid = \"direct\"\ntype = \"direct\"\n"
                 "[[routes]]\ntype = \"default\"\noutbound = \"direct\"\n",
                 proxy_port) < 0) {
        return 2;
    }
    status = rustbox_engine_create(
        (const uint8_t *)config, strlen(config), &engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || engine == 0) {
        return fail(2, "create", &diagnostic);
    }

    status = rustbox_engine_start(engine, &request, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = await_request(engine, request, &diagnostic);
    }
    if (status != RUSTBOX_STATUS_OK) {
        (void)rustbox_engine_destroy(engine, NULL);
        return fail(3, "start", &diagnostic);
    }

    status = rustbox_engine_snapshot(engine, &snapshot, &diagnostic);
    if (status != RUSTBOX_STATUS_OK || snapshot.state != RUSTBOX_ENGINE_RUNNING ||
        snapshot.inbound_count != 1 || snapshot.outbound_count != 1) {
        (void)rustbox_engine_destroy(engine, NULL);
        return fail(4, "snapshot", &diagnostic);
    }

    if (snprintf(curl_command, sizeof(curl_command),
                 "curl --fail --silent --show-error --max-time 10 --noproxy \"\" "
                 "--proxy http://127.0.0.1:%lu \"%s\" --output \"%s\"",
                 proxy_port, argv[2], argv[3]) < 0 ||
        system(curl_command) != 0) {
        (void)rustbox_engine_destroy(engine, NULL);
        fprintf(stderr, "HTTP request through the FFI proxy failed\n");
        return 5;
    }

    response_file = fopen(argv[3], "rb");
    if (response_file == NULL ||
        fgets(response, (int)sizeof(response), response_file) == NULL ||
        strcmp(response, "rustbox-ffi-http-ok\n") != 0) {
        if (response_file != NULL) {
            fclose(response_file);
        }
        (void)rustbox_engine_destroy(engine, NULL);
        fprintf(stderr, "unexpected HTTP response through the FFI proxy\n");
        return 6;
    }
    fclose(response_file);

    status = rustbox_engine_stop(engine, &request, &diagnostic);
    if (status == RUSTBOX_STATUS_OK) {
        status = await_request(engine, request, &diagnostic);
    }
    if (status != RUSTBOX_STATUS_OK) {
        (void)rustbox_engine_destroy(engine, NULL);
        return fail(7, "stop", &diagnostic);
    }

    status = rustbox_engine_destroy(engine, &diagnostic);
    if (status != RUSTBOX_STATUS_OK) {
        return fail(8, "destroy", &diagnostic);
    }

    rustbox_diagnostic_clear(&diagnostic);
    puts("RustBox dynamic FFI HTTP proxy data path passed");
    return 0;
}
