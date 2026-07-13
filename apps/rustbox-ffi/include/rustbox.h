#ifndef RUSTBOX_H
#define RUSTBOX_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(RUSTBOX_SHARED)
#  if defined(RUSTBOX_BUILDING)
#    define RUSTBOX_API __declspec(dllexport)
#  else
#    define RUSTBOX_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && defined(RUSTBOX_BUILDING)
#  define RUSTBOX_API __attribute__((visibility("default")))
#else
#  define RUSTBOX_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t RustBoxEngineHandle;
typedef uint64_t RustBoxRequestHandle;

typedef enum RustBoxRequestStateCode {
    RUSTBOX_REQUEST_PENDING = 0,
    RUSTBOX_REQUEST_SUCCEEDED = 1,
    RUSTBOX_REQUEST_FAILED = 2
} RustBoxRequestStateCode;

typedef enum RustBoxStatusCode {
    RUSTBOX_STATUS_OK = 0,
    RUSTBOX_STATUS_INVALID_CONFIG = 1,
    RUSTBOX_STATUS_NOT_FOUND = 2,
    RUSTBOX_STATUS_RUNTIME_ERROR = 3,
    RUSTBOX_STATUS_INVALID_ARGUMENT = 4,
    RUSTBOX_STATUS_LOCK_POISONED = 5,
    RUSTBOX_STATUS_INTERNAL_ERROR = 6
} RustBoxStatusCode;

typedef enum RustBoxEngineStateCode {
    RUSTBOX_ENGINE_CREATED = 0,
    RUSTBOX_ENGINE_PREPARED = 1,
    RUSTBOX_ENGINE_RUNNING = 2,
    RUSTBOX_ENGINE_STOPPING = 3,
    RUSTBOX_ENGINE_STOPPED = 4,
    RUSTBOX_ENGINE_FAILED = 5
} RustBoxEngineStateCode;

typedef struct RustBoxFfiEngineSnapshot {
    RustBoxEngineStateCode state;
    uint64_t generation;
    uint64_t inbound_count;
    uint64_t outbound_count;
} RustBoxFfiEngineSnapshot;

typedef struct RustBoxFfiDiagnostic {
    RustBoxStatusCode code;
    char *message;
} RustBoxFfiDiagnostic;

RUSTBOX_API uint32_t rustbox_ffi_abi_version(void);

/* Configuration is borrowed UTF-8 TOML and may be released after this call. */
RUSTBOX_API RustBoxStatusCode rustbox_engine_create(
    const uint8_t *bytes,
    size_t len,
    RustBoxEngineHandle *out_handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_start(
    RustBoxEngineHandle handle,
    RustBoxRequestHandle *out_request,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_reload(
    RustBoxEngineHandle handle,
    const uint8_t *bytes,
    size_t len,
    RustBoxRequestHandle *out_request,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_snapshot(
    RustBoxEngineHandle handle,
    RustBoxFfiEngineSnapshot *out_snapshot,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_stop(
    RustBoxEngineHandle handle,
    RustBoxRequestHandle *out_request,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_request_poll(
    RustBoxEngineHandle handle,
    RustBoxRequestHandle request,
    RustBoxRequestStateCode *out_state,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_destroy(
    RustBoxEngineHandle handle,
    RustBoxFfiDiagnostic *diagnostic);

/* The diagnostic must be initialized to { RUSTBOX_STATUS_OK, NULL }. Clear it
 * before passing the same value to another RustBox call. */
RUSTBOX_API void rustbox_diagnostic_clear(RustBoxFfiDiagnostic *diagnostic);

#ifdef __cplusplus
}
#endif

#endif
