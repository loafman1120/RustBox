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

typedef enum RustBoxStatusCode {
    RUSTBOX_STATUS_OK = 0,
    RUSTBOX_STATUS_INVALID_CONFIG = 1,
    RUSTBOX_STATUS_NOT_FOUND = 2,
    RUSTBOX_STATUS_ALREADY_RUNNING = 3,
    RUSTBOX_STATUS_RUNTIME_ERROR = 4,
    RUSTBOX_STATUS_INVALID_ARGUMENT = 5,
    RUSTBOX_STATUS_LOCK_POISONED = 6,
    RUSTBOX_STATUS_INTERNAL_ERROR = 7
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

typedef struct RustBoxFfiMetricsSnapshot {
    uint64_t services_started;
    uint64_t services_stopped;
    uint64_t connections_accepted;
    uint64_t flows_accepted;
    uint64_t flows_active;
    uint64_t flows_completed;
    uint64_t flows_failed;
    uint64_t routes_selected;
    uint64_t outbound_connect_attempts;
    uint64_t outbound_connect_successes;
    uint64_t outbound_connect_failures;
    uint64_t inbound_to_outbound_bytes;
    uint64_t outbound_to_inbound_bytes;
    uint64_t diagnostics;
} RustBoxFfiMetricsSnapshot;

RUSTBOX_API uint32_t rustbox_ffi_abi_version(void);

RUSTBOX_API RustBoxStatusCode rustbox_validate_default_http_proxy(
    uint16_t listen_port,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_validate_default_socks5_proxy(
    uint16_t listen_port,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_validate_config_toml(
    const uint8_t *bytes,
    size_t len,
    RustBoxFfiDiagnostic *diagnostic);

RUSTBOX_API RustBoxStatusCode rustbox_engine_create_default_http_proxy(
    uint16_t listen_port,
    RustBoxEngineHandle *out_handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_create_default_socks5_proxy(
    uint16_t listen_port,
    RustBoxEngineHandle *out_handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_create_from_config_toml(
    const uint8_t *bytes,
    size_t len,
    RustBoxEngineHandle *out_handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_start(
    RustBoxEngineHandle handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_reload_default_http_proxy(
    RustBoxEngineHandle handle,
    uint16_t listen_port,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_reload_default_socks5_proxy(
    RustBoxEngineHandle handle,
    uint16_t listen_port,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_reload_config_toml(
    RustBoxEngineHandle handle,
    const uint8_t *bytes,
    size_t len,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_snapshot(
    RustBoxEngineHandle handle,
    RustBoxFfiEngineSnapshot *out_snapshot,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_metrics(
    RustBoxEngineHandle handle,
    RustBoxFfiMetricsSnapshot *out_metrics,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_stop(
    RustBoxEngineHandle handle,
    RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API RustBoxStatusCode rustbox_engine_destroy(
    RustBoxEngineHandle handle,
    RustBoxFfiDiagnostic *diagnostic);

/* The diagnostic must be initialized to { RUSTBOX_STATUS_OK, NULL }. Clear it
 * before passing the same value to another RustBox call. */
RUSTBOX_API void rustbox_diagnostic_clear(RustBoxFfiDiagnostic *diagnostic);
RUSTBOX_API void rustbox_diagnostic_message_free(char *message);

#ifdef __cplusplus
}
#endif

#endif
