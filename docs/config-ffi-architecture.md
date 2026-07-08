# RustBox Configuration And FFI Architecture

> **Document status:** Design recommendation  
> **Scope:** Configuration files, typed configuration, reload, and FFI/mobile embedding  
> **Related documents:** `docs/architecture.md`, `docs/current-architecture.md`, `docs/observability-architecture.md`

---

## 1. Recommendation

RustBox should use a single configuration pipeline with multiple input
frontends:

```text
File / CLI / GUI / FFI / remote control
        ↓
Raw input DTO
        ↓
SourceConfig
        ↓
NormalizedConfig
        ↓
ValidatedConfig
        ↓
CompiledConfig
        ↓
Composition root
        ↓
Running engine graph
```

The important rule is:

```text
Input format is not runtime architecture.
FFI ABI is not Rust configuration ABI.
Runtime modules receive compiled typed config only.
```

The current `rustbox-config` crate already has the core shape:

```text
SourceConfig -> ParsedConfig -> NormalizedConfig -> ValidatedConfig -> CompiledConfig
```

The next step should be to make the input and ABI boundaries explicit instead
of adding file parsing or FFI structs directly into runtime modules.

---

## 2. Target Crate Responsibilities

Recommended crate layout:

| Crate | Responsibility |
|---|---|
| `rustbox-config` | Format-neutral config model, normalization, validation, compilation |
| `rustbox-config-file` | TOML/JSON/YAML parsing, file includes, env expansion policy, schema/export helpers |
| `rustbox-config-ffi` or `rustbox-ffi` module | C ABI-safe config loading functions and opaque config handles |
| `rustbox-compose` | Turns `CompiledConfig` into a concrete runtime graph |
| `rustbox-control` | Applies compiled config through commands and snapshots |
| `rustbox-reload` | Compile-and-swap transaction phases |

`rustbox-config` should stay independent from filesystem access and specific
serialization formats. That keeps GUI state, FFI input, tests, and file input
on the same path.

---

## 3. Configuration Layers

### 3.1 Raw Input DTO

Raw input DTOs represent a specific source shape.

Examples:

```text
TomlConfigDocument
JsonConfigDocument
FfiConfigDocument
GuiConfigDocument
```

These types may contain convenient strings and loose user input:

```text
"127.0.0.1:18080"
"direct"
"info"
```

They should not be passed to the runtime graph.

### 3.2 SourceConfig

`SourceConfig` is the format-neutral semantic model. It should contain the
same information no matter whether it came from a file, FFI, or GUI.

Recommended fields:

```rust
pub struct SourceConfig {
    pub schema_version: ConfigSchemaVersion,
    pub profile: Option<String>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routes: Vec<RouteRuleConfig>,
    pub dns: Option<DnsConfig>,
    pub observability: Option<ObservabilityConfig>,
    pub reload: Option<ReloadConfig>,
}
```

This layer should use stable logical IDs such as `"http"` and `"direct"`.
Inbound and outbound entries keep shared identity outside their protocol
variant:

```rust
pub struct OutboundConfig {
    pub id: String,
    pub kind: OutboundConfigKind,
}
```

That shape keeps ID handling, duplicate checks, and compiled ID assignment out
of every protocol variant.

Observability configuration belongs to the application/control layer unless it
changes runtime graph construction. Sink choices such as console, file,
platform-native logging, or remote telemetry should not be deserialized inside
protocol modules.

### 3.3 NormalizedConfig

Normalization should resolve defaults without checking cross-reference
correctness yet.

Examples:

- Fill default listen host when only a port is provided.
- Fill default route if the product chooses to allow one.
- Normalize hostnames, protocol names, and enum aliases.
- Apply profile selection.
- Convert legacy schema versions into the current source shape.

This makes validation deterministic and avoids duplicating default logic across
file, FFI, and GUI callers.

### 3.4 ValidatedConfig

Validation checks semantic correctness:

- IDs are non-empty and unique.
- Route references point to existing outbounds.
- Module kinds exist in the registry.
- Required capabilities are available in the selected host/platform plan.
- Ports and endpoints are valid.
- Unsupported combinations are rejected before the runtime graph is touched.
- Reload policy is compatible with the requested change.

Validation should return structured diagnostics, not only a single string.

Recommended diagnostic model:

```rust
pub struct ConfigDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: ConfigDiagnosticCode,
    pub path: ConfigPath,
    pub message: String,
}
```

For file input, `ConfigPath` can map back to document paths such as:

```text
$.inbounds[0].listen
```

For FFI input, the same path can be returned as UTF-8 text.

### 3.5 CompiledConfig

Compilation resolves logical config into typed runtime plans:

- Logical IDs become stable internal IDs.
- Route decisions become typed `RouteDecision` values.
- Module config becomes `CompiledInbound`, `CompiledOutbound`, etc.
- Runtime modules receive only the pieces they need.

`CompiledConfig` is internal Rust API. It should not be exposed through C ABI.

---

## 4. Recommended File Format Strategy

Use one canonical human-authored format first. TOML is a reasonable default for
this repository because it is readable, strict enough for operations, and fits
small local proxy configs.

Recommended initial file shape:

```toml
schema_version = 1

[observability]
level = "info"
file = "target/rustbox.log"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"
# Optional for "http-connect", "socks5", and "mixed" inbounds.
# username = "alice"
# password = "secret"

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"

[[outbounds]]
id = "direct"
type = "direct"

[[rule_sets]]
id = "ads"
type = "inline"
rules = [
  { type = "rule", domain_keyword = ["ads", "tracker"] },
]

[[routes]]
type = "rule"
inbound = ["http"]
network = ["tcp"]
domain_suffix = ["example.test"]
port = [443]
rule_set = ["ads"]
outbound = "direct"

[[routes]]
type = "default"
outbound = "direct"
```

File parsing should live outside `rustbox-config`:

```text
rustbox-config-file
    parse bytes/string
    decode TOML/JSON/YAML
    parse user strings into portable foundation types
    reject unknown fields if strict mode is enabled
    apply schema migration hooks before SourceConfig construction
    convert to SourceConfig
```

Do not let protocol modules deserialize themselves from TOML/JSON. Module
runtime config should be constructed by the config compiler.

Current implementation note: endpoint, CIDR, and port-range string parsing
belongs to `rustbox-types` via `FromStr`; `rustbox-config-file` uses serde DTOs
to produce those strong types before conversion to `SourceConfig`.

Current file observability fields:

| Field | Meaning | Current status |
|---|---|---|
| `level` | Console/file minimum level | Implemented |
| `file` | Append formatted structured events to a host file | Implemented in `rustbox-app` |
| `platform` | Request a platform-native log backend | Parsed, backend supplied by platform/product adapter |
| `remote_endpoint` | Request remote telemetry export | Parsed, exporter supplied by product/integration adapter |

HTTP/gRPC API configuration should be added as a control service, not as an
inbound proxy module. The API service will consume control snapshots and
`ObservabilityStore` data.

Current route file fields support ordered default, reject-default, rule, and
logical route rules. Implemented matchers cover inbound IDs, TCP/UDP network,
domain exact/suffix/keyword/regex, destination/source IP CIDR,
destination/source ports and ranges, local or inline rule-set references,
invert, and logical and/or composition. GeoIP/Geosite compatibility should be
implemented through rule-set importers rather than hard-wiring those deprecated
sing-box fields into the kernel router.

---

## 5. FFI Design

FFI should support configuration without exposing Rust structs, enums, trait
objects, or ownership-sensitive pointers.

Recommended FFI model:

```text
config text / config builder calls
        ↓
Rust-owned config handle
        ↓
validate
        ↓
create or reload engine
        ↓
free config handle
```

Recommended C ABI:

```c
typedef uint64_t rustbox_config_handle;
typedef uint64_t rustbox_engine_handle;

rustbox_status rustbox_config_parse_toml(
    const uint8_t* bytes,
    uintptr_t len,
    rustbox_config_handle* out_config,
    rustbox_diagnostic_list* diagnostics
);

rustbox_status rustbox_config_validate(
    rustbox_config_handle config,
    rustbox_diagnostic_list* diagnostics
);

rustbox_status rustbox_engine_create_from_config(
    rustbox_config_handle config,
    rustbox_engine_handle* out_engine,
    rustbox_diagnostic_list* diagnostics
);

rustbox_status rustbox_engine_reload_config(
    rustbox_engine_handle engine,
    rustbox_config_handle config,
    rustbox_diagnostic_list* diagnostics
);

void rustbox_config_destroy(rustbox_config_handle config);
```

The FFI layer should own handle tables for both engines and configs:

```text
FfiConfigTable
    handle -> SourceConfig or ValidatedConfig

FfiEngineTable
    handle -> ManagedEngine
```

This avoids passing nested C structs for every module type and avoids ABI churn
when Rust config evolves.

### 5.1 FFI Input Modes

Support two complementary input modes:

| Mode | Use case | Stability |
|---|---|---|
| Parse text config over FFI | Desktop/mobile hosts that already have config files or JSON/TOML strings | Best initial path |
| Builder-style FFI API | Simple mobile/GUI construction without text serialization | Add later for stable common cases |

Builder-style API should be intentionally small:

```c
rustbox_config_builder_create(...)
rustbox_config_builder_add_http_connect_inbound(...)
rustbox_config_builder_add_direct_outbound(...)
rustbox_config_builder_set_default_route(...)
rustbox_config_builder_finish(...)
```

Avoid one C struct per Rust enum variant until the config surface stabilizes.

### 5.2 FFI Diagnostics

The current FFI returns one UTF-8 diagnostic string. Configuration should move
toward a diagnostic list:

```c
typedef struct rustbox_ffi_diagnostic {
    rustbox_status code;
    rustbox_diagnostic_severity severity;
    const char* path;
    const char* message;
} rustbox_ffi_diagnostic;
```

The list itself should be Rust-owned and freed through an exported function:

```c
void rustbox_diagnostic_list_free(rustbox_diagnostic_list diagnostics);
```

Never require the host to free individual nested strings unless the ABI clearly
documents ownership.

---

## 6. Reload Semantics

Configuration reload should remain compile-and-swap:

```text
parse new source
normalize
validate
compile
prepare runtime graph
commit graph swap
drain old services
rollback on prepare/commit failure
```

FFI reload should not mutate the running engine until the new config reaches at
least `ValidatedConfig`, and ideally until the replacement graph is prepared.

Recommended behavior:

| Engine state | `reload_config` behavior |
|---|---|
| Created / Stopped | Store validated/compiled config, move to Prepared |
| Running | Prepare new graph, commit, drain old graph |
| Failed | Allow reload only if policy explicitly permits recovery |

Long-lived flows should continue on their chosen execution plan until drained
or stopped by policy.

---

## 7. Security And Compatibility Rules

Configuration must be treated as untrusted input, especially through FFI.

Recommended rules:

- Hard-limit config byte length accepted over FFI.
- Validate UTF-8 before parsing text formats.
- Reject NUL bytes in strings crossing C boundaries.
- Keep file include support disabled initially.
- If includes are added later, resolve them only in `rustbox-config-file`.
- Never expand environment variables inside portable config by default.
- Version the config schema separately from the FFI ABI.
- Support migration from older schema versions before validation.
- Return unknown-field diagnostics in strict mode.

Recommended version separation:

```text
FFI ABI version       changes when exported C function/struct contracts change
Config schema version changes when user-authored config semantics change
Plugin ABI version   changes when external plugin contracts change
```

---

## 8. What To Change Next

Recommended implementation order:

1. Add structured `ConfigDiagnostic` to `rustbox-config`.
2. Extend schema migration hooks when future `schema_version` values appear.
3. Add FFI config handle APIs:

   ```text
   parse text -> config handle -> validate -> create/reload engine
   ```

4. Replace default-only FFI helpers with general config-handle APIs while
   keeping default helpers as convenience wrappers.
5. Add multi-diagnostic FFI reporting.
6. Integrate reload transaction with prepared runtime graph swapping instead
   of stop-and-restart for every reload.

---

## 9. Current Gap Summary

Current implementation:

- Good: format-neutral `SourceConfig` exists.
- Good: `ParsedConfig -> NormalizedConfig -> ValidatedConfig` is explicit.
- Good: validation and compilation are separate.
- Good: FFI uses opaque engine handles and does not expose Rust runtime types.
- Good: reload has a compile-and-swap transaction model.
- Good: TOML file parsing exists in `rustbox-config-file`.
- Good: `rustbox-app --config path` starts from TOML.
- Good: FFI can validate, create, and reload from UTF-8 TOML bytes without
  exposing Rust config structs.
- Partial: schema migration has an explicit hook and currently accepts only
  `schema_version = 1`.
- Gap: diagnostics are single-message rather than structured lists.
- Gap: FFI currently has convenience helpers for default HTTP CONNECT and
  SOCKS5 proxies, but no general config-handle API yet.
- Gap: FFI has no Rust-owned config handles.
- Gap: reload through FFI currently restarts the owned runtime instead of
  preparing and swapping a replacement graph.
- Gap: FFI does not yet expose observability snapshots, metrics, connection
  stats, or event query DTOs.

The best next architectural move is to introduce config handles and
observability snapshot/query DTOs without changing the kernel or protocol
modules.
