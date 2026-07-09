# RustBox 配置与 FFI

配置和 FFI 不需要各自拥有一套引擎。

## 统一路径

```text
CLI: file -> SourceConfig ─┐
                           ├─> RustBox -> start/stop/reload/snapshot
FFI: TOML bytes -> SourceConfig ┘
```

`RustBox::new` 完成 parse/normalize/validate/compile 和运行图准备。CLI 不直接
调用组合器，FFI 也不复制这些步骤。

## FFI 的职责

FFI 只负责：

- 检查指针、长度和 UTF-8；
- 将 TOML 转成 `SourceConfig`；
- 将 `RustBox` 放入 Rust 侧句柄表；
- 把错误转换为稳定状态码和 Rust 分配的诊断字符串；
- 为同步 C ABI 持有 Tokio runtime 并 `block_on` `RustBox` async 方法。

当前 C API：

```c
rustbox_validate_config_toml(...);
rustbox_engine_create_from_config_toml(...);
rustbox_engine_start(...);
rustbox_engine_reload_config_toml(...);
rustbox_engine_snapshot(...);
rustbox_engine_stop(...);
rustbox_engine_destroy(...);
```

默认 HTTP/SOCKS5 函数只是构造默认 `SourceConfig` 的快捷方式。

## 不做的事情

- 不在 FFI 中重新实现配置编译状态机；
- 不区分“FFI engine”和“CLI engine”；
- 不把 Rust enum、引用、Tokio handle 或内部 service 指针暴露给 C；
- 不为每个配置 enum 立即设计一套镜像 C struct；
- 没有实际 GUI/移动调用需求前，不增加 config handle/builder 层。

## Reload

`rustbox_engine_reload_config_toml` 调用的就是 `RustBox::reload`。运行中 reload
会复用 FFI 已持有的 Tokio runtime；未启动的 engine 使用临时 runtime 完成
同一个 async 调用。快照和 generation 由 `RustBox` 更新，FFI 不单独维护。
