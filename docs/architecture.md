# RustBox 架构

RustBox 采用一条直接的主调用链：

```text
CLI / FFI / Rust embedding
          |
          v
       RustBox
  new/start/stop/reload/snapshot
          |
          v
  config + proxy modules + kernel
          |
          v
        Tokio
```

## 原则

1. `apps/rustbox` 只是 CLI。它解析参数、处理终端信号并调用 `RustBox`，不自行
   编译配置或装配代理图。
2. `rustbox-ffi` 只是 ABI 翻译层。它把 C 的字节串、句柄和状态码转换为同一个
   `RustBox` 接口，不维护第二套引擎实现。
3. Tokio 是项目选定的异步运行时，可以在需要异步 I/O 的 crate 中直接使用。
   不为假设中的其他 runtime 增加 adapter、executor 或 wrapper 层。
4. 只有存在真实替换需求时才保留 trait：
   - 测试需要内存网络或可控时钟；
   - Linux、Windows、Android 等平台实现确实不同；
   - 一个协议需要接收 TCP、TLS、代理隧道等多种流。
5. crate 按可独立测试和复用的功能拆分，不按抽象层级拆分。没有独立用途的
   pass-through crate 应合并或删除。

## 公共 Rust 接口

`rustbox` crate 当前承载共享应用接口：

```rust
let mut rustbox = RustBox::new(source_config)?;
rustbox.start().await?;
let snapshot = rustbox.snapshot();
rustbox.reload(next_source_config).await?;
rustbox.stop().await?;
```

源码位于 `crates/rustbox`。内部运行图构造器不属于 CLI 或 FFI API。

## 配置

所有入口使用同一条路径：

```text
TOML / programmatic SourceConfig
  -> parse
  -> normalize
  -> validate
  -> compile
  -> RustBox
```

文件格式解析仍与运行配置模型分开，因为 FFI、GUI 和测试可以直接提供
`SourceConfig`。这是一条有实际调用方的边界，不是为解耦而解耦。

## Tokio 与 host trait

`TokioHost` 位于 `rustbox-host-api`，不再有独立的
`rustbox-runtime-tokio` crate。网络、时钟、随机数和任务默认由 Tokio 实现。

`NetworkProvider`、`Clock`、`PacketDeviceProvider` 等 trait 暂时保留，是因为
测试 host 和平台设备确实有多个实现。它们不是“可替换 runtime 架构”。如果
某个 trait 最终只有 Tokio 一个实现且测试也不需要替身，应继续删除。

## 生命周期

`RustBox` 是生命周期的唯一所有者：

- `new`：校验配置并准备运行图；
- `start`：启动所有 inbound 服务；
- `stop`：按反向顺序停止服务；
- `reload`：准备新图，并在需要时停止旧图、启动新图；
- `snapshot`：向 CLI、FFI、控制 API 返回同一种状态。

C 调用方没有 Tokio runtime，因此 FFI 只额外持有一个 Tokio `Runtime` 来
`block_on` 同一组 async 方法。这是同步 ABI 桥接，不是另一套业务实现。

## 依赖边界

需要坚持的边界很少：

- 协议模块不解析 CLI 参数；
- FFI 不暴露 Rust 引用或 trait object；
- 配置校验不在各 inbound/outbound 中重复；
- 平台路由、TUN 和透明代理操作留在对应平台实现；
- CLI 与 FFI 不直接操作内部 `Engine` 或 service 列表。

除此之外，优先选择直接依赖和普通函数调用。
