# 控制 API

RustBox 为本地客户端 UI 提供两个控制入口：原生/兼容 gRPC，以及 Clash/Mihomo 形状
的 HTTP/WebSocket API。两者共享运行状态和命令服务。

## 启动

```powershell
cargo run -p rustbox-app -- `
  --control-grpc 127.0.0.1:19090 `
  --clash-api 127.0.0.1:9090 `
  --control-token <token> `
  run --config examples/rustbox.toml
```

`--control-token` 同时保护两个入口，也可通过 `RUSTBOX_CONTROL_TOKEN` 提供。非
loopback 地址必须配置 token。浏览器 dashboard 的跨域来源使用可重复的
`--clash-cors-origin <origin>` 显式允许。

## gRPC

gRPC 保留 sing-box `daemon.StartedService` 的 selector/group 兼容契约，并通过
`rustbox.control.v1.RustBoxControl` 提供：

- engine 状态、内存和按 inbound/outbound 聚合流量；
- 活动连接查询、取消，以及连接/日志/流量 stream；
- selector 切换、真实 outbound 延迟测试和 URLTest 触发；
- rule-set 状态与刷新；
- reload 与 stop。

服务启用 reflection v1，可直接发现 schema：

```powershell
grpcurl -plaintext 127.0.0.1:19090 list
grpcurl -plaintext 127.0.0.1:19090 describe rustbox.control.v1.RustBoxControl
```

启用鉴权后为请求添加 `authorization: Bearer <token>`。

## Clash/Mihomo API

HTTP 服务提供版本、运行配置、流量、内存、日志、连接、代理组、规则和 rule-set
provider。流式端点支持 NDJSON 与 WebSocket；selector 切换、连接关闭、规则刷新、
TOML payload reload 和延迟测试都调用真实 runtime。

- OpenAPI 3.1：`/docs/openapi.json`
- 离线 Swagger UI：`/docs`
- 普通鉴权：`Authorization: Bearer <token>`
- WebSocket 兼容鉴权：`?token=<token>`

兼容目标是让常见 Clash dashboard 管理 RustBox 的现有能力，不是复制 Mihomo 的宿主
管理功能。proxy-provider、在线升级、UI 安装、任意 storage、任意文件路径 reload、
临时禁用规则和 URLTest 手动 pin 不受支持；接口会返回空集合或明确错误，不会伪装
成功。

## 安全边界

- 默认只监听 loopback，token 不写入日志；
- query token 只用于 WebSocket upgrade；
- CORS 只允许显式 origin；
- payload、query、stream 缓冲和测速并发均有界；
- 控制 API 不提供任意文件读取或下载能力。

公开部署控制端口不属于 RustBox 的目标场景。如确有需要，应在可信边界增加 TLS、
访问控制和审计。
