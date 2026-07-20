# Clash API 兼容层设计

状态：已实现基线（Phase 1 + 实际 outbound/group 测速）  
调查基线：mihomo `v1.19.29`（2026-07-18 发布）  
目标：让 RustBox 能作为 Clash/Mihomo dashboard 的后端，同时保留现有原生 gRPC 控制面。

## 实现状态

当前代码已经落地 `rustbox-control-service` 与 `rustbox-clash-api`，并接入 RustBox/CLI
生命周期。已实现版本、运行配置投影、流量、内存、日志、连接、代理/组、规则、
rule-set provider、selector 切换、单个/全部连接关闭、TOML payload reload、rule-set
刷新，以及使用真实 outbound 链路的节点/组测速。HTTP handler 上的 `utoipa` 注解会生成
OpenAPI 3.1 契约；运行时在 `/docs/openapi.json` 提供机器可读规范，并在 `/docs` 提供使用
vendored 静态资源的 Swagger UI，不依赖外部 CDN。

刻意不提供 proxy-provider（当前运行模型没有该资源）、升级/UI 管理、任意 storage、
任意文件路径 reload、临时禁用规则和 urltest 手动 pin。对应查询返回稳定空集合，
对应写操作返回明确的 400/404，而不是伪装成功。新增能力时必须继续遵守本文的安全
边界和 fixture contract。

原生 gRPC 与 sing-box 兼容 RPC 在构建时由 `.proto` 生成同一个 descriptor set，并通过
tonic gRPC reflection v1 暴露。RPC 注释、请求/响应消息和 streaming 类型因此可被
`grpcurl`、IDE 及客户端生成器直接发现，无需再维护第二份 RPC 文档。

## 1. 调查结论

mihomo 的 external controller 不是普通的请求/响应 REST API，而是三种交互方式的组合：

- 普通 JSON：版本、配置、代理组、规则、provider 和一次性控制操作；
- newline-delimited JSON 长连接：`/logs`、`/traffic`、`/memory`；
- WebSocket：`/logs`、`/traffic`、`/memory`、`/connections`，每个文本帧是一份完整 JSON 消息。

鉴权使用 `Authorization: Bearer <secret>`。由于浏览器 WebSocket 不能稳定设置自定义 header，mihomo 还接受 `?token=<secret>`。`/traffic` 和 `/memory` 每秒推送一次；`/connections` 默认每秒推送一份完整快照，也接受 `interval` 毫秒参数。

官方 MetaCubeXD 的核心页面实际依赖以下接口：

1. 连接探测和全局状态：`/version`、`/configs`、`/traffic`、`/memory`、`/logs`；
2. 连接管理：`/connections`、`DELETE /connections`、`DELETE /connections/{id}`；
3. 代理管理：`/proxies`、`/proxies/{name}`、选择、解除固定、单节点和组延迟测试；
4. 列表页面：`/rules`、`/providers/proxies`、`/providers/rules`。

因此“API 路径存在”不是完成标准。JSON 字段、HTTP 状态码、流式传输格式、URL path 解码和鉴权行为都属于兼容契约。

参考：

- [mihomo API 文档](https://wiki.metacubex.one/en/api/)
- [mihomo v1.19.29 路由实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/server.go)
- [mihomo v1.19.29 连接接口](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/connections.go)
- [mihomo v1.19.29 代理接口](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/proxies.go)
- [MetaCubeXD API 客户端](https://github.com/MetaCubeX/metacubexd/blob/main/packages/ui/composables/useApi.ts)

## 2. RustBox 现状与缺口

RustBox 已经具备大部分控制能力：

- `ObservabilityStore`：累计流量、按连接流量、活动连接和事件广播；
- `OutboundGroupRegistry`：selector/urltest 列表、当前选择、延迟结果和 selector 切换；
- `RuleSetRegistry`：rule-set 状态和刷新；
- `ControlCommand`：关闭单连接、刷新 rule-set、触发 URLTest、reload、stop；
- gRPC：连接/流量/日志 stream 和 sing-box `StartedService` 兼容接口。

但直接套一层 JSON 会产生以下语义缺口：

| Clash 字段或操作 | 当前 RustBox | 所需改动 |
| --- | --- | --- |
| connection `id` | `u64 flow_id` | wire 层使用十进制字符串，始终视为不透明 ID |
| `metadata` | source/destination 字符串 | 在观测模型中保留结构化 FlowMeta 投影，禁止在 HTTP 层拆字符串 |
| `start` | 缺失 | FlowAccepted 时记录 RFC 3339 时间 |
| `rule` / `rulePayload` | 缺失 | 路由结果携带命中规则的稳定投影 |
| `chains` | 只有解析后的叶子 outbound | 路由解析保留逻辑组到叶子节点的选择链 |
| 关闭全部连接 | 只有关闭单 flow | 增加 `CloseAllConnections` 命令并由 runtime 执行 |
| `/proxies` 叶子节点全集 | group registry 只适合列组及其成员 | 发布 transport-neutral outbound catalog |
| `/rules` | 运行路由表不可枚举为 Clash DTO | 编译阶段生成只读 rule catalog；命中统计可后补 |
| `/configs` | 无 Clash 运行配置投影 | 提供明确的兼容投影，未实现字段返回稳定默认值 |
| 手动单节点测速 | URLTest 只面向组 | 抽出可按 outbound tag 调用的 probe service |
| urltest 解除固定 | RustBox urltest 没有手动 pin | 第一阶段返回 400；实现 pin 后再开放 DELETE |
| proxy/rule providers | 只有 rule-set，且模型不同 | proxy providers 先返回空 map；rule-set 做 provider 投影 |

## 3. 建议架构

不要让 HTTP handler 调 gRPC，也不要把 axum 类型带进数据面。将控制面拆成共享服务层和两个传输适配器：

```text
kernel / runtime events + commands
               |
               v
 rustbox-control-service
  - ControlPlaneHandle
  - connection/outbound/rule catalogs
  - subscriptions and command acknowledgements
          /                 \
         v                   v
rustbox-control-api     rustbox-clash-api
      gRPC                HTTP + WebSocket
```

具体边界：

- `rustbox-control` 继续持有领域命令、出站组与 rule-set 状态；
- 新增 `rustbox-control-service`，从现有 `rustbox-control-api` 抽出 `ControlApiState`、`ControlCommand`、订阅和 transport-neutral 快照；
- `rustbox-control-api` 只保留 protobuf/tonic 映射；
- 新增 `rustbox-clash-api`，只持有 Clash DTO、axum 路由、鉴权、HTTP stream 和 WebSocket 编码；
- `rustbox` 组合根构造一个 `ControlPlaneHandle`，供两个 server 共享；reload 后原子替换 catalog/registry，server 不持有 generation 内对象。

Clash API 使用独立监听地址，不与 gRPC 复用端口。这样生命周期、HTTP/1.1 WebSocket 支持、错误定位和用户配置都更清晰。

建议 CLI：

```text
--control-grpc 127.0.0.1:19090
--clash-api 127.0.0.1:9090
--control-token <secret>
```

`--control-token` 同时保护两个监听器。任何非 loopback 监听都必须配置 token；未启用控制 server 时单独提供 token 应报参数错误。

## 4. 兼容范围

### Phase 1：可连接、可观测、可选择

这是 MetaCubeXD/Yacd 基本可用的首个里程碑。

| 路径 | 行为 |
| --- | --- |
| `GET /` | `{"hello":"mihomo"}`，保持探测兼容 |
| `GET /version` | `{"meta":true,"version":"RustBox <version>"}` |
| `GET /configs` | 只读运行配置投影；至少包含 mode、各端口、allow-lan、ipv6、log-level、tun |
| `GET/WS /traffic` | 每秒 `{up,down,upTotal,downTotal}`；HTTP 为每行一个 JSON |
| `GET/WS /memory` | 每秒 `{inuse,oslimit}`；`oslimit` 固定为 0 |
| `GET/WS /logs` | 支持 `level` 和 `format=structured` |
| `GET/WS /connections` | 立即发送一次，之后按 interval 发送完整活动连接快照 |
| `DELETE /connections/{id}` | 幂等关闭；不存在也返回 204 |
| `DELETE /connections` | 关闭快照中所有活动连接，返回 204 |
| `GET /proxies[/{name}]` | 完整叶子节点与 selector/urltest 组投影 |
| `PUT /proxies/{name}` | body `{"name":"child"}`；只允许 selector，成功 204 |
| `GET /rules` | 当前 generation 的只读规则投影 |
| `GET /providers/proxies` | Phase 1 返回 `{"providers":{}}` |
| `GET /providers/rules` | 将 RustBox rule-set 投影为 provider map |

Phase 1 不伪装支持写配置、升级、重启或 provider 更新。未实现的 mihomo 扩展路径统一返回 404；已存在但当前对象不支持的操作返回 mihomo 风格的 400 JSON error。

### Phase 2：测速与 dashboard 完整代理体验

- `GET /proxies/{name}/delay?url=&timeout=&expected=`；
- `GET /group/{name}/delay`；
- `GET /group` 和 `GET /group/{name}`；
- urltest 手动 pin 与 `DELETE /proxies/{name}` 解除固定；
- provider-scoped 节点查询和 healthcheck（若 RustBox 引入 proxy-provider）。

测速必须通过目标 outbound 的真实拨号链，不允许用系统默认 `reqwest` 连接代替。限制 `timeout`、允许的 URL scheme、并发数和响应读取上限，避免控制端点被用作 SSRF/资源耗尽入口。

### Phase 3：显式支持的动态控制

- `PUT /configs`：只接受 TOML `payload`，走现有 prepare/commit/drain reload；`path` 默认拒绝，避免控制 API 任意读取本地文件；
- `PATCH /configs`：只开放 RustBox 能原子表达的字段；未知或只读字段返回 400，绝不静默成功；
- DNS cache flush、rule-set refresh 等已有明确 runtime 语义的操作。

不建议由内核兼容层承担 `/upgrade`、`/upgrade/ui`、任意 `/storage` 和文件路径 reload。这些属于产品/宿主管理面，会扩大文件与供应链攻击面。

## 5. Wire 映射

### 5.1 连接

```json
{
  "downloadTotal": 456,
  "uploadTotal": 123,
  "memory": 0,
  "connections": [{
    "id": "42",
    "metadata": {
      "network": "tcp",
      "type": "HTTP",
      "sourceIP": "127.0.0.1",
      "sourcePort": "53120",
      "destinationIP": "1.1.1.1",
      "destinationPort": "443",
      "host": "example.com",
      "inboundName": "mixed-in"
    },
    "upload": 123,
    "download": 456,
    "start": "2026-07-20T12:34:56.000Z",
    "chains": ["node-a", "select-main"],
    "rule": "DOMAIN-SUFFIX",
    "rulePayload": "example.com"
  }]
}
```

Clash 的 `chains` 顺序是从最终叶子节点回到外层组。RustBox 应在路由时一次生成，不在查询时根据当前 selector 反推，否则 selector 切换后旧连接会显示错误链路。

### 5.2 代理

类型名使用 Clash 常见大小写：`Direct`、`Reject`、`Socks5`、`Http`、`Shadowsocks`、`VMess`、`VLESS`、`Trojan`、`Hysteria2`、`TUIC`、`WireGuard`、`Selector`、`URLTest`。每个对象至少稳定输出：

```text
name, type, udp, xudp, tfo, alive, history, extra
```

组额外输出：

```text
all, now, hidden, testUrl
```

未知或 RustBox 无法表达的能力使用保守值（例如 `tfo=false`），不要从协议类型猜测运行能力。历史延迟由 registry 转成 `{time, delay}`；失败记录延迟为 0，并保留在 RustBox 原生 API 的详细错误字段中。

### 5.3 错误

统一 DTO：`{"message":"..."}`。建议映射：

| 情况 | 状态码 |
| --- | --- |
| 缺失/错误 token | 401 |
| 路径对象不存在 | 404 |
| JSON、query、timeout、选择目标非法 | 400 |
| 测速超时 | 504 |
| 测速失败 | 503 |
| 命令队列满 | 429 |
| runtime 正在停止或命令处理器消失 | 503 |

## 6. 流与背压

- `/traffic`、`/memory` 使用 interval 定时采样，不为每个订阅者累积历史消息；
- `/logs` 订阅现有 broadcast，慢消费者丢旧消息并继续，不阻塞数据面；
- `/connections` 与 mihomo 一致发送完整快照，不直接转发 upsert/remove 事件；
- 每个 WebSocket 设置写超时和最大帧大小；客户端断开后立即结束订阅 task；
- HTTP streaming response 每条 JSON 后追加 `\n` 并 flush；不能用 SSE 的 `data:` framing；
- server shutdown 通过 `CancellationToken`，并纳入 RustBox 现有 start/stop/reload 生命周期。

## 7. 安全约束

- Bearer 与 query token 比较使用 constant-time 比较；日志不得记录 token 或完整 query string；
- query token 仅用于 WebSocket 升级，普通 HTTP 不接受 query token；
- 默认只监听 loopback；非 loopback 无 token 时配置校验失败；
- CORS 默认只允许显式 origin；提供 `*` 时才允许任意 dashboard；正确处理 private-network preflight；
- 所有 body 设置较小上限；所有 query 参数有边界；path 参数先 percent-decode 一次并按 UTF-8 校验；
- Phase 1 没有文件读写和下载能力。

## 8. 验收与测试

### Contract fixtures

从 mihomo v1.19.29 固定一组脱敏响应 fixture，针对 RustBox DTO 做字段级比较。允许额外字段，但必需字段、JSON 类型、状态码和空值形态必须一致。

### Router tests

- header token、错误 scheme、错误 token、WS query token；
- 名称包含空格、`%`、`/` 的 percent-encoded path；
- selector 成功/失败、关闭存在/不存在连接；
- HTTP NDJSON 与 WebSocket 首帧、后续帧、断开清理；
- interval 下限/上限、慢消费者和 shutdown。

### Dashboard smoke test

以官方 MetaCubeXD 静态页面连接 RustBox，验收：

1. endpoint 检测成功；
2. Overview 的流量和内存持续更新；
3. Proxies 能显示组、节点、当前选择并完成切换；
4. Connections 能显示、刷新和关闭；
5. Logs 能持续显示；
6. Rules 页面能打开；
7. 浏览器控制台没有必需 API 的 4xx/5xx 或 JSON schema 错误。

## 9. 实施顺序

1. 抽出 `rustbox-control-service`，保证现有 gRPC 测试不变；
2. 补齐 connection/outbound/rule 的 transport-neutral snapshot，特别是 route chain；
3. 新增 `rustbox-clash-api` 的鉴权、错误、普通 JSON 路由；
4. 实现 NDJSON/WebSocket 三类 stream；
5. 接入组合根、CLI 参数与生命周期；
6. 完成 mihomo fixture contract tests 和 MetaCubeXD smoke test；
7. 再进入 Phase 2 测速，不与 Phase 1 混在一个变更中。

Phase 1 的完成定义是“官方 dashboard 核心页面可用”，不是“实现了若干同名 endpoint”。
