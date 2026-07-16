# sing-box 出站选择行为调查

调查日期：2026-07-15。本文只使用 sing-box 官方文档与官方仓库作为行为依据。

## 结论

sing-box 的手动出站选择属于 `selector` 组，不是任意修改路由规则。选择请求同时携带组 tag 和 child outbound tag；目标必须是该 selector 的成员。切换影响后续连接，是否中断既有入站连接由 `interrupt_exist_connections` 控制，默认不启用。

RustBox 直接采用 sing-box 的 `daemon.StartedService` 出站组 wire contract：`SubscribeGroups` 和 `SelectOutbound(groupTag, outboundTag)`；只有 `selector` 可写，`urltest` 只读。当前不实现连接中断、选择持久化和主动 URL 测速。

## 官方接口演进

1. sing-box 稳定版的 [Selector 文档](https://sing-box.sagernet.org/configuration/outbound/selector/) 说明 selector 由 `outbounds`、可选 `default` 和 `interrupt_exist_connections` 构成；未设置 default 时选择第一项。该页面仍写明 selector 通过 Clash API 控制。
2. [Clash API 文档](https://sing-box.sagernet.org/configuration/experimental/clash-api/) 说明 `store_selected` 已在 1.8.0 废弃；启用 cache file 后 selector 选择会自动持久化。它是 REST 控制面，不是 gRPC。
3. sing-box 1.14.0 新增官方 [sing-box API 服务](https://sing-box.sagernet.org/configuration/service/api/)：这是支持 bearer token、gRPC-Web 和 dashboard 的原生 gRPC 服务。
4. 官方仓库 [`daemon/started_service.proto`](https://github.com/SagerNet/sing-box/blob/testing/daemon/started_service.proto) 定义了 `SubscribeGroups` 与 `SelectOutbound`。请求字段是 `groupTag` 和 `outboundTag`；组状态包含 `tag`、`type`、`selectable`、`selected` 与 items。官方服务端只把 `selector` 标记为 selectable，对非 selector 返回 invalid argument，对未知组或未知 child 返回 not found。
5. [URLTest 文档](https://sing-box.sagernet.org/configuration/outbound/urltest/) 的当前默认值是 URL `https://www.gstatic.com/generate_204`、interval `3m`、tolerance `50ms`、idle timeout `30m`。RustBox 现有配置模型使用 `interval_seconds`，默认 300 秒，且尚无 idle timeout；这是既有配置差异，本次没有静默修改。

## RustBox 映射

| sing-box 概念 | RustBox 行为 |
| --- | --- |
| selector 的 `outbounds` | 配置编译为 child ID 与逻辑 tag 的固定成员表 |
| selector 的 `default` | 启动时的 `selected`；未设置时由配置层采用第一项 |
| group 状态订阅 | `daemon.StartedService/SubscribeGroups`，先发送完整初始状态，选择变化后再发送完整状态 |
| `SelectOutbound(groupTag, outboundTag)` | 原字段号与 Empty 返回值；成功后由订阅流发布新状态 |
| URLTest group | 可查询、不可手动选择；尚未运行周期探测 |
| `interrupt_exist_connections=false` | 当前固定为此语义：只影响切换后的新 flow |
| cache file / store selected | 尚未实现，重启或 reload 后回到配置 default |

路由表保留组自身的 outbound ID。`RuntimeRouter` 得到基础决策后，通过共享的 `OutboundGroupRegistry` 解析当前 child。切换只更新这份小型内存状态，不重建 engine，也不修改具体协议 outbound。配置层禁止 group 引用 group，从而避免递归与选择环。

## gRPC 错误语义

- 空 `groupTag` 或 `outboundTag`：`INVALID_ARGUMENT`。
- 组不存在，或 child 不属于该 selector：`NOT_FOUND`。
- 对 `urltest` 等非 selector 组手动选择：`INVALID_ARGUMENT`。
- 查询组需要 observe 权限；选择需要 control 权限。

## 后续范围

若继续对齐 sing-box，推荐依次实现：URLTest 主动探测与 tolerance 决策、选择持久化、`interrupt_exist_connections`。这些能力彼此独立，不应阻塞当前手动 selector 控制。
