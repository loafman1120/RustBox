# RustBox 文档

RustBox 是供桌面与移动应用嵌入的客户端网络引擎。本文档只维护当前行为、稳定边界和
必要的运维约束；具体配置以 `examples/` 中可执行的 TOML 为准。

| 文档 | 适合谁 | 内容 |
| --- | --- | --- |
| [架构](architecture.md) | 引擎与模块开发者 | 分层、数据流、配置编译和生命周期 |
| [配置与协议](configuration.md) | 客户端集成者 | 路由、DNS、transport 和协议边界 |
| [原生配置契约](configuration-contract.md) | 配置工具与客户端开发者 | JSON Schema、版本、生成和验证边界 |
| [客户端网络](client-networking.md) | 桌面应用开发者 | TUN、Windows、切网和系统状态恢复 |
| [控制 API](control-api.md) | UI 与控制面开发者 | gRPC、Clash API、鉴权和兼容范围 |

常用入口：

- 基础代理配置：[`examples/rustbox.toml`](../examples/rustbox.toml)
- TUN 配置：[`examples/tun-transparent.toml`](../examples/tun-transparent.toml)
- Flutter 集成：[`apps/rustbox-flutter/README.md`](../apps/rustbox-flutter/README.md)
- 构建和运行：项目根目录 [`README.md`](../README.md)

文档不重复维护完整字段表。原生 TOML/JSON 的字段契约由 Rust 反序列化模型生成；
新增或修改配置时，应更新配置模型、字段注释、验证测试和对应示例。只有涉及长期设计
边界时才扩展手写指南。
