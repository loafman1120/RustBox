# 原生配置契约

RustBox 的原生 TOML 与原生 JSON 是同一份配置语言的两种编码。两者共同反序列化到
`ConfigDocument`，再进入 `FileConfig -> SourceConfig -> CompiledConfig` 流水线。
Clash YAML 是独立的兼容输入前端，不属于本契约。

## 唯一来源

原生配置的机器契约由实际 Rust 反序列化模型生成：

- Serde 类型和属性定义字段、枚举、默认存在性与未知字段策略；
- Rust doc comments 提供字段和分支说明；
- Garde 与少量 `schemars` 属性提供可静态表达的范围和格式；
- `SUPPORTED_SCHEMA_VERSION` 定义当前文档版本。

生成文件位于
[`rustbox-config-v1.schema.json`](../crates/rustbox-config-file/schema/rustbox-config-v1.schema.json)。
它使用 JSON Schema 2020-12，同时适用于原生 TOML 和 JSON。生成文件不得手工编辑。

## 使用

CLI 可输出内嵌契约：

```powershell
cargo run -p rustbox-app -- config-schema
```

启用 Clash HTTP API 后，也可直接读取：

```text
GET /docs/config.schema.json
Content-Type: application/schema+json
```

Taplo 可使用文档顶部的注释指令关联发布版本：

```toml
#:schema https://loafman1120.github.io/RustBox/schema/rustbox-config-v1.schema.json

schema_version = 1
```

该指令只是 TOML 注释，不会进入 RustBox 配置模型。原生 JSON 编辑器可直接关联同一个
Schema URL。

## 生成与防漂移

修改任何原生配置字段后，重新生成契约：

```powershell
cargo run -p rustbox-config-file --features schema-generation `
  --example generate-schema
```

CI 使用 `--check` 重新计算契约；生成结果与仓库中的版本不一致时构建失败。生成器显式
使用 JSON Schema 2020-12 的反序列化契约，避免依赖库默认值变化。

## 验证边界

JSON Schema 负责结构校验和编辑器体验，包括字段名、类型、枚举、分支、基础范围、
默认值和未知字段。它不替代配置编译器。

以下内容仍由 `rustbox-app check-config` 验证：

- inbound、outbound、DNS server 和 rule-set 引用；
- 依赖环与路由终结动作；
- 认证字段、TLS 材料等跨字段组合；
- 文件、远程资源和缓存路径；
- 编译 feature 与当前平台能力；
- 完整运行图能否规范化、验证和编译。

因此，一个文档通过 JSON Schema 表示“结构合法”；只有通过 `check-config` 才表示
“RustBox 当前构建可以使用”。

## 版本规则

Schema 文件名、Schema `$id`、根字段 `schema_version` 和
`SUPPORTED_SCHEMA_VERSION` 必须一致。会改变既有文档解释或导致旧解析器拒绝的结构
变化必须提升配置版本。版本化 Schema URL 应保持不可变；无版本的运行时
`/docs/config.schema.json` 始终返回当前构建支持的版本。
