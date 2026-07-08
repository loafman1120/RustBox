use crate::SourceConfig;

/// 已完成输入层解析的配置，目前保留阶段边界以便后续加入 normalization。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedConfig {
    pub source: SourceConfig,
}

/// 已完成格式无关默认值和兼容性归一的配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedConfig {
    pub source: SourceConfig,
}

/// 已通过语义校验的配置，保证 ID 唯一、引用存在、基础拓扑可构造。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    pub source: SourceConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub message: String,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 配置编译器维持 Source -> Parsed -> Normalized -> Validated -> Compiled 的阶段边界。
pub struct ConfigCompiler;
