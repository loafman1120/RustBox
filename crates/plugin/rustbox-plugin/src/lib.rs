//! 未来插件边界元数据。
//!
//! RustBox v0.x 优先使用 workspace 内静态模块。本 crate 只描述未来外部插件
//! 需要声明的元数据，不把内部 Rust trait 当成外部 ABI。

use rustbox_registry::{CapabilityRequirement, ModuleCategory};

/// 插件清单，声明 ABI 版本、模块类别和所需宿主能力。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginManifest {
    pub id: PluginId,
    pub abi: PluginAbi,
    pub modules: Vec<PluginModule>,
    pub required_capabilities: Vec<CapabilityRequirement>,
}

impl PluginManifest {
    pub fn validate(&self) -> Result<(), PluginManifestError> {
        if self.id.0.is_empty() {
            return Err(PluginManifestError::new("plugin id must not be empty"));
        }
        if self.abi.major == 0 {
            return Err(PluginManifestError::new(
                "plugin ABI major version must be non-zero",
            ));
        }
        if self.modules.is_empty() {
            return Err(PluginManifestError::new(
                "plugin must declare at least one module",
            ));
        }
        for module in &self.modules {
            if module.kind.is_empty() {
                return Err(PluginManifestError::new(
                    "plugin module kind must not be empty",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PluginId(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PluginAbi {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginModule {
    pub category: ModuleCategory,
    pub kind: String,
    pub config_schema: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginManifestError {
    pub message: String,
}

impl PluginManifestError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_declares_modules_without_exposing_rust_traits() {
        let manifest = PluginManifest {
            id: PluginId("example".to_string()),
            abi: PluginAbi { major: 1, minor: 0 },
            modules: vec![PluginModule {
                category: ModuleCategory::Outbound,
                kind: "direct-like".to_string(),
                config_schema: None,
            }],
            required_capabilities: vec![CapabilityRequirement::Network],
        };

        manifest.validate().expect("valid manifest");
    }
}
