//! compile-and-swap reload 事务模型。
//!
//! reload 必须先准备新配置，再提交替换，最后排空旧图；失败时保留显式回滚阶段。

use rustbox_config::CompiledConfig;

/// 单次 reload 事务，记录目标代际、编译配置和当前阶段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadTransaction {
    generation: u64,
    config: CompiledConfig,
    phase: ReloadPhase,
}

impl ReloadTransaction {
    pub fn prepare(generation: u64, config: CompiledConfig) -> Self {
        Self {
            generation,
            config,
            phase: ReloadPhase::Prepare,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn phase(&self) -> ReloadPhase {
        self.phase
    }

    pub fn config(&self) -> &CompiledConfig {
        &self.config
    }

    pub fn commit(&mut self) -> Result<(), ReloadError> {
        self.transition(ReloadPhase::Prepare, ReloadPhase::Commit)
    }

    pub fn drain(&mut self) -> Result<(), ReloadError> {
        self.transition(ReloadPhase::Commit, ReloadPhase::Drain)
    }

    pub fn rollback(&mut self) -> Result<(), ReloadError> {
        match self.phase {
            ReloadPhase::Prepare | ReloadPhase::Commit => {
                self.phase = ReloadPhase::Rollback;
                Ok(())
            }
            ReloadPhase::Drain | ReloadPhase::Rollback => Err(ReloadError::new(
                "reload transaction cannot roll back from current phase",
            )),
        }
    }

    fn transition(&mut self, from: ReloadPhase, to: ReloadPhase) -> Result<(), ReloadError> {
        // 阶段转换必须单向、有序，避免边验证边修改 live engine。
        if self.phase != from {
            return Err(ReloadError::new(format!(
                "invalid reload transition from {:?} to {:?}",
                self.phase, to
            )));
        }
        self.phase = to;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadPhase {
    Prepare,
    Commit,
    Drain,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadError {
    pub message: String,
}

impl ReloadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_config::{ConfigCompiler, SourceConfig};
    use rustbox_types::Endpoint;

    #[test]
    fn reload_transaction_enforces_prepare_commit_drain_order() {
        let source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(0));
        let parsed = ConfigCompiler::parse(source).expect("parse");
        let normalized = ConfigCompiler::normalize(parsed).expect("normalize");
        let validated = ConfigCompiler::validate(normalized).expect("validate");
        let compiled = ConfigCompiler::compile(validated).expect("compile");
        let mut transaction = ReloadTransaction::prepare(2, compiled);

        assert_eq!(transaction.phase(), ReloadPhase::Prepare);
        transaction.commit().expect("commit");
        transaction.drain().expect("drain");
        assert_eq!(transaction.phase(), ReloadPhase::Drain);
        assert!(transaction.rollback().is_err());
    }
}
