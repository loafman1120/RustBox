//! 控制面命令和快照模型。
//!
//! 控制面通过命令、快照和 reload plan 观察或调整引擎，不直接持有内核可变引用。

mod outbound_groups;

pub use outbound_groups::*;

use rustbox_config::CompiledConfig;
use rustbox_route::RouteTable;
use rustbox_types::OutboundId;

/// 控制面可表达的引擎命令。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineCommand {
    Reload(CompiledConfig),
    Stop,
    ReplaceRouteTable(RouteTable),
    EnableOutbound(OutboundId),
    DisableOutbound(OutboundId),
}

/// 面向 CLI、Flutter 和控制 API 的引擎状态快照。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineSnapshot {
    pub state: EngineState,
    pub generation: u64,
    pub inbound_count: usize,
    pub outbound_count: usize,
}

impl EngineSnapshot {
    pub fn created() -> Self {
        Self {
            state: EngineState::Created,
            generation: 0,
            inbound_count: 0,
            outbound_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineState {
    Created,
    Prepared,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadPhase {
    Prepare,
    Commit,
    Drain,
    Rollback,
}

/// reload 的轻量计划，表示下一代配置仍处于事务阶段而非直接修改 live graph。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadPlan {
    pub generation: u64,
    pub config: CompiledConfig,
    pub phase: ReloadPhase,
}

impl ReloadPlan {
    pub fn prepare(next_generation: u64, config: CompiledConfig) -> Self {
        Self {
            generation: next_generation,
            config,
            phase: ReloadPhase::Prepare,
        }
    }

    pub fn commit(mut self) -> Self {
        self.phase = ReloadPhase::Commit;
        self
    }

    pub fn drain(mut self) -> Self {
        self.phase = ReloadPhase::Drain;
        self
    }

    pub fn rollback(mut self) -> Self {
        self.phase = ReloadPhase::Rollback;
        self
    }
}

/// 控制面状态机，保存当前快照和待处理 reload。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlState {
    snapshot: EngineSnapshot,
    pending_reload: Option<ReloadPlan>,
}

impl ControlState {
    pub fn new(snapshot: EngineSnapshot) -> Self {
        Self {
            snapshot,
            pending_reload: None,
        }
    }

    pub fn snapshot(&self) -> &EngineSnapshot {
        &self.snapshot
    }

    pub fn pending_reload(&self) -> Option<&ReloadPlan> {
        self.pending_reload.as_ref()
    }

    pub fn replace_snapshot(&mut self, snapshot: EngineSnapshot) {
        self.snapshot = snapshot;
    }

    pub fn apply_command(&mut self, command: EngineCommand) {
        // 控制命令只更新控制状态；真正运行图替换由组合/运行时层执行。
        match command {
            EngineCommand::Reload(config) => {
                self.pending_reload =
                    Some(ReloadPlan::prepare(self.snapshot.generation + 1, config));
            }
            EngineCommand::Stop => {
                self.snapshot.state = EngineState::Stopping;
            }
            EngineCommand::ReplaceRouteTable(_)
            | EngineCommand::EnableOutbound(_)
            | EngineCommand::DisableOutbound(_) => {
                self.snapshot.generation = self.snapshot.generation.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbox_config::{ConfigCompiler, SourceConfig};
    use rustbox_types::Endpoint;

    #[test]
    fn reload_command_creates_prepare_plan_without_mutating_live_generation() {
        let source = SourceConfig::default_http_proxy(Endpoint::localhost_v4(0));
        let parsed = ConfigCompiler::parse(source).expect("parse");
        let normalized = ConfigCompiler::normalize(parsed).expect("normalize");
        let validated = ConfigCompiler::validate(normalized).expect("validate");
        let compiled = ConfigCompiler::compile(&validated).expect("compile");
        let mut state = ControlState::new(EngineSnapshot::created());

        state.apply_command(EngineCommand::Reload(compiled));

        assert_eq!(state.snapshot().generation, 0);
        assert_eq!(
            state.pending_reload().expect("pending reload").phase,
            ReloadPhase::Prepare
        );
    }
}
