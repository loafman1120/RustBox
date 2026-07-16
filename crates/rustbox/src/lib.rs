//! RustBox 的共享应用接口和运行图装配。
//!
//! CLI、Flutter bridge 和其他嵌入方式都使用 [`RustBox`]。Tokio 是项目选定的异步运行时，
//! 不属于需要从公共应用接口隐藏或替换的架构层。

mod app;
mod compose;
mod control;
mod dns_hijack;
mod error;
mod platform;
mod routing;
mod ruleset;
mod runtime;

pub(crate) use compose::RuntimeGraphBuilder;

pub(crate) use app::ControlGrpcOptions;
pub use app::{RustBox, RustBoxError, RustBoxOptions};
pub use error::ComposeError;
pub use rustbox_dns_core::{DnsAnswer, DnsName, DnsQuery, DnsRecordType, DnsResponse};

#[cfg(test)]
mod tests;
