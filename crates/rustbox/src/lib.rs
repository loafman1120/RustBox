//! RustBox 的共享应用接口和运行图装配。
//!
//! CLI、FFI 和其他嵌入方式都使用 [`RustBox`]。Tokio 是项目选定的异步运行时，
//! 不属于需要从公共应用接口隐藏或替换的架构层。

mod app;
mod compose;
mod control;
mod error;
mod hosted;
mod platform;
mod routing;
mod runtime;

pub(crate) use compose::RuntimeGraphBuilder;

pub(crate) use app::ControlGrpcOptions;
pub use app::{RustBox, RustBoxError, RustBoxOptions};
pub use error::ComposeError;
pub use hosted::{HostedError, HostedRequestId, HostedRequestState, HostedRustBox};

#[cfg(test)]
mod tests;
