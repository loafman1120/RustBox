//! RustBox 的共享应用接口和运行图装配。
//!
//! CLI、Flutter bridge 和其他嵌入方式都使用 [`RustBox`]。Tokio 是项目选定的异步运行时，
//! 不属于需要从公共应用接口隐藏或替换的架构层。

mod app;
mod capabilities;
mod compose;
mod control;
mod dns_hijack;
mod error;
mod routing;
mod ruleset;
mod runtime;

pub(crate) use compose::RuntimeGraphBuilder;

pub(crate) use app::ControlGrpcOptions;
pub use app::{RustBox, RustBoxError, RustBoxOptions};
pub use capabilities::RuntimeCapabilities;
pub use error::ComposeError;
pub use rustbox_dns_core::{DnsAnswer, DnsName, DnsQuery, DnsRecordType, DnsResponse};

/// Capability traits and their request/response types for embedded hosts.
/// This facade lets a bridge implement mobile adapters without depending on
/// RustBox's internal crate layout.
pub mod host {
    pub use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind, PacketDevice};
    pub use rustbox_kernel::host::*;
}

pub use host::{
    NetworkControl, NetworkMetadataLookup, NetworkProvider, NetworkProviderFactory,
    PacketDeviceProvider, ProcessLookup, TransparentProxyProvider,
};

#[cfg(test)]
mod tests;
