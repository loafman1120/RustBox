//! 用户态网络栈边界。
//!
//! TUN/PacketDevice 进入后，由该边界把三层包转换为内核 Flow。
//! 当前只保留接口和 planned 实现，避免把具体 stack 塞进 kernel。

use rustbox_host_api::BoxFuture;
use rustbox_io::PacketDevice;
use rustbox_kernel::FlowSink;

/// 包设备到 FlowSink 的桥接接口。
pub trait NetworkStack: Send {
    fn attach(
        &mut self,
        device: Box<dyn PacketDevice>,
        sink: Box<dyn FlowSink>,
    ) -> BoxFuture<'_, Result<(), StackError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackError {
    pub message: String,
}

impl StackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 占位 stack，用显式错误标记该能力尚未实现。
#[derive(Default)]
pub struct PlannedStack;

impl PlannedStack {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkStack for PlannedStack {
    fn attach(
        &mut self,
        _device: Box<dyn PacketDevice>,
        _sink: Box<dyn FlowSink>,
    ) -> BoxFuture<'_, Result<(), StackError>> {
        Box::pin(async {
            Err(StackError::new(
                "packet-to-flow network stack is not implemented yet",
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackCapability {
    pub supports_tcp: bool,
    pub supports_udp: bool,
    pub supports_ipv4: bool,
    pub supports_ipv6: bool,
}
