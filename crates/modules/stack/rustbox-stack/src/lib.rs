//! User-space network stack boundary.

use rustbox_host_api::BoxFuture;
use rustbox_io::PacketDevice;
use rustbox_kernel::FlowSink;

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
