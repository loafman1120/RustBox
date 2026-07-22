use rustbox_kernel::{NetError, TokioSocketPolicy};
use socket2::Socket;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LinuxSocketPolicy;

impl TokioSocketPolicy for LinuxSocketPolicy {
    fn bind_interface(
        &self,
        socket: &Socket,
        interface: &str,
        _destination: IpAddr,
    ) -> Result<(), NetError> {
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(socket_error)
    }

    fn set_routing_mark(&self, socket: &Socket, mark: u32) -> Result<(), NetError> {
        socket.set_mark(mark).map_err(socket_error)
    }
}

fn socket_error(error: std::io::Error) -> NetError {
    NetError::new(error.to_string())
}
