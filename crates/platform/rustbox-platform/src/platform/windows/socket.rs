use rustbox_kernel::{DialOptions, NetError, TokioSocketPolicy};
use socket2::{SockAddr, Socket};
use socket2_ext::{AddressBinding, BindDeviceOption};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct WindowsSocketPolicy;

impl TokioSocketPolicy for WindowsSocketPolicy {
    fn bind_interface(
        &self,
        socket: &Socket,
        interface: &str,
        destination: IpAddr,
    ) -> Result<(), NetError> {
        let option = if destination.is_ipv4() {
            BindDeviceOption::v4(interface)
        } else {
            BindDeviceOption::v6(interface)
        };
        socket.bind_to_device(option).map_err(socket_error)
    }

    fn bind_udp_socket(
        &self,
        socket: &Socket,
        requested: SocketAddr,
        options: &DialOptions,
    ) -> Result<(), NetError> {
        if let Some(mark) = options.routing_mark {
            self.set_routing_mark(socket, mark)?;
        }
        if let Some(interface) = &options.bind_interface {
            if requested.port() != 0 || !requested.ip().is_unspecified() {
                return Err(NetError::new(
                    "Windows interface-bound UDP sockets require an unspecified address and port 0",
                ));
            }
            return self.bind_interface(socket, interface, requested.ip());
        }

        let configured = if requested.is_ipv4() {
            options.inet4_bind_address
        } else {
            options.inet6_bind_address
        };
        let address = configured.map_or(requested, |source| {
            SocketAddr::new(source, requested.port())
        });
        if address.is_ipv4() != requested.is_ipv4() {
            return Err(NetError::new(
                "UDP source and listener address families differ",
            ));
        }
        socket.bind(&SockAddr::from(address)).map_err(socket_error)
    }
}

fn socket_error(error: std::io::Error) -> NetError {
    NetError::new(error.to_string())
}
