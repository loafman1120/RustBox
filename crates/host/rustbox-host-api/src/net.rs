//! Standard-library network value conversions shared by runtime adapters.

use rustbox_types::{Endpoint, Host, IpAddress};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn ip_address_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

pub fn socket_addr_to_endpoint(addr: SocketAddr) -> Endpoint {
    let host = match addr.ip() {
        IpAddr::V4(ip) => Host::Ip(IpAddress::V4(ip.octets())),
        IpAddr::V6(ip) => Host::Ip(IpAddress::V6(ip.octets())),
    };
    Endpoint::new(host, addr.port())
}

/// Returns `None` for domain endpoints because name resolution belongs to the
/// calling network provider rather than this value-conversion module.
pub fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Option<SocketAddr> {
    match endpoint.host {
        Host::Ip(ip) => Some(SocketAddr::new(ip_address_to_std(ip), endpoint.port)),
        Host::Domain(_) => None,
    }
}
