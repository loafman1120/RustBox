use super::*;

impl TransparentProxyProvider for LinuxPlatform {
    fn bind_tcp(
        &self,
        request: TransparentTcpBind,
    ) -> BoxFuture<'_, Result<Box<dyn TransparentStreamListener>, TransparentProxyError>> {
        Box::pin(bind_linux_transparent_tcp(request))
    }
}

async fn bind_linux_transparent_tcp(
    request: TransparentTcpBind,
) -> Result<Box<dyn TransparentStreamListener>, TransparentProxyError> {
    if request.mode != TransparentRedirectMode::Redirect {
        return Err(TransparentProxyError::new(format!(
            "Linux transparent proxy currently supports redirect mode only; requested {:?}",
            request.mode
        )));
    }
    if request.mark.is_some() {
        return Err(TransparentProxyError::new(
            "Linux transparent redirect does not use socket mark; set mark only for tproxy",
        ));
    }

    let listener = bind_tcp_listener(&request.listen).await?;
    Ok(Box::new(LinuxTransparentTcpListener { inner: listener })
        as Box<dyn TransparentStreamListener>)
}

struct LinuxTransparentTcpListener {
    inner: TcpListener,
}

impl TransparentStreamListener for LinuxTransparentTcpListener {
    fn local_endpoint(&self) -> Option<Endpoint> {
        self.inner.local_addr().ok().map(socket_addr_to_endpoint)
    }

    fn accept(
        &mut self,
    ) -> BoxFuture<'_, Result<AcceptedTransparentStream, TransparentProxyError>> {
        Box::pin(async move {
            let (stream, peer) = self.inner.accept().await.map_err(|err| {
                TransparentProxyError::new(format!("accept transparent TCP: {err}"))
            })?;
            let original_destination = original_destination(&stream)?;
            Ok(AcceptedTransparentStream {
                stream: Box::new(stream),
                peer: socket_addr_to_endpoint(peer),
                original_destination,
            })
        })
    }
}

#[cfg(target_os = "linux")]
async fn bind_tcp_listener(listen: &Endpoint) -> Result<TcpListener, TransparentProxyError> {
    let addr = endpoint_to_socket_addr(listen).map_err(TransparentProxyError::new)?;
    TcpListener::bind(addr)
        .await
        .map_err(|err| TransparentProxyError::new(format!("bind transparent TCP: {err}")))
}

#[cfg(not(target_os = "linux"))]
async fn bind_tcp_listener(_listen: &Endpoint) -> Result<TcpListener, TransparentProxyError> {
    Err(TransparentProxyError::new(
        "Linux transparent proxy is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn original_destination(stream: &TcpStream) -> Result<Endpoint, TransparentProxyError> {
    match stream
        .local_addr()
        .map(|addr| addr.is_ipv4())
        .unwrap_or(true)
    {
        true => {
            let addr = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::OriginalDst)
                .map_err(|err| {
                    TransparentProxyError::new(format!("read SO_ORIGINAL_DST: {err}"))
                })?;
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Ok(Endpoint::new(
                Host::Ip(IpAddress::V4(ip.octets())),
                u16::from_be(addr.sin_port),
            ))
        }
        false => {
            let addr =
                nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::Ip6tOriginalDst)
                    .map_err(|err| {
                        TransparentProxyError::new(format!("read IP6T_SO_ORIGINAL_DST: {err}"))
                    })?;
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            Ok(Endpoint::new(
                Host::Ip(IpAddress::V6(ip.octets())),
                u16::from_be(addr.sin6_port),
            ))
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn original_destination(_stream: &TcpStream) -> Result<Endpoint, TransparentProxyError> {
    Err(TransparentProxyError::new(
        "Linux transparent proxy is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn endpoint_to_socket_addr(endpoint: &Endpoint) -> Result<SocketAddr, String> {
    match &endpoint.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip_to_std(*ip), endpoint.port)),
        Host::Domain(domain) => Err(format!(
            "cannot bind transparent listener to domain {domain}"
        )),
    }
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> Endpoint {
    let host = match addr.ip() {
        IpAddr::V4(ip) => Host::Ip(IpAddress::V4(ip.octets())),
        IpAddr::V6(ip) => Host::Ip(IpAddress::V6(ip.octets())),
    };
    Endpoint::new(host, addr.port())
}

#[cfg(target_os = "linux")]
fn ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}
