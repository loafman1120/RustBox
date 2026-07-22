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
        self.inner.local_addr().ok().map(Endpoint::from)
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
                peer: peer.into(),
                original_destination,
            })
        })
    }
}

async fn bind_tcp_listener(listen: &Endpoint) -> Result<TcpListener, TransparentProxyError> {
    let addr = listen.socket_addr().ok_or_else(|| {
        TransparentProxyError::new(format!(
            "cannot bind transparent listener to domain {}",
            listen.host
        ))
    })?;
    TcpListener::bind(addr)
        .await
        .map_err(|err| TransparentProxyError::new(format!("bind transparent TCP: {err}")))
}

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
                Host::Ip(IpAddr::V4(ip)),
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
                Host::Ip(IpAddr::V6(ip)),
                u16::from_be(addr.sin6_port),
            ))
        }
    }
}
