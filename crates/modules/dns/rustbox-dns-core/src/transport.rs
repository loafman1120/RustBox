use crate::{
    DnsAnswer, DnsError, DnsQuery, DnsRecordType, DnsResponse, DnsServerConfig, DnsServerProtocol,
    DnsSocketProvider, DnsTransport,
};
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::runtime::{
    RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use hickory_resolver::proto::udp::DnsUdpSocket;
use hickory_resolver::proto::xfer::Protocol;
use rustbox_types::Host;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OnceCell;

/// One Tokio/Hickory adapter covers classic DNS and all encrypted transports.
pub struct HickoryTransport {
    server: DnsServerConfig,
    socket_provider: Option<Arc<dyn DnsSocketProvider>>,
    resolver: OnceCell<ResolverKind>,
}

enum ResolverKind {
    Direct(TokioResolver),
    Injected(HickoryResolver<GenericConnector<InjectedRuntimeProvider>>),
}

impl HickoryTransport {
    pub fn new(server: DnsServerConfig) -> Result<Self, DnsError> {
        if matches!(
            server.protocol,
            DnsServerProtocol::Tls | DnsServerProtocol::Https | DnsServerProtocol::Quic
        ) && !matches!(server.endpoint.host, Host::Domain(_))
        {
            return Err(DnsError::new(format!(
                "encrypted DNS server `{}` needs a domain endpoint for TLS verification",
                server.id
            )));
        }
        Ok(Self {
            server,
            socket_provider: None,
            resolver: OnceCell::new(),
        })
    }

    pub fn with_socket_provider(mut self, provider: Arc<dyn DnsSocketProvider>) -> Self {
        self.socket_provider = Some(provider);
        self
    }

    async fn build(&self) -> Result<ResolverKind, DnsError> {
        if self.server.outbound.is_some() && self.socket_provider.is_none() {
            return Err(DnsError::new(format!(
                "DNS server `{}` has no bound outbound socket provider",
                self.server.id
            )));
        }
        let socket_addr = match (&self.server.endpoint.host, &self.socket_provider) {
            (Host::Domain(_), Some(_)) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.server.endpoint.port)
            }
            (Host::Ip(ip), _) => SocketAddr::new(*ip, self.server.endpoint.port),
            (Host::Domain(domain), None) => {
                tokio::net::lookup_host((domain.as_str(), self.server.endpoint.port))
                    .await
                    .map_err(|error| {
                        DnsError::new(format!("bootstrap lookup for `{domain}` failed: {error}"))
                    })?
                    .next()
                    .ok_or_else(|| {
                        DnsError::new(format!(
                            "bootstrap lookup for `{domain}` returned no address"
                        ))
                    })?
            }
        };
        let protocol = match self.server.protocol {
            DnsServerProtocol::Udp => Protocol::Udp,
            DnsServerProtocol::Tcp => Protocol::Tcp,
            DnsServerProtocol::Tls => Protocol::Tls,
            DnsServerProtocol::Https => Protocol::Https,
            DnsServerProtocol::Quic => Protocol::Quic,
        };
        let mut name_server = NameServerConfig::new(socket_addr, protocol);
        if let Host::Domain(domain) = &self.server.endpoint.host {
            name_server.tls_dns_name = Some(domain.clone());
        }
        if self.server.protocol == DnsServerProtocol::Https {
            name_server.http_endpoint = Some("/dns-query".to_string());
        }
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
        if let Some(provider) = &self.socket_provider {
            if self.server.protocol == DnsServerProtocol::Quic {
                return Err(DnsError::new(
                    "DNS over QUIC cannot use a stream/datagram detour",
                ));
            }
            let connector = GenericConnector::new(InjectedRuntimeProvider {
                provider: provider.clone(),
                handle: TokioHandle::default(),
            });
            let mut builder = HickoryResolver::builder_with_config(config, connector);
            builder.options_mut().cache_size = 0;
            builder.options_mut().attempts = 1;
            return Ok(ResolverKind::Injected(builder.build()));
        }
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        builder.options_mut().cache_size = 0;
        builder.options_mut().attempts = 1;
        Ok(ResolverKind::Direct(builder.build()))
    }
}

impl DnsTransport for HickoryTransport {
    async fn exchange(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        let resolver = self.resolver.get_or_try_init(|| self.build()).await?;
        let record_type = match query.record_type {
            DnsRecordType::A => RecordType::A,
            DnsRecordType::Aaaa => RecordType::AAAA,
            DnsRecordType::Cname => RecordType::CNAME,
            DnsRecordType::Mx => RecordType::MX,
            DnsRecordType::Ns => RecordType::NS,
            DnsRecordType::Ptr => RecordType::PTR,
            DnsRecordType::Soa => RecordType::SOA,
            DnsRecordType::Srv => RecordType::SRV,
            DnsRecordType::Txt => RecordType::TXT,
            DnsRecordType::Caa => RecordType::CAA,
            DnsRecordType::Https => RecordType::HTTPS,
            DnsRecordType::Svcb => RecordType::SVCB,
            DnsRecordType::Naptr => RecordType::NAPTR,
            DnsRecordType::Tlsa => RecordType::TLSA,
            DnsRecordType::Ds => RecordType::DS,
            DnsRecordType::Dnskey => RecordType::DNSKEY,
            DnsRecordType::Any => RecordType::ANY,
            DnsRecordType::Other(code) => RecordType::from(code),
        };
        let lookup = match resolver {
            ResolverKind::Direct(resolver) => {
                resolver
                    .lookup(format!("{}.", query.name.as_str()), record_type)
                    .await
            }
            ResolverKind::Injected(resolver) => {
                resolver
                    .lookup(format!("{}.", query.name.as_str()), record_type)
                    .await
            }
        }
        .map_err(|error| {
            DnsError::new(format!(
                "DNS server `{}` query failed: {error}",
                self.server.id
            ))
        })?;
        let records = lookup.record_iter().cloned().collect::<Vec<_>>();
        let answers = records
            .iter()
            .filter_map(|record| match record.data() {
                RData::A(value) => Some(DnsAnswer {
                    host: Host::Ip(IpAddr::V4(value.0)),
                    ttl_seconds: record.ttl(),
                }),
                RData::AAAA(value) => Some(DnsAnswer {
                    host: Host::Ip(IpAddr::V6(value.0)),
                    ttl_seconds: record.ttl(),
                }),
                _ => None,
            })
            .collect();
        Ok(DnsResponse { answers, records })
    }
}

#[derive(Clone)]
struct InjectedRuntimeProvider {
    provider: Arc<dyn DnsSocketProvider>,
    handle: TokioHandle,
}

impl RuntimeProvider for InjectedRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = InjectedUdpSocket;
    type Tcp = AsyncIoTokioAsStd<InjectedTcpStream>;
    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }
    fn connect_tcp(
        &self,
        _server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let provider = self.provider.clone();
        Box::pin(async move {
            let open = provider.open_stream();
            let stream = match timeout {
                Some(timeout) => tokio::time::timeout(timeout, open).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "DNS outbound connect timed out")
                })?,
                None => open.await,
            };
            stream
                .map(|inner| {
                    AsyncIoTokioAsStd(InjectedTcpStream {
                        inner: Mutex::new(inner),
                    })
                })
                .map_err(dns_io_error)
        })
    }
    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let provider = self.provider.clone();
        Box::pin(async move {
            provider
                .open_datagram()
                .await
                .map(|inner| InjectedUdpSocket {
                    inner: Mutex::new(inner),
                    server_addr,
                })
                .map_err(dns_io_error)
        })
    }
}

struct InjectedTcpStream {
    inner: Mutex<Box<dyn rustbox_io::ByteStream>>,
}
impl AsyncRead for InjectedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = self
            .get_mut()
            .inner
            .get_mut()
            .map_err(|_| io::Error::other("poisoned DNS stream"))?;
        Pin::new(&mut **inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for InjectedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = self
            .get_mut()
            .inner
            .get_mut()
            .map_err(|_| io::Error::other("poisoned DNS stream"))?;
        Pin::new(&mut **inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self
            .get_mut()
            .inner
            .get_mut()
            .map_err(|_| io::Error::other("poisoned DNS stream"))?;
        Pin::new(&mut **inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self
            .get_mut()
            .inner
            .get_mut()
            .map_err(|_| io::Error::other("poisoned DNS stream"))?;
        Pin::new(&mut **inner).poll_shutdown(cx)
    }
}

struct InjectedUdpSocket {
    inner: Mutex<Box<dyn rustbox_io::DatagramSocket>>,
    server_addr: SocketAddr,
}
impl DnsUdpSocket for InjectedUdpSocket {
    type Time = TokioTime;
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned DNS datagram"))?;
        Pin::new(&mut **inner)
            .poll_recv_from(cx, buf)
            .map(|result| {
                result
                    .map(|(len, _endpoint)| (len, self.server_addr))
                    .map_err(|error| io::Error::other(error.message))
            })
    }
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned DNS datagram"))?;
        let endpoint = target.into();
        Pin::new(&mut **inner)
            .poll_send_to(cx, buf, &endpoint)
            .map_err(|error| io::Error::other(error.message))
    }
}

fn dns_io_error(error: DnsError) -> io::Error {
    io::Error::other(error.message)
}
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{RData, Record};
    use rustbox_types::Endpoint;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn exchanges_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut packet = vec![0; 2048];
            let (len, peer) = server.recv_from(&mut packet).await.expect("receive");
            let response = response(&packet[..len]);
            server.send_to(&response, peer).await.expect("send");
        });
        assert_transport(DnsServerProtocol::Udp, port).await;
    }

    #[tokio::test]
    async fn exchanges_over_tcp() {
        let server = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.expect("accept");
            let len = stream.read_u16().await.expect("length") as usize;
            let mut packet = vec![0; len];
            stream.read_exact(&mut packet).await.expect("receive");
            let response = response(&packet);
            stream
                .write_u16(response.len() as u16)
                .await
                .expect("length");
            stream.write_all(&response).await.expect("send");
        });
        assert_transport(DnsServerProtocol::Tcp, port).await;
    }

    #[tokio::test]
    async fn exchanges_tcp_through_injected_socket_provider() {
        let server = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.expect("accept");
            let len = stream.read_u16().await.expect("length") as usize;
            let mut packet = vec![0; len];
            stream.read_exact(&mut packet).await.expect("receive");
            let response = response(&packet);
            stream
                .write_u16(response.len() as u16)
                .await
                .expect("length");
            stream.write_all(&response).await.expect("send");
        });
        let transport = HickoryTransport::new(DnsServerConfig {
            id: "proxied".into(),
            protocol: DnsServerProtocol::Tcp,
            endpoint: Endpoint::new(Host::domain("must-not-bootstrap.invalid"), 53),
            outbound: Some("proxy".into()),
        })
        .expect("transport")
        .with_socket_provider(Arc::new(TestSocketProvider { port }));
        let result = transport
            .exchange(DnsQuery {
                name: crate::DnsName::new("transport.test").expect("name"),
                record_type: DnsRecordType::A,
            })
            .await
            .expect("exchange");
        assert_eq!(
            result.answers[0].host,
            Host::Ip(IpAddr::from([203, 0, 113, 9]))
        );
    }

    #[tokio::test]
    async fn exchanges_udp_through_injected_socket_provider() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut packet = vec![0; 2048];
            let (len, peer) = server.recv_from(&mut packet).await.expect("receive");
            server
                .send_to(&response(&packet[..len]), peer)
                .await
                .expect("send");
        });
        let transport = HickoryTransport::new(DnsServerConfig {
            id: "proxied".into(),
            protocol: DnsServerProtocol::Udp,
            endpoint: Endpoint::new(Host::domain("must-not-bootstrap.invalid"), 53),
            outbound: Some("proxy".into()),
        })
        .expect("transport")
        .with_socket_provider(Arc::new(TestSocketProvider { port }));
        let result = transport
            .exchange(DnsQuery {
                name: crate::DnsName::new("transport.test").expect("name"),
                record_type: DnsRecordType::A,
            })
            .await
            .expect("exchange");
        assert_eq!(
            result.answers[0].host,
            Host::Ip(IpAddr::from([203, 0, 113, 9]))
        );
    }

    struct TestSocketProvider {
        port: u16,
    }
    impl crate::DnsSocketProvider for TestSocketProvider {
        fn open_stream(&self) -> crate::SocketFuture<'_, Box<dyn rustbox_io::ByteStream>> {
            Box::pin(async move {
                tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
                    .await
                    .map(|stream| Box::new(stream) as Box<dyn rustbox_io::ByteStream>)
                    .map_err(|error| DnsError::new(error.to_string()))
            })
        }
        fn open_datagram(&self) -> crate::SocketFuture<'_, Box<dyn rustbox_io::DatagramSocket>> {
            Box::pin(async move {
                let socket = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| DnsError::new(e.to_string()))?;
                Ok(Box::new(TestUdpSocket {
                    socket,
                    target: SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
                }) as Box<dyn rustbox_io::DatagramSocket>)
            })
        }
    }

    struct TestUdpSocket {
        socket: UdpSocket,
        target: SocketAddr,
    }
    impl rustbox_io::DatagramSocket for TestUdpSocket {
        fn poll_recv_from(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<(usize, Endpoint), rustbox_io::IoError>> {
            let mut read = ReadBuf::new(buf);
            match self.socket.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(peer)) => Poll::Ready(Ok((read.filled().len(), peer.into()))),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                Poll::Pending => Poll::Pending,
            }
        }
        fn poll_send_to(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
            _target: &Endpoint,
        ) -> Poll<Result<usize, rustbox_io::IoError>> {
            self.socket
                .poll_send_to(cx, buf, self.target)
                .map_err(Into::into)
        }
    }

    async fn assert_transport(protocol: DnsServerProtocol, port: u16) {
        let transport = HickoryTransport::new(DnsServerConfig {
            id: "local".to_string(),
            protocol,
            endpoint: Endpoint::localhost_v4(port),
            outbound: None,
        })
        .expect("transport");
        let result = transport
            .exchange(DnsQuery {
                name: crate::DnsName::new("transport.test").expect("name"),
                record_type: DnsRecordType::A,
            })
            .await
            .expect("exchange");
        assert_eq!(
            result.answers[0].host,
            Host::Ip(IpAddr::from([203, 0, 113, 9]))
        );
    }

    fn response(packet: &[u8]) -> Vec<u8> {
        let request = Message::from_vec(packet).expect("query");
        let query = request.queries()[0].clone();
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .add_query(query.clone())
            .add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
            ));
        response.to_vec().expect("response")
    }
}
