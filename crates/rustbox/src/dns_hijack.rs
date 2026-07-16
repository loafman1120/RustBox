use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_dns_core::DnsSubsystem;
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_kernel::{BoxFuture, Outbound, OutboundContext, OutboundError, TaskScope};
use rustbox_types::{Endpoint, OutboundId};
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct DnsHijackOutbound {
    dns: Arc<DnsSubsystem>,
    tasks: TaskScope,
}

impl DnsHijackOutbound {
    pub(crate) fn new(dns: Arc<DnsSubsystem>, tasks: TaskScope) -> Self {
        Self { dns, tasks }
    }
}

impl Outbound for DnsHijackOutbound {
    fn id(&self) -> OutboundId {
        // Internal hijackers live in a separate registry; this id is never
        // exposed to routing or inserted in the outbound table.
        OutboundId::new(core::num::NonZeroU64::MIN)
    }

    fn open_stream(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn ByteStream>, OutboundError>> {
        Box::pin(async move {
            let (application, mut service) = tokio::io::duplex(64 * 1024);
            let dns = self.dns.clone();
            self.tasks.spawn(async move {
                loop {
                    let length = match service.read_u16().await {
                        Ok(length) => usize::from(length),
                        Err(_) => return,
                    };
                    let mut request = vec![0_u8; length];
                    if service.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    let Ok(response) = dns.exchange_wire(&request).await else {
                        return;
                    };
                    let Ok(length) = u16::try_from(response.len()) else {
                        return;
                    };
                    if service.write_u16(length).await.is_err()
                        || service.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
            });
            Ok(Box::new(application) as Box<dyn ByteStream>)
        })
    }

    fn open_datagram(
        &self,
        _ctx: OutboundContext<'_>,
        _target: Endpoint,
    ) -> BoxFuture<'_, Result<Box<dyn DatagramSocket>, OutboundError>> {
        Box::pin(async move {
            Ok(Box::new(DnsHijackDatagram {
                dns: self.dns.clone(),
                response: None,
            }) as Box<dyn DatagramSocket>)
        })
    }
}

type ResponseFuture = Pin<Box<dyn Future<Output = Result<(Vec<u8>, Endpoint), IoError>> + Send>>;

struct DnsHijackDatagram {
    dns: Arc<DnsSubsystem>,
    response: Option<ResponseFuture>,
}

impl DatagramSocket for DnsHijackDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        let Some(response) = self.response.as_mut() else {
            return Poll::Pending;
        };
        match response.as_mut().poll(cx) {
            Poll::Ready(Ok((packet, source))) => {
                self.response = None;
                if packet.len() > output.len() {
                    return Poll::Ready(Err(IoError::new(
                        IoErrorKind::InvalidInput,
                        "DNS response exceeds datagram receive buffer",
                    )));
                }
                output[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Err(error)) => {
                self.response = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        packet: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        if self.response.is_some() {
            return Poll::Pending;
        }
        let length = packet.len();
        let packet = packet.to_vec();
        let source = target.clone();
        let dns = self.dns.clone();
        self.response = Some(Box::pin(async move {
            dns.exchange_wire(&packet)
                .await
                .map(|packet| (packet, source))
                .map_err(|error| IoError::new(IoErrorKind::Other, error.message))
        }));
        Poll::Ready(Ok(length))
    }
}
