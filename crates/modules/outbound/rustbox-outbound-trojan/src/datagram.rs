use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::{Endpoint, Host};
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::encode_endpoint;

pub(super) struct TrojanDatagram {
    reader: ReadHalf<Box<dyn ByteStream>>,
    writer: WriteHalf<Box<dyn ByteStream>>,
    read_buffer: Vec<u8>,
    write: WriteState,
}

enum WriteState {
    Idle,
    Frame {
        bytes: Vec<u8>,
        written: usize,
        payload_len: usize,
    },
    Flush {
        payload_len: usize,
    },
}

impl TrojanDatagram {
    pub(super) fn new(stream: Box<dyn ByteStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader,
            writer,
            read_buffer: Vec::with_capacity(2048),
            write: WriteState::Idle,
        }
    }
}

impl DatagramSocket for TrojanDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        loop {
            match parse_frame(&self.read_buffer) {
                Ok(Some(frame)) => {
                    if frame.payload_len > output.len() {
                        self.read_buffer.drain(..frame.frame_len);
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::InvalidInput,
                            format!(
                                "trojan UDP payload of {} bytes exceeds receive buffer",
                                frame.payload_len
                            ),
                        )));
                    }
                    output[..frame.payload_len].copy_from_slice(
                        &self.read_buffer
                            [frame.payload_offset..frame.payload_offset + frame.payload_len],
                    );
                    self.read_buffer.drain(..frame.frame_len);
                    return Poll::Ready(Ok((frame.payload_len, frame.source)));
                }
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            let mut bytes = [0_u8; 2048];
            let mut read_buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Err(closed("read trojan UDP frame")));
                }
                Poll::Ready(Ok(())) => self.read_buffer.extend_from_slice(read_buf.filled()),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_send_to(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        target: &Endpoint,
    ) -> Poll<Result<usize, IoError>> {
        loop {
            let this = &mut *self;
            match &mut this.write {
                WriteState::Idle => {
                    let length = match u16::try_from(payload.len()) {
                        Ok(length) => length,
                        Err(_) => {
                            return Poll::Ready(Err(IoError::new(
                                IoErrorKind::InvalidInput,
                                "trojan UDP payload exceeds 65535 bytes",
                            )));
                        }
                    };
                    let mut bytes = Vec::with_capacity(payload.len() + 260);
                    if let Err(error) = encode_endpoint(&mut bytes, target) {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::InvalidInput,
                            error.message,
                        )));
                    }
                    bytes.extend_from_slice(&length.to_be_bytes());
                    bytes.extend_from_slice(b"\r\n");
                    bytes.extend_from_slice(payload);
                    this.write = WriteState::Frame {
                        bytes,
                        written: 0,
                        payload_len: payload.len(),
                    };
                }
                WriteState::Frame {
                    bytes,
                    written,
                    payload_len,
                } => match Pin::new(&mut this.writer).poll_write(cx, &bytes[*written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(closed("write trojan UDP frame")));
                    }
                    Poll::Ready(Ok(n)) => {
                        *written += n;
                        if *written == bytes.len() {
                            this.write = WriteState::Flush {
                                payload_len: *payload_len,
                            };
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => return Poll::Pending,
                },
                WriteState::Flush { payload_len } => {
                    match Pin::new(&mut this.writer).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            let payload_len = *payload_len;
                            this.write = WriteState::Idle;
                            return Poll::Ready(Ok(payload_len));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

struct ParsedFrame {
    source: Endpoint,
    payload_offset: usize,
    payload_len: usize,
    frame_len: usize,
}

fn parse_frame(bytes: &[u8]) -> Result<Option<ParsedFrame>, IoError> {
    let Some(kind) = bytes.first().copied() else {
        return Ok(None);
    };
    let (host, address_end) = match kind {
        0x01 => {
            if bytes.len() < 5 {
                return Ok(None);
            }
            let octets = <[u8; 4]>::try_from(&bytes[1..5]).expect("IPv4 length checked");
            (Host::Ip(IpAddr::V4(octets.into())), 5)
        }
        0x03 => {
            let Some(length) = bytes.get(1).copied().map(usize::from) else {
                return Ok(None);
            };
            let end = 2 + length;
            if bytes.len() < end {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&bytes[2..end]).map_err(|error| {
                IoError::new(
                    IoErrorKind::InvalidInput,
                    format!("invalid trojan UDP domain: {error}"),
                )
            })?;
            (Host::domain(domain), end)
        }
        0x04 => {
            if bytes.len() < 17 {
                return Ok(None);
            }
            let octets = <[u8; 16]>::try_from(&bytes[1..17]).expect("IPv6 length checked");
            (Host::Ip(IpAddr::V6(octets.into())), 17)
        }
        value => {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                format!("unsupported trojan UDP address type {value}"),
            ));
        }
    };

    let header_end = address_end + 6;
    if bytes.len() < header_end {
        return Ok(None);
    }
    let port = u16::from_be_bytes([bytes[address_end], bytes[address_end + 1]]);
    let payload_len = usize::from(u16::from_be_bytes([
        bytes[address_end + 2],
        bytes[address_end + 3],
    ]));
    if bytes[address_end + 4..header_end] != *b"\r\n" {
        return Err(IoError::new(
            IoErrorKind::InvalidInput,
            "invalid trojan UDP frame delimiter",
        ));
    }
    let frame_len = header_end + payload_len;
    if bytes.len() < frame_len {
        return Ok(None);
    }
    Ok(Some(ParsedFrame {
        source: Endpoint::new(host, port),
        payload_offset: header_end,
        payload_len,
        frame_len,
    }))
}

fn closed(operation: &str) -> IoError {
    IoError::new(IoErrorKind::Closed, format!("{operation}: stream closed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_fragmented_udp_frame() {
        let source = Endpoint::new(Host::domain("dns.example"), 53);
        let (client, mut server) = tokio::io::duplex(8);
        let mut datagram = TrojanDatagram::new(Box::new(client));
        let mut frame = Vec::new();
        encode_endpoint(&mut frame, &source).unwrap();
        frame.extend_from_slice(b"\0\x04\r\npong");

        let writer = tokio::spawn(async move {
            server.write_all(&frame[..3]).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(&frame[3..]).await.unwrap();
        });

        let mut output = [0; 8];
        let (length, actual) =
            poll_fn(|cx| Pin::new(&mut datagram).poll_recv_from(cx, &mut output))
                .await
                .unwrap();
        writer.await.unwrap();
        assert_eq!(actual, source);
        assert_eq!(&output[..length], b"pong");
    }

    #[tokio::test]
    async fn writes_addressed_udp_frame() {
        let target = Endpoint::localhost_v4(53);
        let (client, mut server) = tokio::io::duplex(32);
        let mut datagram = TrojanDatagram::new(Box::new(client));
        poll_fn(|cx| Pin::new(&mut datagram).poll_send_to(cx, b"ping", &target))
            .await
            .unwrap();

        let mut frame = [0; 15];
        server.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x01\x7f\0\0\x01\0\x35\0\x04\r\nping");
    }
}
