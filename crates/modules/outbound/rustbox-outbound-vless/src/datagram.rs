use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::Endpoint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

pub(super) struct VlessDatagram {
    target: Endpoint,
    reader: ReadHalf<Box<dyn ByteStream>>,
    writer: WriteHalf<Box<dyn ByteStream>>,
    read: ReadState,
    write: WriteState,
}

enum ReadState {
    Length { bytes: [u8; 2], read: usize },
    Payload { bytes: Vec<u8>, read: usize },
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

impl VlessDatagram {
    pub(super) fn new(stream: Box<dyn ByteStream>, target: Endpoint) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader,
            writer,
            read: ReadState::Length {
                bytes: [0; 2],
                read: 0,
            },
            write: WriteState::Idle,
        }
    }
}

impl DatagramSocket for VlessDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        loop {
            let this = &mut *self;
            match &mut this.read {
                ReadState::Length { bytes, read } => {
                    match poll_read_exact(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                        Poll::Ready(Ok(n)) => *read += n,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if *read == bytes.len() {
                        let len = usize::from(u16::from_be_bytes(*bytes));
                        this.read = ReadState::Payload {
                            bytes: vec![0; len],
                            read: 0,
                        };
                    }
                }
                ReadState::Payload { bytes, read } => {
                    if *read < bytes.len() {
                        match poll_read_exact(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                            Poll::Ready(Ok(n)) => *read += n,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    if *read == bytes.len() {
                        if bytes.len() > output.len() {
                            let length = bytes.len();
                            this.read = ReadState::Length {
                                bytes: [0; 2],
                                read: 0,
                            };
                            return Poll::Ready(Err(IoError::new(
                                IoErrorKind::InvalidInput,
                                format!(
                                    "VLESS UDP payload of {length} bytes exceeds receive buffer"
                                ),
                            )));
                        }
                        let length = bytes.len();
                        output[..length].copy_from_slice(bytes);
                        let source = this.target.clone();
                        this.read = ReadState::Length {
                            bytes: [0; 2],
                            read: 0,
                        };
                        return Poll::Ready(Ok((length, source)));
                    }
                }
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
                    if target != &this.target {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::InvalidInput,
                            "VLESS native UDP session cannot change target",
                        )));
                    }
                    let length = match u16::try_from(payload.len()) {
                        Ok(length) => length,
                        Err(_) => {
                            return Poll::Ready(Err(IoError::new(
                                IoErrorKind::InvalidInput,
                                "VLESS UDP payload exceeds 65535 bytes",
                            )));
                        }
                    };
                    let mut bytes = Vec::with_capacity(payload.len() + 2);
                    bytes.extend_from_slice(&length.to_be_bytes());
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
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(closed("write VLESS UDP frame"))),
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

fn poll_read_exact<R: AsyncRead + Unpin>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    output: &mut [u8],
) -> Poll<Result<usize, IoError>> {
    if output.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let mut buffer = ReadBuf::new(output);
    match reader.as_mut().poll_read(cx, &mut buffer) {
        Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
            Poll::Ready(Err(closed("read VLESS UDP frame")))
        }
        Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
        Poll::Pending => Poll::Pending,
    }
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
    async fn preserves_packet_boundaries_across_partial_stream_reads() {
        let target = Endpoint::localhost_v4(53);
        let (client, mut server) = tokio::io::duplex(8);
        let mut datagram = VlessDatagram::new(Box::new(client), target.clone());

        server.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        server.write_all(&[4, 1, 2, 3, 4]).await.unwrap();

        let mut output = [0; 8];
        let (length, source) =
            poll_fn(|cx| Pin::new(&mut datagram).poll_recv_from(cx, &mut output))
                .await
                .unwrap();
        assert_eq!(source, target);
        assert_eq!(&output[..length], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn writes_length_prefixed_packet() {
        let target = Endpoint::localhost_v4(53);
        let (client, mut server) = tokio::io::duplex(8);
        let mut datagram = VlessDatagram::new(Box::new(client), target.clone());

        let written = poll_fn(|cx| Pin::new(&mut datagram).poll_send_to(cx, b"ping", &target))
            .await
            .unwrap();
        assert_eq!(written, 4);

        let mut frame = [0; 6];
        server.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\0\x04ping");
    }
}
