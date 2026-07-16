use core::pin::Pin;
use core::task::{Context, Poll};
use rustbox_io::{ByteStream, DatagramSocket, IoError, IoErrorKind};
use rustbox_types::Endpoint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::body::BodyCipher;

pub(super) struct VmessDatagram {
    target: Endpoint,
    reader: ReadHalf<Box<dyn ByteStream>>,
    writer: WriteHalf<Box<dyn ByteStream>>,
    read_cipher: BodyCipher,
    write_cipher: BodyCipher,
    expected_response: u8,
    read: ReadState,
    write: WriteState,
}

enum ReadState {
    ResponseLength { bytes: [u8; 18], read: usize },
    ResponseHeader { bytes: Vec<u8>, read: usize },
    RecordLength { bytes: [u8; 2], read: usize },
    Record { bytes: Vec<u8>, read: usize },
}

enum WriteState {
    Idle,
    Record {
        bytes: Vec<u8>,
        written: usize,
        payload_len: usize,
    },
    Flush {
        payload_len: usize,
    },
}

impl VmessDatagram {
    pub(super) fn new(
        stream: Box<dyn ByteStream>,
        read_cipher: BodyCipher,
        write_cipher: BodyCipher,
        expected_response: u8,
        target: Endpoint,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader,
            writer,
            read_cipher,
            write_cipher,
            expected_response,
            read: ReadState::ResponseLength {
                bytes: [0; 18],
                read: 0,
            },
            write: WriteState::Idle,
        }
    }
}

impl DatagramSocket for VmessDatagram {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<Result<(usize, Endpoint), IoError>> {
        loop {
            let this = &mut *self;
            match &mut this.read {
                ReadState::ResponseLength { bytes, read } => {
                    match poll_read_some(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                        Poll::Ready(Ok(n)) => *read += n,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if *read == bytes.len() {
                        let length = match this.read_cipher.response_header_length(bytes) {
                            Ok(length) => length,
                            Err(error) => return Poll::Ready(Err(invalid(error))),
                        };
                        this.read = ReadState::ResponseHeader {
                            bytes: vec![0; length + 16],
                            read: 0,
                        };
                    }
                }
                ReadState::ResponseHeader { bytes, read } => {
                    match poll_read_some(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                        Poll::Ready(Ok(n)) => *read += n,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if *read == bytes.len() {
                        if let Err(error) = this
                            .read_cipher
                            .validate_response_header(bytes, this.expected_response)
                        {
                            return Poll::Ready(Err(invalid(error)));
                        }
                        this.read = ReadState::RecordLength {
                            bytes: [0; 2],
                            read: 0,
                        };
                    }
                }
                ReadState::RecordLength { bytes, read } => {
                    match poll_read_some(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                        Poll::Ready(Ok(n)) => *read += n,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if *read == bytes.len() {
                        let length = usize::from(u16::from_be_bytes(*bytes));
                        if length == 0 {
                            return Poll::Ready(Err(closed("VMess UDP stream ended")));
                        }
                        this.read = ReadState::Record {
                            bytes: vec![0; length],
                            read: 0,
                        };
                    }
                }
                ReadState::Record { bytes, read } => {
                    match poll_read_some(Pin::new(&mut this.reader), cx, &mut bytes[*read..]) {
                        Poll::Ready(Ok(n)) => *read += n,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if *read == bytes.len() {
                        let payload = match this.read_cipher.open_record(bytes) {
                            Ok(payload) => payload,
                            Err(error) => return Poll::Ready(Err(invalid(error))),
                        };
                        this.read = ReadState::RecordLength {
                            bytes: [0; 2],
                            read: 0,
                        };
                        if payload.len() > output.len() {
                            return Poll::Ready(Err(IoError::new(
                                IoErrorKind::InvalidInput,
                                format!(
                                    "VMess UDP payload of {} bytes exceeds receive buffer",
                                    payload.len()
                                ),
                            )));
                        }
                        output[..payload.len()].copy_from_slice(&payload);
                        return Poll::Ready(Ok((payload.len(), this.target.clone())));
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
                            "VMess native UDP session cannot change target",
                        )));
                    }
                    let record = match this.write_cipher.seal_record(payload) {
                        Ok(record) => record,
                        Err(error) => return Poll::Ready(Err(invalid(error))),
                    };
                    this.write = WriteState::Record {
                        bytes: record,
                        written: 0,
                        payload_len: payload.len(),
                    };
                }
                WriteState::Record {
                    bytes,
                    written,
                    payload_len,
                } => match Pin::new(&mut this.writer).poll_write(cx, &bytes[*written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(closed("write VMess UDP record")));
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

fn poll_read_some<R: AsyncRead + Unpin>(
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
            Poll::Ready(Err(closed("read VMess UDP record")))
        }
        Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
        Poll::Pending => Poll::Pending,
    }
}

fn invalid(error: std::io::Error) -> IoError {
    IoError::new(IoErrorKind::InvalidInput, error.to_string())
}

fn closed(message: &str) -> IoError {
    IoError::new(IoErrorKind::Closed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Security;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ciphers() -> (BodyCipher, BodyCipher) {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        (
            BodyCipher::new(Security::None, &key, &iv, 0x42),
            BodyCipher::new(Security::None, &key, &iv, 0x42),
        )
    }

    #[tokio::test]
    async fn writes_one_record_per_datagram() {
        let target = Endpoint::localhost_v4(53);
        let (client, mut server) = tokio::io::duplex(16);
        let (read_cipher, write_cipher) = ciphers();
        let mut datagram = VmessDatagram::new(
            Box::new(client),
            read_cipher,
            write_cipher,
            0x42,
            target.clone(),
        );

        poll_fn(|cx| Pin::new(&mut datagram).poll_send_to(cx, b"ping", &target))
            .await
            .unwrap();
        let mut frame = [0; 6];
        server.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\0\x04ping");
    }

    #[tokio::test]
    async fn reads_response_header_then_one_datagram() {
        let target = Endpoint::localhost_v4(53);
        let (client, mut server) = tokio::io::duplex(64);
        let (read_cipher, write_cipher) = ciphers();
        let response_header = read_cipher.seal_response_header_for_test(0x42);
        let mut datagram = VmessDatagram::new(
            Box::new(client),
            read_cipher,
            write_cipher,
            0x42,
            target.clone(),
        );
        let writer = tokio::spawn(async move {
            server.write_all(&response_header[..5]).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(&response_header[5..]).await.unwrap();
            server.write_all(b"\0\x04pong").await.unwrap();
        });

        let mut output = [0; 8];
        let (length, source) =
            poll_fn(|cx| Pin::new(&mut datagram).poll_recv_from(cx, &mut output))
                .await
                .unwrap();
        writer.await.unwrap();
        assert_eq!(source, target);
        assert_eq!(&output[..length], b"pong");
    }
}
