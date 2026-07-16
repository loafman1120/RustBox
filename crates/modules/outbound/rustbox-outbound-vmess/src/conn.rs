use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::body::BodyCipher;
use rustbox_kernel::TaskScope;

/// Spawn a VMess relay task that handles AEAD body record framing.
///
/// Returns a `DuplexStream` that the caller reads/writes plain bytes on.
/// The background task encrypts writes into body records and decrypts
/// reads from body records on the underlying stream.
pub fn spawn_vmess_relay(
    sessions: &TaskScope,
    stream: Box<dyn rustbox_io::ByteStream>,
    mut read_cipher: BodyCipher,
    mut write_cipher: BodyCipher,
    resp_v: u8,
) -> DuplexStream {
    let (client, proxy) = tokio::io::duplex(32768);

    sessions.spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(stream);

        if let Err(error) = read_cipher.read_response_header(&mut rd, resp_v).await {
            tracing::warn!(%error, "vmess: invalid response header");
            return;
        }

        let (mut proxy_rd, mut proxy_wr) = tokio::io::split(proxy);

        // Upstream: stream → decrypt → proxy_wr
        let read_direction = async move {
            while let Ok(plaintext) = read_cipher.read_record(&mut rd).await {
                if proxy_wr.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            let _ = proxy_wr.shutdown().await;
        };

        // Downstream: proxy_rd → encrypt → stream
        let write_direction = async move {
            let mut buf = vec![0u8; BodyCipher::max_plaintext()];
            loop {
                let n = match proxy_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if write_cipher.write_record(&mut wr, &buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        };

        tokio::select! {
            _ = read_direction => {}
            _ = write_direction => {}
        }
    });

    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Security;
    use std::time::Duration;

    fn ciphers() -> (BodyCipher, BodyCipher) {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        (
            BodyCipher::new(Security::None, &key, &iv, 0x42),
            BodyCipher::new(Security::None, &key, &iv, 0x42),
        )
    }

    #[tokio::test]
    async fn upstream_eof_terminates_the_pending_write_direction() {
        let sessions = TaskScope::new();
        let (upstream, mut peer) = tokio::io::duplex(64);
        let (read_cipher, write_cipher) = ciphers();
        let response_header = read_cipher.seal_response_header_for_test(0x42);
        let _client = spawn_vmess_relay(
            &sessions,
            Box::new(upstream),
            read_cipher,
            write_cipher,
            0x42,
        );
        sessions.close();

        peer.write_all(&response_header).await.unwrap();
        drop(peer);

        tokio::time::timeout(Duration::from_secs(1), sessions.wait())
            .await
            .expect("VMess relay task outlived upstream EOF");
    }

    #[tokio::test]
    async fn client_eof_terminates_the_pending_read_direction() {
        let sessions = TaskScope::new();
        let (upstream, mut peer) = tokio::io::duplex(64);
        let (read_cipher, write_cipher) = ciphers();
        let response_header = read_cipher.seal_response_header_for_test(0x42);
        let client = spawn_vmess_relay(
            &sessions,
            Box::new(upstream),
            read_cipher,
            write_cipher,
            0x42,
        );
        sessions.close();

        peer.write_all(&response_header).await.unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(1), sessions.wait())
            .await
            .expect("VMess relay task outlived client EOF");
    }
}
