//! ShadowTLS v3 client transport.
//!
//! The record authentication logic is adapted from the permissively licensed
//! `ihciah/shadow-tls` reference implementation, but uses ordinary Tokio I/O
//! and current rustls instead of its Monoio/rustls fork.

use crate::{
    StreamTransport, TlsLayerConfig, TransportContext, TransportError, rustls_client_config,
};
use hmac::{Hmac as HmacImpl, Mac};
use rustbox_io::ByteStream;
use rustbox_kernel::{BoxFuture, TaskScope};
use rustbox_types::Endpoint;
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TLS_HEADER: usize = 5;
const HMAC_SIZE: usize = 4;
const SHADOW_HEADER: usize = TLS_HEADER + HMAC_SIZE;
const APPLICATION_DATA: u8 = 0x17;
const HANDSHAKE: u8 = 0x16;
const SERVER_HELLO: u8 = 0x02;
const SERVER_RANDOM_INDEX: usize = TLS_HEADER + 1 + 3 + 2;

#[derive(Clone)]
struct ShadowHmac(HmacImpl<Sha1>);

impl ShadowHmac {
    fn new(password: &str, data: &[u8], suffix: &[u8]) -> Self {
        let mut value = HmacImpl::<Sha1>::new_from_slice(password.as_bytes())
            .expect("HMAC accepts arbitrary key lengths");
        value.update(data);
        value.update(suffix);
        Self(value)
    }

    fn update(&mut self, value: &[u8]) {
        self.0.update(value);
    }

    fn finalize4(&self) -> [u8; 4] {
        self.0.clone().finalize().into_bytes()[..4]
            .try_into()
            .expect("four-byte slice")
    }
}

pub struct ShadowTlsTransport {
    server: Endpoint,
    password: String,
    tls: TlsLayerConfig,
    underlay: Arc<dyn StreamTransport>,
    tasks: TaskScope,
}

impl ShadowTlsTransport {
    pub fn new(
        server: Endpoint,
        password: String,
        tls: TlsLayerConfig,
        underlay: Arc<dyn StreamTransport>,
        tasks: TaskScope,
    ) -> Result<Self, TransportError> {
        if password.is_empty() {
            return Err(TransportError::new(
                "ShadowTLS v3 password must not be empty",
            ));
        }
        if !tls.enabled {
            return Err(TransportError::new("ShadowTLS v3 requires TLS"));
        }
        if tls.reality.is_some() || tls.ech_config.is_some() {
            return Err(TransportError::new(
                "ShadowTLS handshake does not support REALITY or ECH",
            ));
        }
        Ok(Self {
            server,
            password,
            tls,
            underlay,
            tasks,
        })
    }
}

impl StreamTransport for ShadowTlsTransport {
    fn connect<'a>(
        &'a self,
        ctx: TransportContext<'a>,
        _target: Endpoint,
    ) -> BoxFuture<'a, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            let raw = self.underlay.connect(ctx, self.server.clone()).await?;
            let (raw, server_random, handshake_hmac) =
                shadow_handshake(raw, &self.password, &self.tls).await?;
            let outbound_hmac = ShadowHmac::new(&self.password, &server_random, b"C");
            let inbound_hmac = ShadowHmac::new(&self.password, &server_random, b"S");
            let (application, relay) = tokio::io::duplex(64 * 1024);
            self.tasks.spawn(relay_records(
                relay,
                raw,
                outbound_hmac,
                inbound_hmac,
                Some(handshake_hmac),
            ));
            Ok(Box::new(application) as Box<dyn ByteStream>)
        })
    }
}

async fn shadow_handshake(
    mut raw: Box<dyn ByteStream>,
    password: &str,
    tls: &TlsLayerConfig,
) -> Result<(Box<dyn ByteStream>, [u8; 32], ShadowHmac), TransportError> {
    let server_name = tls
        .server_name
        .clone()
        .ok_or_else(|| TransportError::new("ShadowTLS TLS server_name is required"))?;
    let name = ServerName::try_from(server_name)
        .map_err(|error| TransportError::new(format!("ShadowTLS server name: {error}")))?;
    let config = rustls_client_config(tls)?;
    let mut connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|error| TransportError::new(format!("ShadowTLS TLS client: {error}")))?;
    let mut server_random = None;
    let mut handshake_hmac = None;
    let mut authorized = false;

    while connection.is_handshaking() {
        while connection.wants_write() {
            let mut record = Vec::new();
            connection
                .write_tls(&mut record)
                .map_err(|error| TransportError::new(format!("ShadowTLS ClientHello: {error}")))?;
            sign_client_hello(&mut record, password)?;
            raw.write_all(&record).await.map_err(|error| {
                TransportError::new(format!("ShadowTLS handshake write: {error}"))
            })?;
        }
        if !connection.wants_read() {
            continue;
        }
        let mut record = read_tls_record(&mut raw).await?;
        inspect_server_record(
            &mut record,
            password,
            &mut server_random,
            &mut handshake_hmac,
            &mut authorized,
        )?;
        connection
            .read_tls(&mut Cursor::new(&record))
            .map_err(|error| TransportError::new(format!("ShadowTLS TLS record: {error}")))?;
        connection
            .process_new_packets()
            .map_err(|error| TransportError::new(format!("ShadowTLS TLS handshake: {error}")))?;
    }
    while connection.wants_write() {
        let mut record = Vec::new();
        connection
            .write_tls(&mut record)
            .map_err(|error| TransportError::new(format!("ShadowTLS TLS finish: {error}")))?;
        raw.write_all(&record)
            .await
            .map_err(|error| TransportError::new(format!("ShadowTLS finish write: {error}")))?;
    }
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(TransportError::new(
            "ShadowTLS v3 strict mode requires TLS 1.3",
        ));
    }
    if !authorized {
        return Err(TransportError::new(
            "ShadowTLS server did not authenticate the TLS handshake",
        ));
    }
    Ok((
        raw,
        server_random.ok_or_else(|| TransportError::new("ShadowTLS ServerRandom missing"))?,
        handshake_hmac.ok_or_else(|| TransportError::new("ShadowTLS handshake HMAC missing"))?,
    ))
}

fn sign_client_hello(records: &mut [u8], password: &str) -> Result<(), TransportError> {
    let mut offset = 0;
    while offset + TLS_HEADER <= records.len() {
        let length = usize::from(u16::from_be_bytes([
            records[offset + 3],
            records[offset + 4],
        ]));
        let end = offset + TLS_HEADER + length;
        if end > records.len() {
            return Err(TransportError::new("truncated TLS ClientHello"));
        }
        let content_type = records[offset];
        let body = &mut records[offset + TLS_HEADER..end];
        const SESSION_ID: usize = 1 + 3 + 2 + 32 + 1;
        if content_type == HANDSHAKE && body.first() == Some(&1) && body.len() >= SESSION_ID + 32 {
            let mut session = [0_u8; 32];
            rand::fill(&mut session[..28]);
            body[SESSION_ID..SESSION_ID + 32].copy_from_slice(&session);
            let mut hmac = ShadowHmac::new(password, &[], &[]);
            hmac.update(body);
            session[28..].copy_from_slice(&hmac.finalize4());
            body[SESSION_ID..SESSION_ID + 32].copy_from_slice(&session);
            return Ok(());
        }
        offset = end;
    }
    Ok(())
}

fn inspect_server_record(
    record: &mut Vec<u8>,
    password: &str,
    server_random: &mut Option<[u8; 32]>,
    handshake_hmac: &mut Option<ShadowHmac>,
    authorized: &mut bool,
) -> Result<(), TransportError> {
    if record[0] == HANDSHAKE
        && record.get(TLS_HEADER) == Some(&SERVER_HELLO)
        && record.len() >= SERVER_RANDOM_INDEX + 32
    {
        let random: [u8; 32] = record[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]
            .try_into()
            .expect("checked length");
        *server_random = Some(random);
        *handshake_hmac = Some(ShadowHmac::new(password, &random, &[]));
    } else if record[0] == APPLICATION_DATA
        && record.len() >= SHADOW_HEADER
        && let Some(hmac) = handshake_hmac
    {
        hmac.update(&record[SHADOW_HEADER..]);
        if record[TLS_HEADER..SHADOW_HEADER] == hmac.finalize4() {
            let random = server_random.expect("HMAC requires ServerRandom");
            let key = Sha256::digest([password.as_bytes(), &random].concat());
            for (byte, key) in record[SHADOW_HEADER..].iter_mut().zip(key.iter().cycle()) {
                *byte ^= key;
            }
            record.copy_within(SHADOW_HEADER.., TLS_HEADER);
            record.truncate(record.len() - HMAC_SIZE);
            let size = (record.len() - TLS_HEADER) as u16;
            record[3..5].copy_from_slice(&size.to_be_bytes());
            *authorized = true;
        }
    }
    Ok(())
}

async fn read_tls_record<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut header = [0_u8; TLS_HEADER];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|error| TransportError::new(format!("ShadowTLS record header: {error}")))?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut record = Vec::with_capacity(TLS_HEADER + length);
    record.extend_from_slice(&header);
    record.resize(TLS_HEADER + length, 0);
    reader
        .read_exact(&mut record[TLS_HEADER..])
        .await
        .map_err(|error| TransportError::new(format!("ShadowTLS record body: {error}")))?;
    Ok(record)
}

async fn relay_records(
    application: tokio::io::DuplexStream,
    raw: Box<dyn ByteStream>,
    mut outbound_hmac: ShadowHmac,
    mut inbound_hmac: ShadowHmac,
    mut handshake_hmac: Option<ShadowHmac>,
) {
    let (mut app_read, mut app_write) = tokio::io::split(application);
    let (mut raw_read, mut raw_write) = tokio::io::split(raw);
    let upload = async {
        let mut payload = vec![0_u8; u16::MAX as usize - HMAC_SIZE];
        loop {
            let length = app_read.read(&mut payload).await?;
            if length == 0 {
                return std::io::Result::Ok(());
            }
            outbound_hmac.update(&payload[..length]);
            let signature = outbound_hmac.finalize4();
            outbound_hmac.update(&signature);
            let frame_length = length + HMAC_SIZE;
            let mut frame = Vec::with_capacity(TLS_HEADER + frame_length);
            frame.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
            frame.extend_from_slice(&(frame_length as u16).to_be_bytes());
            frame.extend_from_slice(&signature);
            frame.extend_from_slice(&payload[..length]);
            raw_write.write_all(&frame).await?;
        }
    };
    let download = async {
        loop {
            let record = read_tls_record_io(&mut raw_read).await?;
            if record[0] != APPLICATION_DATA || record.len() < SHADOW_HEADER {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected ShadowTLS record",
                ));
            }
            if let Some(ignore) = handshake_hmac.as_mut() {
                ignore.update(&record[SHADOW_HEADER..]);
                if record[TLS_HEADER..SHADOW_HEADER] == ignore.finalize4() {
                    continue;
                }
                handshake_hmac = None;
            }
            inbound_hmac.update(&record[SHADOW_HEADER..]);
            let expected = inbound_hmac.finalize4();
            if record[TLS_HEADER..SHADOW_HEADER] != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ShadowTLS HMAC mismatch",
                ));
            }
            inbound_hmac.update(&expected);
            app_write.write_all(&record[SHADOW_HEADER..]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    let _ = tokio::try_join!(upload, download);
}

async fn read_tls_record_io<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Vec<u8>> {
    let mut header = [0_u8; TLS_HEADER];
    reader.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut record = Vec::with_capacity(TLS_HEADER + length);
    record.extend_from_slice(&header);
    record.resize(TLS_HEADER + length, 0);
    reader.read_exact(&mut record[TLS_HEADER..]).await?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_hmac_is_chained() {
        let mut hmac = ShadowHmac::new("password", &[7; 32], b"C");
        hmac.update(b"payload");
        let first = hmac.finalize4();
        hmac.update(&first);
        assert_ne!(first, hmac.finalize4());
    }
}
