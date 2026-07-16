//! Shared UDP-over-TCP v2 framing.

use rustbox_types::{Endpoint, Host, IpAddress};
use std::future::Future;
use std::io;

pub const SENTINEL: &str = "sp.v2.udp-over-tcp.arpa";

pub trait Reader {
    fn read_exact<'a>(
        &'a mut self,
        output: &'a mut [u8],
    ) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

pub fn encode_address(target: &Endpoint) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32);
    match &target.host {
        Host::Ip(IpAddress::V4(value)) => {
            output.push(0);
            output.extend_from_slice(value);
        }
        Host::Domain(value) => {
            output.push(2);
            output.push(u8::try_from(value.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "UOT domain exceeds 255 bytes")
            })?);
            output.extend_from_slice(value.as_bytes());
        }
        Host::Ip(IpAddress::V6(value)) => {
            output.push(1);
            output.extend_from_slice(value);
        }
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(output)
}

pub fn encode_datagram(target: &Endpoint, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UOT packet is too large"))?;
    let mut output = encode_address(target)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub async fn read_address<R: Reader + Send>(reader: &mut R) -> io::Result<Endpoint> {
    let mut kind = [0_u8; 1];
    reader.read_exact(&mut kind).await?;
    let host = match kind[0] {
        0 => {
            let mut value = [0_u8; 4];
            reader.read_exact(&mut value).await?;
            Host::Ip(IpAddress::V4(value))
        }
        2 => {
            let mut length = [0_u8; 1];
            reader.read_exact(&mut length).await?;
            let mut value = vec![0_u8; usize::from(length[0])];
            reader.read_exact(&mut value).await?;
            Host::domain(
                String::from_utf8(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        }
        1 => {
            let mut value = [0_u8; 16];
            reader.read_exact(&mut value).await?;
            Host::Ip(IpAddress::V6(value))
        }
        value => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported UOT address type {value}"),
            ));
        }
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port).await?;
    Ok(Endpoint::new(host, u16::from_be_bytes(port)))
}

pub async fn read_datagram<R: Reader + Send>(reader: &mut R) -> io::Result<(Vec<u8>, Endpoint)> {
    let endpoint = read_address(reader).await?;
    let mut length = [0_u8; 2];
    reader.read_exact(&mut length).await?;
    let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    reader.read_exact(&mut payload).await?;
    Ok((payload, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SliceReader<'a>(&'a [u8]);
    impl Reader for SliceReader<'_> {
        async fn read_exact<'a>(&'a mut self, output: &'a mut [u8]) -> io::Result<()> {
            if self.0.len() < output.len() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            output.copy_from_slice(&self.0[..output.len()]);
            self.0 = &self.0[output.len()..];
            Ok(())
        }
    }

    #[tokio::test]
    async fn codec_round_trips_domain() {
        let endpoint = Endpoint::new(Host::domain("dns.example"), 53);
        let frame = encode_datagram(&endpoint, b"query").unwrap();
        assert_eq!(frame[0], 2, "UOT v2 uses address family 2 for FQDN");
        let (payload, decoded) = read_datagram(&mut SliceReader(&frame)).await.unwrap();
        assert_eq!(decoded, endpoint);
        assert_eq!(payload, b"query");
    }

    #[tokio::test]
    async fn ipv4_wire_format_matches_sing_uot_v2() {
        let endpoint = Endpoint::new(Host::Ip(IpAddress::V4([127, 0, 0, 1])), 53);
        let frame = encode_datagram(&endpoint, b"query").unwrap();
        assert_eq!(
            frame,
            [0, 127, 0, 0, 1, 0, 53, 0, 5, b'q', b'u', b'e', b'r', b'y']
        );
        let (payload, decoded) = read_datagram(&mut SliceReader(&frame)).await.unwrap();
        assert_eq!(decoded, endpoint);
        assert_eq!(payload, b"query");
    }
}
