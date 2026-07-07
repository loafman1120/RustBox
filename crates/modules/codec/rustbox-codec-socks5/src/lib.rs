//! 运行时无关的 SOCKS5 codec。
//!
//! 本 crate 只解析和编码协议字节，不打开 socket、不派生任务、不读文件、
//! 也不依赖 Tokio。它可被 inbound、未来 outbound 和 fuzz 测试共同复用。

use rustbox_types::{Endpoint, Host, IpAddress};

pub const SOCKS_VERSION: u8 = 0x05;

/// SOCKS5 greeting 中客户端声明的认证方法集合。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Greeting {
    pub methods: Vec<AuthMethod>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    NoAuthentication,
    UsernamePassword,
    NoAcceptableMethods,
    Private(u8),
}

/// SOCKS5 CONNECT 请求的解析结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub command: Command,
    pub target: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyCode {
    Succeeded,
    GeneralFailure,
    CommandNotSupported,
    AddressTypeNotSupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksError {
    pub message: String,
}

impl SocksError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 解析 greeting 字节，不执行任何网络 I/O。
pub fn parse_greeting(input: &[u8]) -> Result<Greeting, SocksError> {
    if input.len() < 2 {
        return Err(SocksError::new("SOCKS5 greeting is too short"));
    }
    if input[0] != SOCKS_VERSION {
        return Err(SocksError::new("unsupported SOCKS version"));
    }
    let method_count = input[1] as usize;
    if input.len() != method_count + 2 {
        return Err(SocksError::new("SOCKS5 greeting method length mismatch"));
    }
    let methods = input[2..].iter().copied().map(AuthMethod::from).collect();
    Ok(Greeting { methods })
}

/// 编码服务端选择的认证方法。
pub fn encode_method_selection(method: AuthMethod) -> [u8; 2] {
    [SOCKS_VERSION, method.into()]
}

/// 编码 SOCKS5 reply，供 inbound 成功/失败握手复用。
pub fn encode_reply(code: ReplyCode, bound: &Endpoint) -> Result<Vec<u8>, SocksError> {
    let mut output = vec![SOCKS_VERSION, code.into(), 0x00];
    match &bound.host {
        Host::Ip(IpAddress::V4(octets)) => {
            output.push(0x01);
            output.extend_from_slice(octets);
        }
        Host::Domain(domain) => {
            let len = u8::try_from(domain.len())
                .map_err(|_| SocksError::new("SOCKS5 domain reply is too long"))?;
            output.push(0x03);
            output.push(len);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddress::V6(octets)) => {
            output.push(0x04);
            output.extend_from_slice(octets);
        }
    }
    output.extend_from_slice(&bound.port.to_be_bytes());
    Ok(output)
}

/// 解析 SOCKS5 request，并把目标地址转换成 RustBox `Endpoint`。
pub fn parse_connect_request(input: &[u8]) -> Result<ConnectRequest, SocksError> {
    if input.len() < 7 {
        return Err(SocksError::new("SOCKS5 request is too short"));
    }
    if input[0] != SOCKS_VERSION {
        return Err(SocksError::new("unsupported SOCKS version"));
    }
    if input[2] != 0 {
        return Err(SocksError::new("SOCKS5 reserved byte must be zero"));
    }
    let command = Command::try_from(input[1])?;
    let (host, port_offset) = match input[3] {
        0x01 => {
            if input.len() < 10 {
                return Err(SocksError::new("SOCKS5 IPv4 request is too short"));
            }
            (
                Host::Ip(IpAddress::V4([input[4], input[5], input[6], input[7]])),
                8,
            )
        }
        0x03 => {
            let domain_len = input[4] as usize;
            let end = 5 + domain_len;
            if input.len() < end + 2 {
                return Err(SocksError::new("SOCKS5 domain request is too short"));
            }
            let domain = std::str::from_utf8(&input[5..end])
                .map_err(|_| SocksError::new("SOCKS5 domain is not UTF-8"))?;
            (Host::Domain(domain.to_string()), end)
        }
        0x04 => {
            if input.len() < 22 {
                return Err(SocksError::new("SOCKS5 IPv6 request is too short"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[4..20]);
            (Host::Ip(IpAddress::V6(octets)), 20)
        }
        _ => return Err(SocksError::new("unsupported SOCKS5 address type")),
    };
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    Ok(ConnectRequest {
        command,
        target: Endpoint::new(host, port),
    })
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::NoAuthentication,
            0x02 => Self::UsernamePassword,
            0xff => Self::NoAcceptableMethods,
            other => Self::Private(other),
        }
    }
}

impl From<AuthMethod> for u8 {
    fn from(value: AuthMethod) -> Self {
        match value {
            AuthMethod::NoAuthentication => 0x00,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::NoAcceptableMethods => 0xff,
            AuthMethod::Private(other) => other,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(SocksError::new("unsupported SOCKS5 command")),
        }
    }
}

impl From<ReplyCode> for u8 {
    fn from(value: ReplyCode) -> Self {
        match value {
            ReplyCode::Succeeded => 0x00,
            ReplyCode::GeneralFailure => 0x01,
            ReplyCode::CommandNotSupported => 0x07,
            ReplyCode::AddressTypeNotSupported => 0x08,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_connect_request_without_runtime_dependencies() {
        let request = parse_connect_request(&[
            0x05, 0x01, 0x00, 0x03, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', 0x01, 0xbb,
        ])
        .expect("parse socks request");

        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.target.port, 443);
        assert_eq!(
            request.target.host,
            Host::Domain("example.test".to_string())
        );
    }

    #[test]
    fn encodes_success_reply_without_runtime_dependencies() {
        let reply = encode_reply(
            ReplyCode::Succeeded,
            &Endpoint::new(Host::Ip(IpAddress::V4([0, 0, 0, 0])), 0),
        )
        .expect("encode reply");

        assert_eq!(reply, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }
}
