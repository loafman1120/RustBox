//! Socket capability injected by the composition root.
//!
//! DNS transports never select routes themselves. A provider is scoped to one
//! configured server and opens physical or detoured sockets supplied by the host.

use crate::DnsError;
use rustbox_io::{ByteStream, DatagramSocket};
use std::{future::Future, pin::Pin};

pub type SocketFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsError>> + Send + 'a>>;

pub trait DnsSocketProvider: Send + Sync {
    fn open_stream(&self) -> SocketFuture<'_, Box<dyn ByteStream>>;
    fn open_datagram(&self) -> SocketFuture<'_, Box<dyn DatagramSocket>>;
}
