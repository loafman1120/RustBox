use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct SystemDialer;

impl SystemDialer {
    pub async fn dial_context(addr: &str) -> Result<TcpStream, std::io::Error> {
        timeout(Duration::from_secs(5), TcpStream::connect(addr)).await?
    }
}
