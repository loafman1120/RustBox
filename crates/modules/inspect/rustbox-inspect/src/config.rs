use tokio::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SniffConfig {
    pub max_bytes: usize,
    pub max_datagrams: usize,
    pub timeout: Duration,
}

impl Default for SniffConfig {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024,
            max_datagrams: 4,
            timeout: Duration::from_millis(300),
        }
    }
}
