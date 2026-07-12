use super::*;

/// 文件日志 sink。文件 sink 属于宿主适配层，不进入可移植核心。
#[derive(Debug)]
pub struct FileObservabilitySink {
    level: LevelFilter,
    file: Mutex<File>,
}

impl FileObservabilitySink {
    pub fn append(path: impl AsRef<Path>, level: LevelFilter) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            level,
            file: Mutex::new(file),
        })
    }
}

impl ObservabilitySink for FileObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.level.allows(event.level) {
                return;
            }
            let line = format_event(&event);
            let mut file = self.file.lock().expect("file observability sink lock");
            let _ = writeln!(file, "{line}");
        })
    }
}

/// 平台日志后端。Windows ETW、Android logcat、Apple unified logging 等由宿主实现。
pub trait PlatformLogBackend: Send + Sync {
    fn log(&self, event: &Event, formatted: &str);
}

#[derive(Debug)]
pub struct PlatformLogSink<B> {
    level: LevelFilter,
    backend: B,
}

impl<B> PlatformLogSink<B>
where
    B: PlatformLogBackend,
{
    pub fn new(backend: B, level: LevelFilter) -> Self {
        Self { level, backend }
    }
}

impl<B> ObservabilitySink for PlatformLogSink<B>
where
    B: PlatformLogBackend,
{
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.level.allows(event.level) {
                let formatted = format_event(&event);
                self.backend.log(&event, &formatted);
            }
        })
    }
}

/// 远程遥测导出器。HTTP/gRPC/OTLP 客户端由宿主或外层 crate 适配。
pub trait TelemetryExporter: Send + Sync {
    fn export(&self, event: Event) -> BoxFuture<'_, Result<(), TelemetryError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryError {
    pub message: String,
}

impl TelemetryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub struct RemoteTelemetrySink<E> {
    level: LevelFilter,
    exporter: E,
}

impl<E> RemoteTelemetrySink<E>
where
    E: TelemetryExporter,
{
    pub fn new(exporter: E, level: LevelFilter) -> Self {
        Self { level, exporter }
    }
}

impl<E> ObservabilitySink for RemoteTelemetrySink<E>
where
    E: TelemetryExporter,
{
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.level.allows(event.level) {
                let _ = self.exporter.export(event).await;
            }
        })
    }
}
