use super::*;

/// 控制台输出目标。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

/// 事件级别过滤器，当前可由 `RUSTBOX_LOG` 配置。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LevelFilter {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl LevelFilter {
    pub fn from_env() -> Self {
        std::env::var("RUSTBOX_LOG")
            .ok()
            .and_then(|value| Self::parse(&value))
            .unwrap_or(Self::Info)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    pub(crate) fn allows(self, level: EventLevel) -> bool {
        match self {
            Self::Trace => true,
            Self::Debug => !matches!(level, EventLevel::Trace),
            Self::Info => matches!(
                level,
                EventLevel::Info | EventLevel::Warn | EventLevel::Error
            ),
            Self::Warn => matches!(level, EventLevel::Warn | EventLevel::Error),
            Self::Error => matches!(level, EventLevel::Error),
            Self::Off => false,
        }
    }
}

/// Concrete destinations selected by an application host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservabilityOutput {
    Console,
    File(PathBuf),
    ConsoleAndFile(PathBuf),
}

/// Fully resolved observability settings, independent of their CLI, file, or
/// environment source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservabilityConfig {
    pub level: LevelFilter,
    pub output: ObservabilityOutput,
}

impl ObservabilityConfig {
    pub fn build(self) -> io::Result<RuntimeObservability> {
        let store = Arc::new(ObservabilityStore::default());
        let mut sink = CompositeObservabilitySink::new().with_sink(store.clone());

        if matches!(
            self.output,
            ObservabilityOutput::Console | ObservabilityOutput::ConsoleAndFile(_)
        ) {
            sink = sink.with_sink(Arc::new(ConsoleObservabilitySink::stderr(self.level)));
        }

        if let ObservabilityOutput::File(path) | ObservabilityOutput::ConsoleAndFile(path) =
            self.output
        {
            sink = sink.with_sink(Arc::new(FileObservabilitySink::append(path, self.level)?));
        }

        Ok(RuntimeObservability {
            sink: Arc::new(sink),
            store,
        })
    }
}

pub struct RuntimeObservability {
    pub sink: Arc<CompositeObservabilitySink>,
    pub store: Arc<ObservabilityStore>,
}

impl RuntimeObservability {
    /// In-memory observability for embedded hosts that do not want implicit output.
    pub fn store_only() -> Self {
        let store = Arc::new(ObservabilityStore::default());
        let sink = Arc::new(CompositeObservabilitySink::new().with_sink(store.clone()));
        Self { sink, store }
    }
}

/// 控制台 sink，用于 CLI 默认观测输出。
#[derive(Clone, Debug)]
pub struct ConsoleObservabilitySink {
    stream: ConsoleStream,
    level: LevelFilter,
}

impl ConsoleObservabilitySink {
    pub fn stderr(level: LevelFilter) -> Self {
        Self {
            stream: ConsoleStream::Stderr,
            level,
        }
    }

    pub fn stdout(level: LevelFilter) -> Self {
        Self {
            stream: ConsoleStream::Stdout,
            level,
        }
    }

    pub fn stderr_from_env() -> Self {
        Self::stderr(LevelFilter::from_env())
    }

    pub fn level(&self) -> LevelFilter {
        self.level
    }
}

impl ObservabilitySink for ConsoleObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.level.allows(event.level) {
                return;
            }

            let line = format_event(&event);
            match self.stream {
                ConsoleStream::Stdout => println!("{line}"),
                ConsoleStream::Stderr => eprintln!("{line}"),
            }
        })
    }
}

/// 记录型 sink，供测试和嵌入方断言事件序列。
#[derive(Debug, Default)]
pub struct RecordingObservabilitySink {
    events: Mutex<Vec<Event>>,
}

impl RecordingObservabilitySink {
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .expect("recording observability sink lock")
            .clone()
    }
}

impl ObservabilitySink for RecordingObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("recording observability sink lock")
                .push(event);
        })
    }
}

/// 组合 sink，用于同时输出到 console、文件、metrics store、平台日志或遥测。
#[derive(Clone, Default)]
pub struct CompositeObservabilitySink {
    sinks: Vec<Arc<dyn ObservabilitySink>>,
}

impl CompositeObservabilitySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sink(mut self, sink: Arc<dyn ObservabilitySink>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl ObservabilitySink for CompositeObservabilitySink {
    fn emit(&self, event: Event) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            for sink in &self.sinks {
                sink.emit(event.clone()).await;
            }
        })
    }
}
