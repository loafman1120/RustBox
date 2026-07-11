use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
use rustbox::{RustBox, RustBoxOptions};
use rustbox_config_file::{ObservabilityOutput, load_toml_file};
use rustbox_control::EngineCommand;
use rustbox_control_api::{AuthPolicy, ControlApiConfig};
use rustbox_observability::{
    CompositeObservabilitySink, ConsoleObservabilitySink, FileObservabilitySink, LevelFilter,
    ObservabilityStore,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// 应用入口只负责选择配置来源、建立组合根、启动和响应 Ctrl-C。
#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();
    let control_api_config = control_api_config_from_cli(&cli.control)
        .unwrap_or_else(|err| Cli::command().error(ErrorKind::ValueValidation, err).exit());
    let (mut runtime, listen) = match cli.command {
        CliCommand::PlatformCapabilities => {
            print_platform_capabilities();
            return;
        }
        CliCommand::CheckConfig { config } => {
            let file_config = load_toml_file(&config).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", config.display(), err.message)
            });
            let runtime = RustBox::new(file_config.source)
                .unwrap_or_else(|err| panic!("check config `{}`: {err:?}", config.display()));
            let snapshot = runtime.snapshot();
            println!(
                "RustBox config OK: services={} outbounds={}",
                snapshot.inbound_count, snapshot.outbound_count
            );
            return;
        }
        CliCommand::Run { config } => {
            // 文件配置先进入 config-file，再进入统一 SourceConfig -> CompiledConfig 流水线。
            let file_config = load_toml_file(&config).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", config.display(), err.message)
            });
            let observability = observability_from_file(&file_config)
                .unwrap_or_else(|err| panic!("configure observability: {err}"));
            let mut options = RustBoxOptions::default().with_observability(observability.sink);
            if let Some(config) = control_api_config {
                options = options.with_control_grpc(config, observability.store);
            }
            (
                RustBox::with_options(file_config.source, options).expect("compose config file"),
                "configured proxy graph started",
            )
        }
    };
    runtime.start().await.expect("start configured proxy graph");

    if let Some(listen) = runtime.control_grpc_addr() {
        tracing::info!(%listen, "RustBox control gRPC listening");
    }

    tracing::info!(message = listen, "RustBox started");
    let control_enabled = runtime.control_grpc_addr().is_some();
    let stop_reason = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.expect("wait for ctrl-c");
            "Ctrl-C"
        }
        command = runtime.next_control_command(), if control_enabled => {
            match command {
                Some(EngineCommand::Stop) => "control API stop command",
                Some(_) => "control API command",
                None => "control API command channel closed",
            }
        }
    };

    tracing::info!(reason = stop_reason, "RustBox stopping");
    runtime.stop().await.expect("stop configured proxy graph");
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("RUSTBOX_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[derive(Debug, Parser)]
#[command(
    name = "rustbox-app",
    version,
    about = "RustBox proxy runtime",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(flatten)]
    control: ControlArgs,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Args)]
struct ControlArgs {
    #[arg(long, value_name = "ADDR", global = true)]
    control_grpc: Option<SocketAddr>,

    #[arg(long, value_name = "TOKEN", global = true, requires = "control_grpc")]
    control_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum CliCommand {
    /// Start from a TOML configuration file.
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Validate and compose a TOML configuration without starting services.
    CheckConfig {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Print detected platform capability support.
    PlatformCapabilities,
}

struct RuntimeObservability {
    sink: Arc<CompositeObservabilitySink>,
    store: Arc<ObservabilityStore>,
}

fn print_platform_capabilities() {
    let capabilities = rustbox_platform::current_capabilities();
    println!("{} platform capabilities:", capabilities.platform);
    println!("  tcp_udp: {:?}", capabilities.tcp_udp);
    println!("  packet_device: {:?}", capabilities.packet_device);
    println!("  route_control: {:?}", capabilities.route_control);
    println!("  transparent_proxy: {:?}", capabilities.transparent_proxy);
    println!("  process_lookup: {:?}", capabilities.process_lookup);
}

fn control_api_config_from_cli(args: &ControlArgs) -> Result<Option<ControlApiConfig>, String> {
    let Some(listen) = args.control_grpc else {
        return Ok(None);
    };
    let auth = args
        .control_token
        .clone()
        .or_else(|| std::env::var("RUSTBOX_CONTROL_TOKEN").ok())
        .map(AuthPolicy::bearer_token)
        .unwrap_or_else(AuthPolicy::disabled);
    Ok(Some(ControlApiConfig {
        listen,
        auth,
        ..ControlApiConfig::default()
    }))
}

fn observability_from_file(
    config: &rustbox_config_file::FileConfig,
) -> Result<RuntimeObservability, String> {
    let Some(config) = config.observability.as_ref() else {
        return observability_with_outputs(LevelFilter::from_env(), &ObservabilityOutput::Console);
    };
    observability_with_outputs(
        config.level.unwrap_or_else(LevelFilter::from_env),
        &config.output,
    )
}

fn observability_with_outputs(
    level: LevelFilter,
    output: &ObservabilityOutput,
) -> Result<RuntimeObservability, String> {
    let store = Arc::new(ObservabilityStore::default());
    let mut sink = CompositeObservabilitySink::new().with_sink(store.clone());

    if matches!(
        output,
        ObservabilityOutput::Console | ObservabilityOutput::ConsoleAndFile(_)
    ) {
        sink = sink.with_sink(Arc::new(ConsoleObservabilitySink::stderr(level)));
    }

    if let ObservabilityOutput::File(path) | ObservabilityOutput::ConsoleAndFile(path) = output {
        let file_sink = FileObservabilitySink::append(path, level).map_err(|err| {
            format!(
                "failed to open observability file `{}`: {err}",
                path.display()
            )
        })?;
        sink = sink.with_sink(Arc::new(file_sink));
    }

    Ok(RuntimeObservability {
        sink: Arc::new(sink),
        store,
    })
}
