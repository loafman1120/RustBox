use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
use rustbox::{RustBox, RustBoxOptions};
use rustbox_config_file::load_toml_file;
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
        println!("RustBox control gRPC listening on {listen}");
    }

    println!("RustBox {listen}");
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

    eprintln!("RustBox stopping after {stop_reason}");
    runtime.stop().await.expect("stop configured proxy graph");
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

    #[arg(long, value_name = "TOKEN", global = true)]
    control_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(rename_all = "kebab-case")]
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
    let linux = rustbox_platform_linux::LinuxPlatform::new().capability_matrix();
    println!("Linux platform capabilities:");
    println!("  tcp_udp: {:?}", linux.tcp_udp);
    println!("  packet_device: {:?}", linux.packet_device);
    println!("  route_control: {:?}", linux.route_control);
    println!("  transparent_proxy: {:?}", linux.transparent_proxy);
    println!("  process_lookup: {:?}", linux.process_lookup);
}

fn control_api_config_from_cli(args: &ControlArgs) -> Result<Option<ControlApiConfig>, String> {
    if args.control_grpc.is_none() && args.control_token.is_some() {
        return Err("`--control-token` requires `--control-grpc <ADDR>`".to_string());
    }

    let Some(listen) = args.control_grpc else {
        return Ok(None);
    };
    let auth = args
        .control_token
        .clone()
        .or_else(|| std::env::var("RUSTBOX_CONTROL_TOKEN").ok())
        .map(AuthPolicy::bearer_token)
        .unwrap_or_else(AuthPolicy::disabled);
    let config = ControlApiConfig {
        listen,
        auth,
        ..ControlApiConfig::default()
    };
    config.validate().map_err(|err| err.message)?;
    Ok(Some(config))
}

fn observability_from_file(
    config: &rustbox_config_file::FileConfig,
) -> Result<RuntimeObservability, String> {
    let level = config
        .observability
        .as_ref()
        .and_then(|observability| observability.level.as_deref())
        .and_then(LevelFilter::parse)
        .unwrap_or_else(LevelFilter::from_env);
    let file = config
        .observability
        .as_ref()
        .and_then(|observability| observability.file.as_deref());
    observability_with_outputs(level, file)
}

fn observability_with_outputs(
    level: LevelFilter,
    file: Option<&str>,
) -> Result<RuntimeObservability, String> {
    let store = Arc::new(ObservabilityStore::default());
    let mut sink = CompositeObservabilitySink::new()
        .with_sink(Arc::new(ConsoleObservabilitySink::stderr(level)))
        .with_sink(store.clone());

    if let Some(path) = file {
        let file_sink = FileObservabilitySink::append(path, level)
            .map_err(|err| format!("failed to open observability file `{path}`: {err}"))?;
        sink = sink.with_sink(Arc::new(file_sink));
    }

    Ok(RuntimeObservability {
        sink: Arc::new(sink),
        store,
    })
}
