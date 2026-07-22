use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
mod observability;

use observability::ObservabilityArgs;
use rustbox::{RustBox, RustBoxOptions};
use rustbox_clash_api::ClashApiConfig;
use rustbox_config_file::{load_config_file, load_config_source};
use rustbox_control::EngineCommand;
use rustbox_control_api::{AuthPolicy, ControlApiConfig};
use std::net::SocketAddr;
use std::path::PathBuf;

/// 应用入口只负责选择配置来源、建立组合根、启动和响应 Ctrl-C。
#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();
    let control_token = cli
        .control
        .control_token
        .clone()
        .or_else(|| std::env::var("RUSTBOX_CONTROL_TOKEN").ok());
    let control_api_config = cli.control.control_grpc.map(|listen| {
        let auth = control_token
            .clone()
            .map_or_else(AuthPolicy::disabled, AuthPolicy::bearer_token);
        ControlApiConfig {
            listen,
            auth,
            ..ControlApiConfig::default()
        }
    });
    let clash_api_config = cli.control.clash_api.map(|listen| ClashApiConfig {
        listen,
        secret: control_token.clone(),
        cors_allowed_origins: cli.control.clash_cors_origin.clone(),
    });
    if control_token.is_some() && control_api_config.is_none() && clash_api_config.is_none() {
        Cli::command()
            .error(
                ErrorKind::ArgumentConflict,
                "--control-token requires --control-grpc or --clash-api",
            )
            .exit();
    }
    let (mut runtime, listen) = match cli.command {
        CliCommand::PlatformCapabilities => {
            print_platform_capabilities();
            return;
        }
        CliCommand::CheckConfig { config } => {
            let source = load_config_source(&config).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", config.display(), err.message)
            });
            let runtime = RustBox::new(source)
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
            let file_config = load_config_file(&config).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", config.display(), err.message)
            });
            let observability = cli
                .observability
                .build(file_config.observability.as_ref())
                .unwrap_or_else(|err| Cli::command().error(ErrorKind::ValueValidation, err).exit());
            let mut options = RustBoxOptions::default().with_observability(observability.sink);
            if let Some(config) = control_api_config {
                options = options.with_control_grpc(config, observability.store.clone());
            }
            if let Some(config) = clash_api_config {
                options = options.with_clash_api(config, observability.store);
            }
            (
                RustBox::with_options(file_config.source, options).expect("compose config file"),
                "configured proxy graph started",
            )
        }
    };
    let mut network_monitor = rustbox_platform::network_change_monitor()
        .unwrap_or_else(|error| panic!("subscribe to network changes: {error}"));
    runtime.start().await.expect("start configured proxy graph");

    if let Some(listen) = runtime.control_grpc_addr() {
        tracing::info!(%listen, "RustBox control gRPC listening");
    }
    if let Some(listen) = runtime.clash_api_addr() {
        tracing::info!(%listen, "RustBox Clash API listening");
    }

    tracing::info!(message = listen, "RustBox started");
    let control_enabled =
        runtime.control_grpc_addr().is_some() || runtime.clash_api_addr().is_some();
    let stop_reason = loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.expect("wait for ctrl-c");
                break "Ctrl-C";
            }
            command = runtime.next_control_command(), if control_enabled => {
                match command {
                    Some(command) if command.command == EngineCommand::Stop => break "control API stop command",
                    Some(command) => {
                        if let Err(error) = runtime.apply_control_request(command).await {
                            tracing::error!(?error, "control command failed");
                        }
                    }
                    None => break "control API command channel closed",
                }
            }
            changed = next_network_change(&mut network_monitor) => {
                if changed {
                    tracing::info!("physical network changed; rebuilding RustBox routes and bindings");
                    if let Err(error) = runtime.reconcile_network_change().await {
                        tracing::error!(?error, "network change reconciliation failed");
                    }
                }
            }
        }
    };

    tracing::info!(reason = stop_reason, "RustBox stopping");
    runtime.stop().await.expect("stop configured proxy graph");
}

async fn next_network_change(monitor: &mut Option<rustbox_platform::NetworkChangeMonitor>) -> bool {
    match monitor {
        Some(monitor) => monitor.changed().await,
        None => std::future::pending().await,
    }
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

    #[command(flatten)]
    observability: ObservabilityArgs,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Args)]
struct ControlArgs {
    #[arg(long, value_name = "ADDR", global = true)]
    control_grpc: Option<SocketAddr>,

    #[arg(long, value_name = "ADDR", global = true)]
    clash_api: Option<SocketAddr>,

    #[arg(long, value_name = "TOKEN", global = true)]
    control_token: Option<String>,

    #[arg(long, value_name = "ORIGIN", global = true, requires = "clash_api")]
    clash_cors_origin: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum CliCommand {
    /// Start from a TOML, native JSON, or Clash YAML configuration file.
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Validate and compose a TOML, native JSON, or Clash YAML configuration.
    CheckConfig {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Print detected platform capability support.
    PlatformCapabilities,
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
