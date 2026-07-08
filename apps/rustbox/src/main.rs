use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
use rustbox_compose::TokioComposition;
use rustbox_config_file::load_toml_file;
use rustbox_control::{ControlState, EngineCommand, EngineSnapshot, EngineState};
use rustbox_control_api::{AuthPolicy, ControlApiConfig, ControlApiState};
use rustbox_observability::{
    CompositeObservabilitySink, ConsoleObservabilitySink, FileObservabilitySink, LevelFilter,
    ObservabilityStore,
};
use rustbox_types::Endpoint;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// 应用入口只负责选择配置来源、建立组合根、启动和响应 Ctrl-C。
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mode = runtime_mode_from_cli(&cli).unwrap_or_else(|err| err.exit());
    let control_api_config = control_api_config_from_cli(&cli.control)
        .unwrap_or_else(|err| Cli::command().error(ErrorKind::ValueValidation, err).exit());
    let (mut runtime, listen, observability_store) = match mode {
        RuntimeMode::ArchitectureSummary => {
            print_architecture_summary();
            return;
        }
        RuntimeMode::PlatformCapabilities => {
            print_platform_capabilities();
            return;
        }
        RuntimeMode::CheckConfig(path) => {
            let file_config = load_toml_file(&path).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", path.display(), err.message)
            });
            let runtime = TokioComposition::new()
                .compose_source(file_config.source)
                .unwrap_or_else(|err| panic!("check config `{}`: {err:?}", path.display()));
            println!(
                "RustBox config OK: services={} outbounds={}",
                runtime.service_count(),
                runtime.engine().outbound_count()
            );
            return;
        }
        RuntimeMode::HttpProxy => {
            let observability = observability_from_cli();
            (
                TokioComposition::default_http_proxy_with_observability(
                    Endpoint::localhost_v4(18080),
                    observability.sink,
                )
                .expect("compose default HTTP proxy"),
                "HTTP CONNECT proxy listening on 127.0.0.1:18080",
                observability.store,
            )
        }
        RuntimeMode::Socks5Proxy => {
            let observability = observability_from_cli();
            (
                TokioComposition::default_socks5_proxy_with_observability(
                    Endpoint::localhost_v4(1080),
                    observability.sink,
                )
                .expect("compose default SOCKS5 proxy"),
                "SOCKS5 proxy listening on 127.0.0.1:1080",
                observability.store,
            )
        }
        RuntimeMode::ConfigFile(path) => {
            // 文件配置先进入 config-file，再进入统一 SourceConfig -> CompiledConfig 流水线。
            let file_config = load_toml_file(&path).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", path.display(), err.message)
            });
            let observability = observability_from_file(&file_config)
                .unwrap_or_else(|err| panic!("configure observability: {err}"));
            (
                TokioComposition::with_observability(observability.sink)
                    .compose_source(file_config.source)
                    .expect("compose config file"),
                "configured proxy graph started",
                observability.store,
            )
        }
    };
    runtime
        .start("rustbox-app")
        .await
        .expect("start default proxy");

    let inbound_count = runtime.service_count();
    let outbound_count = runtime.engine().outbound_count();
    let control_state = Arc::new(Mutex::new(ControlState::new(EngineSnapshot {
        state: EngineState::Running,
        generation: 0,
        inbound_count,
        outbound_count,
    })));

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let control_api_task = if let Some(config) = control_api_config {
        let listen = config.listen;
        let state = ControlApiState::new(observability_store, Arc::clone(&control_state))
            .with_command_sender(command_tx);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            rustbox_control_api::serve_grpc(config, state, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        println!("RustBox control gRPC listening on {listen}");
        Some((shutdown_tx, task))
    } else {
        None
    };

    println!("RustBox {listen}");
    let stop_reason = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.expect("wait for ctrl-c");
            "Ctrl-C"
        }
        command = command_rx.recv(), if control_api_task.is_some() => {
            match command {
                Some(EngineCommand::Stop) => "control API stop command",
                Some(_) => "control API command",
                None => "control API command channel closed",
            }
        }
    };

    eprintln!("RustBox stopping after {stop_reason}");
    runtime.stop().await.expect("stop default proxy");

    if let Ok(mut state) = control_state.lock() {
        let mut snapshot = state.snapshot().clone();
        snapshot.state = EngineState::Stopped;
        snapshot.inbound_count = inbound_count;
        snapshot.outbound_count = outbound_count;
        state.replace_snapshot(snapshot);
    }

    if let Some((shutdown_tx, task)) = control_api_task {
        let _ = shutdown_tx.send(());
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("RustBox control gRPC stopped with error: {err}"),
            Err(err) => eprintln!("RustBox control gRPC task failed: {err}"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "rustbox-app", version, about = "RustBox proxy runtime")]
struct Cli {
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    #[command(flatten)]
    control: ControlArgs,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Args)]
struct ControlArgs {
    #[arg(long, value_name = "ADDR", global = true)]
    control_grpc: Option<SocketAddr>,

    #[arg(long, value_name = "TOKEN", global = true)]
    control_token: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
#[command(rename_all = "kebab-case")]
enum CliCommand {
    /// Start from a TOML configuration file.
    Run,
    /// Validate and compose a TOML configuration without starting services.
    CheckConfig,
    /// Print detected platform capability support.
    PlatformCapabilities,
    /// Start the default local HTTP CONNECT proxy.
    HttpProxy,
    /// Start the default local SOCKS5 proxy.
    Socks5Proxy,
}

impl CliCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::CheckConfig => "check-config",
            Self::PlatformCapabilities => "platform-capabilities",
            Self::HttpProxy => "http-proxy",
            Self::Socks5Proxy => "socks5-proxy",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum RuntimeMode {
    ArchitectureSummary,
    CheckConfig(PathBuf),
    ConfigFile(PathBuf),
    HttpProxy,
    PlatformCapabilities,
    Socks5Proxy,
}

struct RuntimeObservability {
    sink: Arc<CompositeObservabilitySink>,
    store: Arc<ObservabilityStore>,
}

fn runtime_mode_from_cli(cli: &Cli) -> Result<RuntimeMode, clap::Error> {
    match cli.command {
        Some(CliCommand::HttpProxy) => {
            reject_config_for_command(cli, CliCommand::HttpProxy)?;
            Ok(RuntimeMode::HttpProxy)
        }
        Some(CliCommand::Socks5Proxy) => {
            reject_config_for_command(cli, CliCommand::Socks5Proxy)?;
            Ok(RuntimeMode::Socks5Proxy)
        }
        Some(CliCommand::Run) => config_file_mode(cli),
        Some(CliCommand::CheckConfig) => cli
            .config
            .clone()
            .map(RuntimeMode::CheckConfig)
            .ok_or_else(|| {
                Cli::command().error(
                    ErrorKind::MissingRequiredArgument,
                    "`check-config` requires --config <FILE>",
                )
            }),
        Some(CliCommand::PlatformCapabilities) => {
            reject_config_for_command(cli, CliCommand::PlatformCapabilities)?;
            Ok(RuntimeMode::PlatformCapabilities)
        }
        None => Ok(cli
            .config
            .clone()
            .map(RuntimeMode::ConfigFile)
            .unwrap_or(RuntimeMode::ArchitectureSummary)),
    }
}

fn config_file_mode(cli: &Cli) -> Result<RuntimeMode, clap::Error> {
    cli.config
        .clone()
        .map(RuntimeMode::ConfigFile)
        .ok_or_else(|| {
            Cli::command().error(
                ErrorKind::MissingRequiredArgument,
                "`run` requires --config <FILE>",
            )
        })
}

fn reject_config_for_command(cli: &Cli, command: CliCommand) -> Result<(), clap::Error> {
    if cli.config.is_some() {
        return Err(Cli::command().error(
            ErrorKind::ArgumentConflict,
            format!("`{}` cannot be used with --config", command.as_str()),
        ));
    }

    Ok(())
}

fn print_architecture_summary() {
    println!("{}", rustbox_kernel::architecture_summary());
    println!("Run `rustbox-app http-proxy` to start the default local HTTP CONNECT proxy.");
    println!("Run `rustbox-app socks5-proxy` to start the default local SOCKS5 proxy.");
    println!("Run `rustbox-app --config rustbox.toml` to start from a config file.");
    println!("Run `rustbox-app check-config --config rustbox.toml` to validate a config file.");
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

fn observability_from_cli() -> RuntimeObservability {
    observability_with_outputs(LevelFilter::from_env(), None).expect("configure CLI observability")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_http_proxy_command() {
        let cli = Cli::try_parse_from(["rustbox-app", "http-proxy"]).expect("parse cli");

        assert_eq!(cli.command, Some(CliCommand::HttpProxy));
        assert!(cli.config.is_none());
    }

    #[test]
    fn parses_config_file_without_subcommand() {
        let cli = Cli::try_parse_from(["rustbox-app", "--config", "examples/rustbox.toml"])
            .expect("parse cli");

        assert_eq!(cli.command, None);
        assert_eq!(cli.config, Some(PathBuf::from("examples/rustbox.toml")));
    }

    #[test]
    fn parses_config_file_after_run_subcommand() {
        let cli = Cli::try_parse_from(["rustbox-app", "run", "--config", "examples/rustbox.toml"])
            .expect("parse cli");

        assert_eq!(cli.command, Some(CliCommand::Run));
        assert_eq!(cli.config, Some(PathBuf::from("examples/rustbox.toml")));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        let error = Cli::try_parse_from(["rustbox-app", "unknown"]).expect_err("reject cli");

        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn parses_control_grpc_flags() {
        let cli = Cli::try_parse_from([
            "rustbox-app",
            "--control-grpc",
            "127.0.0.1:19090",
            "--control-token",
            "secret",
            "http-proxy",
        ])
        .expect("parse cli");

        assert_eq!(
            cli.control.control_grpc,
            Some("127.0.0.1:19090".parse().expect("socket addr"))
        );
        assert_eq!(cli.control.control_token, Some("secret".to_string()));
    }

    #[test]
    fn rejects_control_token_without_grpc_listener() {
        let cli = Cli::try_parse_from(["rustbox-app", "--control-token", "secret", "http-proxy"])
            .expect("parse cli");

        let error = control_api_config_from_cli(&cli.control).expect_err("reject unused token");

        assert!(error.contains("--control-grpc"));
    }

    #[test]
    fn maps_cli_to_runtime_modes() {
        let summary = Cli::try_parse_from(["rustbox-app"]).expect("parse cli");
        assert_eq!(
            runtime_mode_from_cli(&summary).expect("runtime mode"),
            RuntimeMode::ArchitectureSummary
        );

        let config = Cli::try_parse_from(["rustbox-app", "--config", "examples/rustbox.toml"])
            .expect("parse cli");
        assert_eq!(
            runtime_mode_from_cli(&config).expect("runtime mode"),
            RuntimeMode::ConfigFile(PathBuf::from("examples/rustbox.toml"))
        );

        let http = Cli::try_parse_from(["rustbox-app", "http-proxy"]).expect("parse cli");
        assert_eq!(
            runtime_mode_from_cli(&http).expect("runtime mode"),
            RuntimeMode::HttpProxy
        );

        let check = Cli::try_parse_from([
            "rustbox-app",
            "check-config",
            "--config",
            "examples/rustbox.toml",
        ])
        .expect("parse cli");
        assert_eq!(
            runtime_mode_from_cli(&check).expect("runtime mode"),
            RuntimeMode::CheckConfig(PathBuf::from("examples/rustbox.toml"))
        );

        let capabilities =
            Cli::try_parse_from(["rustbox-app", "platform-capabilities"]).expect("parse cli");
        assert_eq!(
            runtime_mode_from_cli(&capabilities).expect("runtime mode"),
            RuntimeMode::PlatformCapabilities
        );
    }

    #[test]
    fn rejects_config_with_builtin_proxy_command() {
        let cli = Cli::try_parse_from([
            "rustbox-app",
            "http-proxy",
            "--config",
            "examples/rustbox.toml",
        ])
        .expect("parse cli");

        let error = runtime_mode_from_cli(&cli).expect_err("reject conflicting mode");

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn rejects_run_without_config() {
        let cli = Cli::try_parse_from(["rustbox-app", "run"]).expect("parse cli");

        let error = runtime_mode_from_cli(&cli).expect_err("reject missing config");

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }
}
