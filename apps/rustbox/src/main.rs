use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use rustbox_compose::TokioComposition;
use rustbox_config_file::load_toml_file;
use rustbox_observability::{ConsoleObservabilitySink, LevelFilter};
use rustbox_types::Endpoint;
use std::path::PathBuf;
use std::sync::Arc;

/// 应用入口只负责选择配置来源、建立组合根、启动和响应 Ctrl-C。
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let observability = Arc::new(observability_from_cli(&cli));
    let (mut runtime, listen) = match (cli.command, cli.config) {
        (None, None) => {
            print_architecture_summary();
            return;
        }
        (Some(CliCommand::HttpProxy), None) => (
            TokioComposition::default_http_proxy_with_observability(
                Endpoint::localhost_v4(18080),
                observability,
            )
            .expect("compose default HTTP proxy"),
            "HTTP CONNECT proxy listening on 127.0.0.1:18080",
        ),
        (Some(CliCommand::Socks5Proxy), None) => (
            TokioComposition::default_socks5_proxy_with_observability(
                Endpoint::localhost_v4(1080),
                observability,
            )
            .expect("compose default SOCKS5 proxy"),
            "SOCKS5 proxy listening on 127.0.0.1:1080",
        ),
        (None | Some(CliCommand::Run), Some(path)) => {
            // 文件配置先进入 config-file，再进入统一 SourceConfig -> CompiledConfig 流水线。
            let file_config = load_toml_file(&path).unwrap_or_else(|err| {
                panic!("load config file `{}`: {}", path.display(), err.message)
            });
            let configured_observability = Arc::new(observability_from_file(&file_config));
            (
                TokioComposition::with_observability(configured_observability)
                    .compose_source(file_config.source)
                    .expect("compose config file"),
                "configured proxy graph started",
            )
        }
        (Some(CliCommand::Run), None) => Cli::command()
            .error(
                ErrorKind::MissingRequiredArgument,
                "`run` requires --config <FILE>",
            )
            .exit(),
        (Some(command), Some(_)) => Cli::command()
            .error(
                ErrorKind::ArgumentConflict,
                format!("`{}` cannot be used with --config", command.as_str()),
            )
            .exit(),
    };
    runtime
        .start("rustbox-app")
        .await
        .expect("start default proxy");

    println!("RustBox {listen}");
    tokio::signal::ctrl_c().await.expect("wait for ctrl-c");
    runtime.stop().await.expect("stop default proxy");
}

#[derive(Debug, Parser)]
#[command(name = "rustbox-app", version, about = "RustBox proxy runtime")]
struct Cli {
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
#[command(rename_all = "kebab-case")]
enum CliCommand {
    /// Start from a TOML configuration file.
    Run,
    /// Start the default local HTTP CONNECT proxy.
    HttpProxy,
    /// Start the default local SOCKS5 proxy.
    Socks5Proxy,
}

impl CliCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::HttpProxy => "http-proxy",
            Self::Socks5Proxy => "socks5-proxy",
        }
    }
}

fn print_architecture_summary() {
    println!("{}", rustbox_kernel::architecture_summary());
    println!("Run `rustbox-app http-proxy` to start the default local HTTP CONNECT proxy.");
    println!("Run `rustbox-app socks5-proxy` to start the default local SOCKS5 proxy.");
    println!("Run `rustbox-app --config rustbox.toml` to start from a config file.");
}

fn observability_from_cli(cli: &Cli) -> ConsoleObservabilitySink {
    if cli.config.is_some() {
        return ConsoleObservabilitySink::stderr(LevelFilter::from_env());
    }
    ConsoleObservabilitySink::stderr_from_env()
}

fn observability_from_file(config: &rustbox_config_file::FileConfig) -> ConsoleObservabilitySink {
    let level = config
        .observability
        .as_ref()
        .and_then(|observability| observability.level.as_deref())
        .and_then(LevelFilter::parse)
        .unwrap_or_else(LevelFilter::from_env);
    ConsoleObservabilitySink::stderr(level)
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
}
