use clap::{Args, ValueEnum};
use rustbox_config_file::FileObservabilityConfig;
use rustbox_observability::{
    LevelFilter, ObservabilityConfig, ObservabilityOutput, RuntimeObservability,
};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct ObservabilityArgs {
    /// Override the configured runtime event level.
    #[arg(long = "observability-level", value_name = "LEVEL", global = true, value_parser = parse_level)]
    level: Option<LevelFilter>,

    /// Override the configured runtime event destination.
    #[arg(long = "observability-output", value_enum, global = true)]
    output: Option<OutputSelector>,

    /// Event log path used by file destinations.
    #[arg(
        long = "observability-file",
        value_name = "FILE",
        global = true,
        requires = "output"
    )]
    file: Option<PathBuf>,
}

impl ObservabilityArgs {
    pub fn resolve(
        &self,
        file: Option<&FileObservabilityConfig>,
    ) -> Result<ObservabilityConfig, String> {
        let configured = file
            .map(FileObservabilityConfig::runtime_config)
            .unwrap_or_else(|| ObservabilityConfig {
                level: LevelFilter::from_env(),
                output: ObservabilityOutput::Console,
            });
        let level = self.level.unwrap_or(configured.level);
        let configured_output = configured.output;
        let output = match self.output {
            None => configured_output,
            Some(OutputSelector::Console) => {
                if self.file.is_some() {
                    return Err("--observability-file cannot be used with console output".into());
                }
                ObservabilityOutput::Console
            }
            Some(selector @ (OutputSelector::File | OutputSelector::ConsoleAndFile)) => {
                let path = self
                    .file
                    .clone()
                    .or_else(|| output_path(&configured_output).cloned())
                    .ok_or_else(|| format!("--observability-output {} requires --observability-file or a file path in the TOML config", selector.cli_name()))?;
                match selector {
                    OutputSelector::File => ObservabilityOutput::File(path),
                    OutputSelector::ConsoleAndFile => ObservabilityOutput::ConsoleAndFile(path),
                    OutputSelector::Console => unreachable!(),
                }
            }
        };
        Ok(ObservabilityConfig { level, output })
    }

    pub fn build(
        &self,
        file: Option<&FileObservabilityConfig>,
    ) -> Result<RuntimeObservability, String> {
        self.resolve(file)?
            .build()
            .map_err(|error| format!("failed to configure observability output: {error}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputSelector {
    Console,
    File,
    ConsoleAndFile,
}

impl OutputSelector {
    fn cli_name(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::File => "file",
            Self::ConsoleAndFile => "console-and-file",
        }
    }
}

fn output_path(output: &ObservabilityOutput) -> Option<&PathBuf> {
    match output {
        ObservabilityOutput::Console => None,
        ObservabilityOutput::File(path) | ObservabilityOutput::ConsoleAndFile(path) => Some(path),
    }
}

fn parse_level(value: &str) -> Result<LevelFilter, String> {
    LevelFilter::parse(value)
        .ok_or_else(|| "expected one of: trace, debug, info, warn, error, off".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(
        level: Option<LevelFilter>,
        output: Option<OutputSelector>,
        file: Option<&str>,
    ) -> ObservabilityArgs {
        ObservabilityArgs {
            level,
            output,
            file: file.map(PathBuf::from),
        }
    }

    #[test]
    fn cli_overrides_file_config() {
        let file = FileObservabilityConfig {
            level: Some(LevelFilter::Info),
            output: ObservabilityOutput::File("from-file.log".into()),
            platform: None,
            remote_endpoint: None,
        };
        let resolved = args(
            Some(LevelFilter::Debug),
            Some(OutputSelector::ConsoleAndFile),
            Some("from-cli.log"),
        )
        .resolve(Some(&file))
        .expect("resolve config");

        assert_eq!(resolved.level, LevelFilter::Debug);
        assert_eq!(
            resolved.output,
            ObservabilityOutput::ConsoleAndFile("from-cli.log".into())
        );
    }

    #[test]
    fn file_selector_requires_a_path() {
        let error = args(None, Some(OutputSelector::File), None)
            .resolve(None)
            .expect_err("missing file path");
        assert!(error.contains("requires --observability-file"));
    }

    #[test]
    fn console_rejects_a_file_path() {
        let error = args(None, Some(OutputSelector::Console), Some("unused.log"))
            .resolve(None)
            .expect_err("unused file path");
        assert!(error.contains("cannot be used with console"));
    }
}
