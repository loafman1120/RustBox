use rustbox_config_file::{SUPPORTED_SCHEMA_VERSION, generate_native_config_schema};
use std::fs;
use std::path::PathBuf;

fn main() {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join(format!(
            "rustbox-config-v{SUPPORTED_SCHEMA_VERSION}.schema.json"
        ));
    let mut rendered =
        serde_json::to_string_pretty(&generate_native_config_schema()).expect("render schema");
    rendered.push('\n');

    if std::env::args().any(|arg| arg == "--check") {
        let checked_in = fs::read_to_string(&output)
            .unwrap_or_else(|error| panic!("read `{}`: {error}", output.display()));
        if checked_in != rendered {
            eprintln!(
                "native configuration schema is stale: regenerate `{}`",
                output.display()
            );
            std::process::exit(1);
        }
        println!("native configuration schema is current");
        return;
    }

    fs::create_dir_all(output.parent().expect("schema output directory"))
        .expect("create schema output directory");
    fs::write(&output, rendered)
        .unwrap_or_else(|error| panic!("write `{}`: {error}", output.display()));
    println!("generated {}", output.display());
}
