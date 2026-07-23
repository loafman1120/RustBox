use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let destination = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: export_openapi <destination>");
    let document = rustbox_clash_api::openapi()
        .to_pretty_json()
        .expect("serialize RustBox OpenAPI document");

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).expect("create OpenAPI destination directory");
    }
    fs::write(&destination, document).expect("write generated OpenAPI document");
    println!("wrote {}", destination.display());
}
