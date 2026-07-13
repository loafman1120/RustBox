fn main() {
    println!("cargo:rerun-if-changed=include/rustbox.h");
    println!("cargo:rerun-if-changed=tests/c/header_smoke.c");
    println!("cargo:rerun-if-changed=tests/c/lifecycle_smoke.c");
    cc::Build::new()
        .file("tests/c/header_smoke.c")
        .file("tests/c/lifecycle_smoke.c")
        .include("include")
        .warnings(true)
        .compile("rustbox_ffi_header_smoke");
}
