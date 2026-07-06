use rustbox_compose::TokioComposition;
use rustbox_observability::ConsoleObservabilitySink;
use rustbox_types::Endpoint;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let command = std::env::args().nth(1);
    if command.as_deref() != Some("http-proxy") {
        println!("{}", rustbox_kernel::architecture_summary());
        println!("Run `rustbox-app http-proxy` to start the default local HTTP CONNECT proxy.");
        return;
    }

    let observability = Arc::new(ConsoleObservabilitySink::stderr_from_env());
    let mut runtime = TokioComposition::default_http_proxy_with_observability(
        Endpoint::localhost_v4(18080),
        observability,
    )
    .expect("compose default HTTP proxy");
    runtime
        .start("rustbox-app")
        .await
        .expect("start default HTTP proxy");

    println!("RustBox HTTP CONNECT proxy listening on 127.0.0.1:18080");
    tokio::signal::ctrl_c().await.expect("wait for ctrl-c");
    runtime.stop().await.expect("stop default HTTP proxy");
}
