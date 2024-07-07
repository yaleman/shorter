use clap::*;
use tracing::info;

#[allow(dead_code)]
fn default_listener() -> &'static str {
    "127.0.0.1:6969"
}

#[derive(Parser)]
struct CliOpts {
    #[clap(env = "SHORTER_LISTENER_ADDR", default_value = default_listener())]
    pub listener_addr: String,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let cli = CliOpts::parse();
    info!("Starting server on http://{}", &cli.listener_addr);
    shorter::start_server(&cli.listener_addr).await;
}
