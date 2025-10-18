use clap::*;
use shorter::logging::setup_logging;
use tracing::info;

#[allow(dead_code)]
fn default_listener() -> &'static str {
    "127.0.0.1:9000"
}

#[derive(Parser)]
struct CliOpts {
    /// Frontend URL (e.g., https://short.example.com) - used for OIDC redirect URI
    #[clap(env = "SHORTER_FRONTEND_URL")]
    pub frontend_url: String,

    /// OIDC discovery URL (e.g., https://accounts.google.com/.well-known/openid-configuration)
    #[clap(env = "SHORTER_OIDC_DISCOVERY_URL")]
    pub oidc_discovery_url: String,

    /// OIDC client ID
    #[clap(env = "SHORTER_OIDC_CLIENT_ID")]
    pub oidc_client_id: String,

    /// Path to TLS certificate file (required)
    #[clap(env = "SHORTER_TLS_CERT")]
    pub tls_cert: String,

    /// Path to TLS private key file (required)
    #[clap(env = "SHORTER_TLS_KEY")]
    pub tls_key: String,
    #[clap(env = "SHORTER_LISTENER_ADDR", default_value = default_listener())]
    pub listener_addr: String,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    setup_logging();

    let cli = CliOpts::parse();

    // Build OIDC config if parameters are provided
    let redirect_uri = format!(
        "{}{}",
        &cli.frontend_url,
        shorter::constants::Urls::AuthCallback.as_ref()
    );
    let oidc_config = Some(shorter::OidcConfig {
        issuer_url: cli.oidc_discovery_url,
        client_id: cli.oidc_client_id,
        redirect_uri,
    });

    // info!("Starting server on https://{}", &cli.listener_addr);
    info!(
        "  Frontend URL: {} / {}",
        &cli.frontend_url, &cli.frontend_url
    );
    shorter::start_server(&cli.listener_addr, oidc_config, &cli.tls_cert, &cli.tls_key).await;
}
