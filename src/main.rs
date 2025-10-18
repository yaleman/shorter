use clap::*;
use tracing::{info, warn};

#[allow(dead_code)]
fn default_listener() -> &'static str {
    "127.0.0.1:9000"
}

#[derive(Parser)]
struct CliOpts {
    #[clap(env = "SHORTER_LISTENER_ADDR", default_value = default_listener())]
    pub listener_addr: String,

    /// Frontend URL (e.g., https://short.example.com) - used for OIDC redirect URI
    #[clap(env = "SHORTER_FRONTEND_URL")]
    pub frontend_url: String,

    /// OIDC discovery URL (e.g., https://accounts.google.com/.well-known/openid-configuration)
    #[clap(env = "SHORTER_OIDC_DISCOVERY_URL")]
    pub oidc_discovery_url: Option<String>,

    /// OIDC client ID
    #[clap(env = "SHORTER_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    /// Path to TLS certificate file (required)
    #[clap(env = "SHORTER_TLS_CERT")]
    pub tls_cert: String,

    /// Path to TLS private key file (required)
    #[clap(env = "SHORTER_TLS_KEY")]
    pub tls_key: String,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let cli = CliOpts::parse();

    // Build OIDC config if parameters are provided
    let oidc_config = match (&cli.oidc_discovery_url, &cli.oidc_client_id) {
        (Some(discovery_url), Some(client_id)) => {
            // Build redirect URI from frontend URL
            let redirect_uri = format!("{}/auth/callback", &cli.frontend_url);

            info!("OIDC authentication enabled");
            info!("  Discovery URL: {}", discovery_url);
            info!("  Client ID: {}", client_id);
            info!("  Redirect URI: {}", redirect_uri);
            Some(shorter::OidcConfig {
                issuer_url: discovery_url.clone(),
                client_id: client_id.clone(),
                redirect_uri,
            })
        }
        _ => {
            warn!("OIDC authentication not configured");
            warn!("  Set SHORTER_OIDC_DISCOVERY_URL and SHORTER_OIDC_CLIENT_ID to enable");
            warn!("  Admin routes will require authentication when OIDC is configured");
            None
        }
    };

    info!("Starting server on https://{}", &cli.listener_addr);
    info!("  Frontend URL: {}", &cli.frontend_url);
    info!("  TLS Certificate: {}", &cli.tls_cert);
    info!("  TLS Key: {}", &cli.tls_key);
    shorter::start_server(&cli.listener_addr, oidc_config, &cli.tls_cert, &cli.tls_key).await;
}
