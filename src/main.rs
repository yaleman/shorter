use clap::Parser;
use shorter::{logging::setup_logging, CliOpts};
use tracing::info;

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
        issuer_url: cli.oidc_discovery_url.to_owned(),
        client_id: cli.oidc_client_id.clone(),
        redirect_uri,
    });

    // info!("Starting server on https://{}", &cli.listener_addr);
    info!(
        "  Frontend URL: {} / {}",
        &cli.frontend_url, &cli.frontend_url
    );
    shorter::start_server(cli, oidc_config).await;
}
