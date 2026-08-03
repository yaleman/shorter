use std::process::ExitCode;

use clap::Parser;
use shorter::{constants::Urls, logging::setup_logging, start_server, CliOpts, OidcConfig};
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    // initialize tracing
    if let Err(err) = setup_logging() {
        eprintln!("Failed to initialize logging: {:?}", err);
        return ExitCode::FAILURE;
    };

    let cli = CliOpts::parse();

    // Build OIDC config if parameters are provided
    let redirect_uri = format!("{}{}", cli.frontend_url, Urls::AuthCallback.as_ref());
    let oidc_config = Some(OidcConfig {
        issuer_url: cli.oidc_discovery_url.to_owned(),
        client_id: cli.oidc_client_id.clone(),
        redirect_uri,
    });

    info!(
        "Frontend URL: {} / Listening on {}",
        &cli.frontend_url, &cli.listener_addr
    );
    match start_server(cli, oidc_config).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
