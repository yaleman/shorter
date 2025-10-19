#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

pub mod constants;
pub(crate) mod db;
pub mod entities;
pub mod error;
pub mod logging;
pub(crate) mod oauth;
pub(crate) mod prelude;
#[cfg(test)]
mod tests;
pub(crate) mod web;

use std::path::PathBuf;
use std::sync::Arc;

use crate::db::DB;
use crate::error::MyError;
use crate::oauth::OAuthClient;
use crate::web::build_app;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tracing::error;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DB>,
    pub oauth_client: Option<Arc<OAuthClient>>,
    pub session_pool: sqlx::SqlitePool,
}

impl AppState {
    /// Create new AppState with database and optional OAuth client
    pub async fn new(
        database_url: &str,
        oidc_config: Option<OidcConfig>,
    ) -> Result<Self, crate::error::MyError> {
        let db = DB::new(database_url).await?;

        // Create separate sqlx pool for session store
        let session_pool = sqlx::SqlitePool::connect(database_url).await.map_err(|e| {
            crate::error::MyError::DatabaseError(format!(
                "database_url={}, error={}",
                database_url, e
            ))
        })?;

        // Migrate session store tables
        let session_store = tower_sessions_sqlx_store::SqliteStore::new(session_pool.clone());
        session_store.migrate().await.map_err(|e| {
            crate::error::MyError::DatabaseError(format!("Failed to migrate session store: {}", e))
        })?;

        let oauth_client = if let Some(config) = oidc_config {
            Some(Arc::new(
                OAuthClient::new(
                    &config.issuer_url,
                    &config.client_id,
                    &config.redirect_uri,
                    Arc::new(db.clone()),
                )
                .await?,
            ))
        } else {
            None
        };

        Ok(Self {
            db: Arc::new(db),
            oauth_client,
            session_pool,
        })
    }

    #[cfg(test)]
    pub async fn new_test() -> Self {
        let db = DB::new_test().await;
        let session_pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create session pool");

        Self {
            db: Arc::new(db),
            oauth_client: None,
            session_pool,
        }
    }
}

/// OIDC configuration
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub redirect_uri: String,
}

pub async fn start_server(cli: CliOpts, oidc_config: Option<OidcConfig>) -> Result<(), MyError> {
    rustls::crypto::aws_lc_rs::default_provider().install_default()?;
    let db_path_str = cli.db_path.as_os_str().to_string_lossy();

    let shared_state = AppState::new(&format!("sqlite://{}?mode=rwc", db_path_str), oidc_config)
        .await
        .inspect_err(|e| error!("Failed to initialize application: {:?}", e))?;

    let app = build_app(shared_state);

    // Load TLS configuration
    let tls_config = RustlsConfig::from_pem_file(&cli.tls_cert, &cli.tls_key)
        .await
        .map_err(|e| {
            error!("Failed to load TLS certificates: {:?}", e);
            error!("  Certificate: {}", cli.tls_cert);
            error!("  Key: {}", cli.tls_key);
            MyError::from(e)
        })?;

    // Use axum-server with TLS
    axum_server::bind_rustls(cli.listener_addr.parse()?, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| {
            error!("Server error: {:?}", e);
            e.into()
        })
}

#[allow(dead_code)]
fn default_listener() -> &'static str {
    "127.0.0.1:9000"
}

#[derive(Parser)]
pub struct CliOpts {
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
    #[clap(env = "SHORTER_LISTENER_ADDR", default_value = "127.0.0.1:9000")]
    pub listener_addr: String,

    #[clap(env = "SHORTER_DB_PATH", default_value = "shorter.sqlite3")]
    pub db_path: PathBuf,
}
