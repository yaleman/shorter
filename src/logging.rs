//! Logging setup for the application
//!

use tower_http::trace::{MakeSpan, OnResponse};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::error::MyError;

// Initialize tracing subscriber
pub fn setup_logging() -> Result<(), MyError> {
    // Initialize tracing subscriber
    let log_level = std::env::var("RUST_LOG")
        .unwrap_or("info".to_string())
        .to_lowercase();
    let log_level_sqlx = std::env::var("RUST_LOG_SQLX").unwrap_or("info".to_string());
    let log_level_tower_http = std::env::var("RUST_LOG_TOWER_HTTP").unwrap_or(log_level.clone());

    let format_layer = tracing_subscriber::fmt::layer()
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_target(log_level == "debug" || log_level == "trace")
        .with_level(true)
        .with_ansi(false)
        .compact();
    let filter_layer = tracing_subscriber::EnvFilter::builder().parse(format!(
        "shorter={log_level},tower_http={log_level_tower_http},h2=warn,sqlx={log_level_sqlx}",
    ))?;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(format_layer)
        .init();
    Ok(())
}

#[cfg(test)]
pub(crate) fn setup_test_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(
             tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_test_writer()
        .with_level(true)
        )
        .with(tracing_subscriber::EnvFilter::new("debug,russh::client=info,russh::sshbuffer=info,russh::keys::agent::client=info,russh::keys::agent=info,h2::codec=warn"))
        .try_init();
}

#[derive(Clone)]
pub(crate) struct HttpLogger {}

impl<B> MakeSpan<B> for HttpLogger {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let span = tracing::info_span!(
            "",
            http.method = %method,
            http.uri = %uri.path(),
        );

        span
    }
}

impl<B> OnResponse<B> for HttpLogger {
    fn on_response(
        self,
        response: &http::Response<B>,
        latency: std::time::Duration,
        span: &tracing::Span,
    ) {
        let status = response.status();
        span.record("http.status_code", status.as_u16());
        span.record("http.response_latency_ms", latency.as_millis());

        tracing::info!(
            http.status_code = status.as_u16(),
            http.response_latency_ms = latency.as_millis(),
        );
    }
}
