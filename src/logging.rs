//! Logging setup for the application
//!

use tower_http::trace::{MakeSpan, OnResponse};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Initialize tracing subscriber
pub fn setup_logging() {
    // Initialize tracing subscriber
    let log_level = std::env::var("RUST_LOG").unwrap_or("info".to_string());
    let log_level_sqlx = std::env::var("RUST_LOG_SQLX").unwrap_or("info".to_string());
    let log_level_tower_http = std::env::var("RUST_LOG_TOWER_HTTP").unwrap_or(log_level.clone());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "shorter={log_level},tower_http={log_level_tower_http},h2=warn,sqlx={log_level_sqlx}",
        )))
        .with(tracing_subscriber::fmt::layer())
        .init();
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
            "HTTP Request",
            http.method = %method,
            http.uri = %uri.path(),
        );

        span
    }
}

// impl<B> OnRequest<B> for HttpLogger {
//     fn on_request(&mut self, request: &http::Request<B>, span: &tracing::Span) {
//         // let method = request.method();
//         // let uri = request.uri();
//         // span.record("http.request.method", &method.as_str());
//         // span.record("http.uri", &uri.path());
//     }
// }

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
