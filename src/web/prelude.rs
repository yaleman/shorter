use askama::Template;
pub(crate) use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
pub(crate) use axum::{extract::State, response::Redirect};
pub(crate) use http::StatusCode;
pub(crate) use tower_sessions::Session;
pub(crate) use tracing::*;

pub(crate) use crate::AppState;

// Askama template wrapper for HTML responses
pub(crate) struct HtmlTemplate<T>(pub(crate) T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {}", err),
            )
                .into_response(),
        }
    }
}
