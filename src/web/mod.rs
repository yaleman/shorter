pub(crate) mod admin;
pub(crate) mod auth;
pub(crate) mod csrf;
pub(crate) mod prelude;

use crate::constants::{Urls, BANNED_TAGS};
use crate::db::LinkWithOwner;
use crate::oauth::middleware::require_auth;
use crate::web::admin::cspheaders_layer;
use askama::Template;
use axum::middleware::from_fn;
use axum::response::{Html, IntoResponse};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    middleware,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, SessionManagerLayer};
// use tower_http::trace::TraceLayer;
use tracing::{error, instrument};
use url::Url;

use prelude::*;

pub(crate) fn build_app(shared_state: AppState) -> Router {
    // Create session layer (secure cookies for HTTPS)
    let session_store =
        tower_sessions_sqlx_store::SqliteStore::new(shared_state.session_pool.clone());
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true) // HTTPS only - secure cookies
        .with_expiry(Expiry::OnInactivity(time::Duration::hours(1)));

    // Admin routes with authentication middleware
    let admin_routes = Router::new()
        .route("/", get(admin::admin_list))
        .route("/create", get(admin::admin_create_form))
        .route("/create", post(admin::admin_create))
        .route("/edit/{id}", get(admin::admin_edit_form))
        .route("/edit/{id}", post(admin::admin_edit))
        .route("/delete/{id}", get(admin::admin_delete_confirm))
        .route("/delete/{id}", post(admin::admin_delete))
        .route_layer(from_fn(cspheaders_layer))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            require_auth,
        ));
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(crate::logging::HttpLogger {})
        .on_response(crate::logging::HttpLogger {});

    Router::new()
        // Public routes
        .route("/", get(root))
        .route(
            "/static/shorter.css",
            get(|| async {
                (
                    StatusCode::OK,
                    [("Content-Type", "text/css")],
                    #[cfg(debug_assertions)]
                    #[allow(clippy::expect_used)]
                    tokio::fs::read_to_string(format!(
                        "{}/src/static/shorter.css",
                        env!("CARGO_MANIFEST_DIR")
                    ))
                    .await
                    .expect("failed to read css file!"),
                    #[cfg(not(debug_assertions))]
                    include_str!("../static/shorter.css"),
                )
            }),
        )
        .route("/healthcheck", get(|| async { StatusCode::OK }))
        .route("/static/favicon.ico", get(favicon))
        .route("/link", post(create_link_api))
        .route("/{link}/preview", get(link_preview))
        .route("/{link}", get(link))
        // Auth routes
        .route(Urls::Login.as_ref(), get(auth::auth_login))
        .route(Urls::AuthCallback.as_ref(), get(auth::auth_callback))
        .route(Urls::AuthLogout.as_ref(), get(auth::auth_logout))
        // Admin routes (protected)
        .nest("/admin/", admin_routes)
        .fallback(|| async { NotFoundTemplate {}.into_response() })
        .layer(session_layer)
        .layer(trace_layer)
        .with_state(shared_state)
}

// Link preview template
#[derive(Template)]
#[template(path = "link_preview.html")]
struct LinkPreviewTemplate {
    name: String,
    tag: String,
    target: String,
}

// Query params for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
    state: String,
}

// basic handler that redirects to admin
#[instrument(level = "info")]
async fn root() -> Redirect {
    Redirect::to("/admin/")
}

#[instrument(level = "info")]
// favicon handler - returns 204 No Content
async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[instrument(level = "info", skip(state))]
async fn link(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if BANNED_TAGS.contains(&tag.as_ref()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid tag".to_string()).into_response());
    }

    let link = state.db.get_link(&tag).await.map_err(|err| {
        error!("Error getting link '{}'  {:?}", &tag, err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error getting link".to_string(),
        )
            .into_response()
    })?;

    match link {
        None => Err(NotFoundTemplate {}.into_response()),
        Some(link) => Ok((
            [(header::REFERRER_POLICY, "no-referrer")],
            Redirect::to(link.target.to_string().as_str()),
        )),
    }
}

#[derive(Template)]
#[template(path = "404.html")]
struct NotFoundTemplate {}

impl axum::response::IntoResponse for NotFoundTemplate {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::NOT_FOUND,
            Html(
                self.render()
                    .unwrap_or_else(|_| "404 Not Found".to_string()),
            ),
        )
            .into_response()
    }
}

#[instrument(level = "info", skip(state))]
async fn link_preview(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Result<HtmlTemplate<LinkPreviewTemplate>, impl IntoResponse> {
    if BANNED_TAGS.contains(&tag.as_ref()) {
        return Err(NotFoundTemplate {}.into_response());
    }

    let link = state.db.get_link(&tag).await.map_err(|err| {
        error!("Error getting link '{}': {:?}", &tag, err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error getting link".to_string(),
        )
            .into_response()
    })?;

    match link {
        None => Err(NotFoundTemplate {}.into_response()),
        Some(link) => Ok(HtmlTemplate(LinkPreviewTemplate {
            name: link.name,
            tag: link.tag,
            target: link.target.to_string(),
        })),
    }
}

// API endpoint for creating links (requires owner_subject in JSON)
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateLinkApiRequest {
    pub owner_subject: String,
    pub name: String,
    pub target: Url,
    pub tag: Option<String>,
}

#[instrument(level = "info", skip(state))]
async fn create_link_api(
    State(state): State<AppState>,
    Json(request): Json<CreateLinkApiRequest>,
) -> Result<Json<LinkWithOwner>, (StatusCode, String)> {
    // Check for banned tags
    if let Some(ref tag) = request.tag {
        if BANNED_TAGS.contains(&tag.as_str()) {
            return Err((StatusCode::BAD_REQUEST, "Invalid tag".to_string()));
        }
    }

    // Create the link
    let link = state
        .db
        .create_link(
            &request.owner_subject,
            &request.name,
            &request.target,
            request.tag,
        )
        .await
        .map_err(|err| {
            error!("Failed to save link: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save link".to_string(),
            )
        })?;

    Ok(link.into())
}
