pub mod auth;
pub mod db;
pub mod entities;
pub mod error;
pub mod prelude;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use crate::auth::{middleware::require_auth, AuthUser, OAuthClient};
use crate::db::{LinkWithOwner, DB};
use askama::Template;
use axum::{
    debug_handler,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_sessions::{Expiry, Session, SessionManagerLayer};
use url::Url;

const BANNED_TAGS: [&str; 3] = ["link", "admin", "preview"];

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DB>,
    pub oauth_client: Option<Arc<OAuthClient>>,
}

impl AppState {
    /// Create new AppState with database and optional OAuth client
    pub async fn new(
        database_url: &str,
        oidc_config: Option<OidcConfig>,
    ) -> Result<Self, crate::error::MyError> {
        let db = DB::new(database_url).await?;

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
        })
    }

    #[cfg(test)]
    pub async fn new_test() -> Self {
        let db = DB::new_test().await;

        Self {
            db: Arc::new(db),
            oauth_client: None,
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

pub(crate) fn build_app(shared_state: AppState) -> Router {
    // Create session layer (secure cookies for HTTPS)
    let session_store = tower_sessions_sqlx_store::SqliteStore::new(
        shared_state.db.conn.get_sqlite_connection_pool().clone(),
    );
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true) // HTTPS only - secure cookies
        .with_expiry(Expiry::OnInactivity(time::Duration::hours(24)));

    // Admin routes with authentication middleware
    let admin_routes = Router::new()
        .route("/", get(admin_list))
        .route("/create", get(admin_create_form))
        .route("/create", post(admin_create))
        .route("/edit/{id}", get(admin_edit_form))
        .route("/edit/{id}", post(admin_edit))
        .route("/delete/{id}", post(admin_delete))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            require_auth,
        ));

    Router::new()
        // Public routes
        .route("/", get(root))
        .route("/favicon.ico", get(favicon))
        .route("/link", post(create_link_api))
        .route("/{link}/preview", get(link_preview))
        .route("/{link}", get(link))
        // Auth routes
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/logout", get(auth_logout))
        // Admin routes (protected)
        .nest("/admin", admin_routes)
        .layer(session_layer)
        .with_state(shared_state)
}

pub async fn start_server(
    listener_addr: &str,
    oidc_config: Option<OidcConfig>,
    tls_cert_path: &str,
    tls_key_path: &str,
) {
    use axum_server::tls_rustls::RustlsConfig;

    let shared_state = match AppState::new("sqlite://shorter.sqlite3", oidc_config).await {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to initialize application: {:?}", e);
            return;
        }
    };

    let app = build_app(shared_state);

    // Load TLS configuration
    let tls_config = match RustlsConfig::from_pem_file(tls_cert_path, tls_key_path).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load TLS certificates: {:?}", e);
            eprintln!("  Certificate: {}", tls_cert_path);
            eprintln!("  Key: {}", tls_key_path);
            return;
        }
    };

    eprintln!("Starting HTTPS server on https://{}", listener_addr);

    // Use axum-server with TLS
    if let Err(e) = axum_server::bind_rustls(listener_addr.parse().unwrap(), tls_config)
        .serve(app.into_make_service())
        .await
    {
        eprintln!("Server error: {:?}", e);
    }
}

// Askama template wrapper for HTML responses
struct HtmlTemplate<T>(T);

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

// Admin templates
#[derive(Template)]
#[template(path = "admin_list.html")]
struct AdminListTemplate {
    links: Vec<LinkWithOwner>,
    user: AuthUser,
}

#[derive(Template)]
#[template(path = "admin_create.html")]
struct AdminCreateTemplate {
    error: Option<String>,
    user: AuthUser,
}

#[derive(Template)]
#[template(path = "admin_edit.html")]
struct AdminEditTemplate {
    link: LinkWithOwner,
    error: Option<String>,
    user: AuthUser,
}

// Form structs for admin operations
#[derive(Debug, Deserialize)]
struct LinkFormData {
    name: String,
    target: String,
    tag: String,
}

// Query params for OAuth callback
#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

// ========== Auth Handlers ==========

#[debug_handler]
async fn auth_login(State(state): State<AppState>) -> Result<Redirect, (StatusCode, String)> {
    let oauth_client = state.oauth_client.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth not configured".to_string(),
    ))?;

    let (auth_url, _state) = oauth_client.generate_auth_url().await.map_err(|e| {
        eprintln!("Failed to generate auth URL: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to start login".to_string(),
        )
    })?;

    Ok(Redirect::to(&auth_url))
}

#[debug_handler]
async fn auth_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
    session: Session,
) -> Result<Redirect, (StatusCode, String)> {
    let oauth_client = state.oauth_client.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth not configured".to_string(),
    ))?;

    // Exchange code for tokens
    let (email, subject) = oauth_client
        .exchange_code(&query.code, &query.state)
        .await
        .map_err(|e| {
            eprintln!("Failed to exchange code: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication failed".to_string(),
            )
        })?;

    // Get or create user in database
    let user = state
        .db
        .get_or_create_user(&subject, &email, None)
        .await
        .map_err(|e| {
            eprintln!("Failed to create user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create user".to_string(),
            )
        })?;

    // Store user subject in session
    session
        .insert("user_subject", user.subject)
        .await
        .map_err(|e| {
            eprintln!("Failed to store session: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save session".to_string(),
            )
        })?;

    Ok(Redirect::to("/admin/"))
}

#[debug_handler]
async fn auth_logout(session: Session) -> Result<Redirect, (StatusCode, String)> {
    session
        .remove::<String>("user_subject")
        .await
        .map_err(|e| {
            eprintln!("Failed to clear session: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to logout".to_string(),
            )
        })?;

    Ok(Redirect::to("/"))
}

// ========== Admin Handlers ==========

#[debug_handler]
async fn admin_list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<HtmlTemplate<AdminListTemplate>, (StatusCode, String)> {
    let links = state.db.list_links().await.map_err(|err| {
        eprintln!("Error listing links: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list links".to_string(),
        )
    })?;

    Ok(HtmlTemplate(AdminListTemplate { links, user }))
}

#[debug_handler]
async fn admin_create_form(
    Extension(user): Extension<AuthUser>,
) -> HtmlTemplate<AdminCreateTemplate> {
    HtmlTemplate(AdminCreateTemplate { error: None, user })
}

#[debug_handler]
async fn admin_create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Form(form_data): Form<LinkFormData>,
) -> Result<Response, (StatusCode, String)> {
    // Parse the target URL
    let target = Url::parse(&form_data.target)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid target URL".to_string()))?;

    // Check if tag is empty or contains only whitespace
    let tag = if form_data.tag.trim().is_empty() {
        None
    } else {
        Some(form_data.tag.trim().to_string())
    };

    // Check for banned tags
    if let Some(ref tag_val) = tag {
        if BANNED_TAGS.contains(&tag_val.as_str()) {
            return Ok(HtmlTemplate(AdminCreateTemplate {
                error: Some(format!("Tag '{}' is reserved and cannot be used", tag_val)),
                user,
            })
            .into_response());
        }
    }

    // Create the link (owned by current user)
    state
        .db
        .create_link(&user.subject, &form_data.name, &target, tag)
        .await
        .map_err(|err| {
            eprintln!("Failed to create link: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create link".to_string(),
            )
        })?;

    // Redirect to admin list
    Ok(Redirect::to("/admin/").into_response())
}

#[debug_handler]
async fn admin_edit_form(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<HtmlTemplate<AdminEditTemplate>, (StatusCode, String)> {
    let link = state.db.get_link_by_id(&id).await.map_err(|err| {
        eprintln!("Error getting link: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get link".to_string(),
        )
    })?;

    match link {
        Some(link) => Ok(HtmlTemplate(AdminEditTemplate {
            link,
            error: None,
            user,
        })),
        None => Err((StatusCode::NOT_FOUND, "Link not found".to_string())),
    }
}

#[debug_handler]
async fn admin_edit(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Form(form_data): Form<LinkFormData>,
) -> Result<Response, (StatusCode, String)> {
    // Parse the target URL
    let target = Url::parse(&form_data.target)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid target URL".to_string()))?;

    // Check for banned tags
    if BANNED_TAGS.contains(&form_data.tag.as_str()) {
        // Get the current link to show in error state
        let current_link = state
            .db
            .get_link_by_id(&id)
            .await
            .map_err(|err| {
                eprintln!("Error getting link: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get link".to_string(),
                )
            })?
            .ok_or((StatusCode::NOT_FOUND, "Link not found".to_string()))?;

        return Ok(HtmlTemplate(AdminEditTemplate {
            link: current_link,
            error: Some(format!(
                "Tag '{}' is reserved and cannot be used",
                form_data.tag
            )),
            user,
        })
        .into_response());
    }

    // Update the link
    state
        .db
        .update_link(&id, &form_data.name, &target, &form_data.tag)
        .await
        .map_err(|err| {
            eprintln!("Failed to update link: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update link".to_string(),
            )
        })?;

    // Redirect to admin list
    Ok(Redirect::to("/admin/").into_response())
}

#[debug_handler]
async fn admin_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Redirect, (StatusCode, String)> {
    state.db.delete_link(&id).await.map_err(|err| {
        eprintln!("Failed to delete link: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete link".to_string(),
        )
    })?;

    Ok(Redirect::to("/admin/"))
}

// basic handler that redirects to admin
async fn root() -> Redirect {
    Redirect::to("/admin/")
}

// favicon handler - returns 204 No Content
async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[debug_handler]
async fn link(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Result<Redirect, (StatusCode, String)> {
    if BANNED_TAGS.contains(&tag.as_ref()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid tag".to_string()));
    }

    let link = state.db.get_link(&tag).await.map_err(|err| {
        eprintln!("Error getting link '{}'  {:?}", &tag, err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error getting link".to_string(),
        )
    })?;

    match link {
        None => Err((StatusCode::NOT_FOUND, "404 Link Not Found".to_string())),
        Some(link) => Ok(Redirect::to(link.target.to_string().as_str())),
    }
}

#[debug_handler]
async fn link_preview(Path(link): Path<String>) -> String {
    format!("link_preview: '{}'", &link)
}

// API endpoint for creating links (requires owner_subject in JSON)
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateLinkApiRequest {
    pub owner_subject: String,
    pub name: String,
    pub target: Url,
    pub tag: Option<String>,
}

#[debug_handler]
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
            eprintln!("Failed to save link: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save link".to_string(),
            )
        })?;

    Ok(link.into())
}
