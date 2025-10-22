//! Admin Handlers

use std::sync::LazyLock;

use crate::{
    constants::BANNED_TAGS, db::LinkWithOwner, oauth::middleware::AuthUser, web::NotFoundTemplate,
};
use askama::Template;
use axum::{
    extract::Path,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Form,
};
use axum_csp::{CspDirectiveType, CspHeaderBuilder, CspValue};
use http::HeaderValue;
use serde::Deserialize;
use url::Url;

use super::prelude::*;

// Admin templates
#[derive(Template)]
#[template(path = "admin_list.html")]
pub(crate) struct AdminListTemplate {
    links: Vec<LinkWithOwner>,
    user: AuthUser,
}

#[derive(Template)]
#[template(path = "admin_create.html")]
pub(crate) struct AdminCreateTemplate {
    error: Option<String>,
    user: AuthUser,
    tag: Option<String>,
    target: Option<String>,
    display_name: Option<String>,
    csrf_token: String,
}

impl Default for AdminCreateTemplate {
    fn default() -> Self {
        AdminCreateTemplate {
            error: None,
            user: AuthUser {
                subject: String::new(),
                email: String::new(),
                display_name: None,
            },
            tag: None,
            target: None,
            display_name: None,
            csrf_token: String::new(),
        }
    }
}

#[derive(Template)]
#[template(path = "admin_edit.html")]
pub(crate) struct AdminEditTemplate {
    link: LinkWithOwner,
    error: Option<String>,
    user: AuthUser,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "admin_delete.html")]
pub(crate) struct AdminDeleteTemplate {
    link: LinkWithOwner,
    user: AuthUser,
    csrf_token: String,
}

// Form structs for admin operations
#[derive(Debug, Deserialize)]
pub(crate) struct LinkFormData {
    name: String,
    target: String,
    tag: String,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteFormData {
    csrf_token: String,
}

#[instrument(level = "info", skip_all)]
pub(crate) async fn admin_list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<HtmlTemplate<AdminListTemplate>, (StatusCode, String)> {
    let links = state.db.list_links().await.map_err(|err| {
        error!("Error listing links: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list links".to_string(),
        )
    })?;

    Ok(HtmlTemplate(AdminListTemplate { links, user }))
}

#[instrument(level = "info")]
pub(crate) async fn admin_create_form(
    Extension(user): Extension<AuthUser>,
    session: tower_sessions::Session,
) -> Result<HtmlTemplate<AdminCreateTemplate>, StatusCode> {
    let csrf_token = super::csrf::generate_csrf_token(&session).await?;
    Ok(HtmlTemplate(AdminCreateTemplate {
        user,
        csrf_token,
        ..Default::default()
    }))
}

#[instrument(level = "info", skip(state))]
pub(crate) async fn admin_create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    session: tower_sessions::Session,
    Form(form_data): Form<LinkFormData>,
) -> Result<Response, (StatusCode, String)> {
    // Validate CSRF token
    super::csrf::validate_csrf_token(&session, &form_data.csrf_token)
        .await
        .map_err(|e| (e, "CSRF token validation failed".to_string()))?;

    // Parse the target URL
    let target = match Url::parse(&form_data.target) {
        Ok(url) => url,
        Err(_) => {
            let csrf_token = super::csrf::generate_csrf_token(&session)
                .await
                .map_err(|e| (e, "Failed to generate CSRF token".to_string()))?;
            return Ok(HtmlTemplate(AdminCreateTemplate {
                error: Some(format!("Invalid target URL: {}", form_data.target)),
                user,
                tag: Some(form_data.tag),
                target: Some(form_data.target),
                display_name: Some(form_data.name),
                csrf_token,
            })
            .into_response());
        }
    };

    // Check if tag is empty or contains only whitespace
    let tag = if form_data.tag.trim().is_empty() {
        None
    } else {
        Some(form_data.tag.trim().to_string())
    };

    // Check for banned tags
    if let Some(ref tag_val) = tag {
        if BANNED_TAGS.contains(&tag_val.as_str()) {
            let csrf_token = super::csrf::generate_csrf_token(&session)
                .await
                .map_err(|e| (e, "Failed to generate CSRF token".to_string()))?;
            return Ok(HtmlTemplate(AdminCreateTemplate {
                error: Some(format!("Tag '{}' is reserved and cannot be used", tag_val)),
                user,
                tag: Some(form_data.tag),
                target: Some(form_data.target),
                display_name: Some(form_data.name),
                csrf_token,
            })
            .into_response());
        }
    }

    // Create the link (owned by current user)
    if let Err(err) = state
        .db
        .create_link(&user.subject, &form_data.name, &target, tag)
        .await
    {
        match err {
            crate::error::MyError::TagExists => {
                let csrf_token = super::csrf::generate_csrf_token(&session)
                    .await
                    .map_err(|e| (e, "Failed to generate CSRF token".to_string()))?;
                return Ok(HtmlTemplate(AdminCreateTemplate {
                    error: Some(format!("Tag '{}' already exists", form_data.tag)),
                    tag: Some(form_data.tag),
                    target: Some(form_data.target),
                    display_name: Some(form_data.name),
                    user,
                    csrf_token,
                })
                .into_response());
            }
            _ => {
                error!("Failed to create link: {:?}", err);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create link".to_string(),
                ))
            }
        }
    } else {
        Ok(Redirect::to("/admin/").into_response())
    }

    // Redirect to admin list
}

#[instrument(level = "info", skip(state))]
pub(crate) async fn admin_edit_form(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    session: tower_sessions::Session,
) -> Result<HtmlTemplate<AdminEditTemplate>, impl IntoResponse> {
    let csrf_token = super::csrf::generate_csrf_token(&session)
        .await
        .map_err(|e| e.into_response())?;

    let link = state.db.get_link_by_id(&id).await.map_err(|err| {
        error!("Error getting link: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get link".to_string(),
        )
            .into_response()
    })?;

    match link {
        Some(link) => Ok(HtmlTemplate(AdminEditTemplate {
            link,
            error: None,
            user,
            csrf_token,
        })),
        None => Err(NotFoundTemplate {}.into_response()),
    }
}

#[instrument(level = "info", skip(state))]
pub(crate) async fn admin_edit(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    session: tower_sessions::Session,
    axum::Form(form_data): Form<LinkFormData>,
) -> Result<Response, (StatusCode, String)> {
    // Validate CSRF token
    super::csrf::validate_csrf_token(&session, &form_data.csrf_token)
        .await
        .map_err(|e| (e, "CSRF token validation failed".to_string()))?;

    // Parse the target URL
    let target = match Url::parse(&form_data.target) {
        Ok(url) => url,
        Err(_) => {
            // get the link
            let current_link = state
                .db
                .get_link_by_id(&id)
                .await
                .map_err(|err| {
                    error!("Error getting link: {:?}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to get link".to_string(),
                    )
                })?
                .ok_or((StatusCode::NOT_FOUND, "Link not found".to_string()))?;
            let csrf_token = super::csrf::generate_csrf_token(&session)
                .await
                .map_err(|e| (e, "Failed to generate CSRF token".to_string()))?;
            return Ok(HtmlTemplate(AdminEditTemplate {
                link: current_link,
                error: Some(format!("Invalid target URL: {}", form_data.target)),
                user,
                csrf_token,
            })
            .into_response());
        }
    };

    // Check for banned tags
    if BANNED_TAGS.contains(&form_data.tag.as_str()) {
        // Get the current link to show in error state
        let current_link = state
            .db
            .get_link_by_id(&id)
            .await
            .map_err(|err| {
                error!("Error getting link: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get link".to_string(),
                )
            })?
            .ok_or((StatusCode::NOT_FOUND, "Link not found".to_string()))?;

        let csrf_token = super::csrf::generate_csrf_token(&session)
            .await
            .map_err(|e| (e, "Failed to generate CSRF token".to_string()))?;

        return Ok(HtmlTemplate(AdminEditTemplate {
            link: current_link,
            error: Some(format!(
                "Tag '{}' is reserved and cannot be used",
                form_data.tag
            )),
            user,
            csrf_token,
        })
        .into_response());
    }

    // Update the link
    state
        .db
        .update_link(&id, &form_data.name, &target, &form_data.tag)
        .await
        .map_err(|err| {
            error!("Failed to update link: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update link".to_string(),
            )
        })?;

    // Redirect to admin list
    Ok(Redirect::to("/admin/").into_response())
}

#[instrument(level = "info", skip(state))]
pub(crate) async fn admin_delete_confirm(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    session: tower_sessions::Session,
) -> Result<HtmlTemplate<AdminDeleteTemplate>, impl IntoResponse> {
    let csrf_token = super::csrf::generate_csrf_token(&session)
        .await
        .map_err(|e| e.into_response())?;

    let link = state.db.get_link_by_id(&id).await.map_err(|err| {
        error!("Error getting link: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get link".to_string(),
        )
            .into_response()
    })?;

    match link {
        Some(link) => Ok(HtmlTemplate(AdminDeleteTemplate {
            link,
            user,
            csrf_token,
        })),
        None => Err(NotFoundTemplate {}.into_response()),
    }
}

#[instrument(level = "info", skip(state))]
pub(crate) async fn admin_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: tower_sessions::Session,
    Form(form_data): Form<DeleteFormData>,
) -> Result<Redirect, (StatusCode, String)> {
    // Validate CSRF token
    super::csrf::validate_csrf_token(&session, &form_data.csrf_token)
        .await
        .map_err(|e| (e, "CSRF token validation failed".to_string()))?;

    state.db.delete_link(&id).await.map_err(|err| {
        error!("Failed to delete link: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete link".to_string(),
        )
    })?;

    Ok(Redirect::to("/admin/"))
}

static CSP_DIRECTIVES: LazyLock<HeaderValue> = LazyLock::new(|| {
    CspHeaderBuilder::new()
        .add(CspDirectiveType::DefaultSrc, vec![CspValue::SelfSite])
        .finish()
});

pub(crate) async fn cspheaders_layer(
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // wait for the middleware to come back
    let mut response = next.run(req).await;

    // add the header
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        CSP_DIRECTIVES.clone(),
    );

    Ok(response)
}
