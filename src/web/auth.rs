use crate::web::OAuthCallbackQuery;

use super::prelude::*;

// ========== Auth Handlers ==========

#[instrument(level = "info", skip_all)]
pub(crate) async fn auth_login(
    State(state): State<AppState>,
) -> Result<Redirect, (StatusCode, String)> {
    let oauth_client = state.oauth_client.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth not configured".to_string(),
    ))?;

    let (auth_url, _state) = oauth_client.generate_auth_url().await.map_err(|e| {
        error!("Failed to generate auth URL: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to start login".to_string(),
        )
    })?;

    Ok(Redirect::to(&auth_url))
}

#[instrument(level = "info", skip_all)]
pub(crate) async fn auth_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
    session: Session,
) -> Result<Redirect, (StatusCode, String)> {
    debug!(
        "Auth callback received - code: {}, state: {}",
        &query.code, &query.state
    );

    let oauth_client = state.oauth_client.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth not configured".to_string(),
    ))?;

    // Exchange code for tokens
    let (email, subject) = oauth_client
        .exchange_code(&query.code, &query.state)
        .await
        .map_err(|e| {
            error!(error=?e, "Failed to exchange OAuth2 code with IDP!");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication failed".to_string(),
            )
        })?;

    debug!(
        "OAuth2 Code exchange successful - email: {}, subject: {}",
        &email, &subject
    );

    // Get or create user in database
    let user = state
        .db
        .get_or_create_user(&subject, &email, None)
        .await
        .map_err(|e| {
            error!("Failed to create user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Check the logs!".to_string(),
            )
        })?;

    trace!("trying to create store user sesssion");
    // Store user subject in session
    session
        .insert("user_subject", user.subject)
        .await
        .map_err(|e| {
            error!("Failed to store session: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save session".to_string(),
            )
        })?;
    trace!("successfully stored user session, redirecting");
    Ok(Redirect::to("/admin/"))
}

#[instrument(level = "info", skip_all)]
pub(crate) async fn auth_logout(session: Session) -> Result<Redirect, (StatusCode, String)> {
    session
        .remove::<String>("user_subject")
        .await
        .map_err(|e| {
            error!("Failed to clear session: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to logout".to_string(),
            )
        })?;

    Ok(Redirect::to("/"))
}
