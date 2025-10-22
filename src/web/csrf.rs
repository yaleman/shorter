//! CSRF protection utilities

use axum::http::StatusCode;
use tower_sessions::Session;
use tracing::error;
use uuid::Uuid;

const CSRF_TOKEN_KEY: &str = "csrf_token";

/// Generate a new CSRF token and store it in the session
pub(crate) async fn generate_csrf_token(session: &Session) -> Result<String, StatusCode> {
    let token = Uuid::new_v4().to_string();
    session
        .insert(CSRF_TOKEN_KEY, token.clone())
        .await
        .map_err(|e| {
            error!("Failed to store CSRF token in session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(token)
}

/// Validate a CSRF token against the session and remove it (one-time use)
pub(crate) async fn validate_csrf_token(session: &Session, token: &str) -> Result<(), StatusCode> {
    let stored_token: Option<String> = session.get(CSRF_TOKEN_KEY).await.map_err(|e| {
        error!("Failed to retrieve CSRF token from session: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Remove the token from session (one-time use)
    session
        .remove::<String>(CSRF_TOKEN_KEY)
        .await
        .map_err(|e| {
            error!("Failed to remove CSRF token from session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match stored_token {
        Some(stored) if stored == token => Ok(()),
        Some(_) => {
            error!("CSRF token mismatch");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            error!("No CSRF token found in session");
            Err(StatusCode::FORBIDDEN)
        }
    }
}
