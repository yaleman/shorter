use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;

use crate::AppState;
use crate::{constants::Urls, entities::user};

/// Authenticated user information extracted from session
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub subject: String,
    pub email: String,
    pub display_name: Option<String>,
}

impl From<user::Model> for AuthUser {
    fn from(user: user::Model) -> Self {
        AuthUser {
            subject: user.subject,
            email: user.email,
            display_name: user.display_name,
        }
    }
}

/// Middleware that requires authentication
/// Checks session for user_subject, loads user from DB, and adds to request extensions
/// Redirects to /admin/login if not authenticated
pub async fn require_auth(
    State(state): State<AppState>,
    session: Session,
    mut request: Request,
    next: Next,
) -> Response {
    // Get user subject from session
    let user_subject: Option<String> = match session.get("user_subject").await {
        Ok(subject) => subject,
        Err(e) => {
            tracing::error!("Failed to get user_subject from session: {:?}", e);
            return Redirect::to(Urls::Login.as_ref()).into_response();
        }
    };

    let user_subject = match user_subject {
        Some(subject) => subject,
        None => {
            // Not authenticated, redirect to login
            return Redirect::to(Urls::Login.as_ref()).into_response();
        }
    };

    // Load user from database
    let user = match state.db.get_user_by_subject(&user_subject).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // User not found in DB, clear session and redirect to login
            tracing::warn!(
                "User {} not found in database, clearing session",
                user_subject
            );
            let _ = session.remove::<String>("user_subject").await;
            return Redirect::to(Urls::Login.as_ref()).into_response();
        }
        Err(e) => {
            tracing::error!("Failed to load user from database: {:?}", e);
            return Redirect::to(Urls::Login.as_ref()).into_response();
        }
    };

    // Add user to request extensions
    let auth_user: AuthUser = user.into();
    request.extensions_mut().insert(auth_user);

    next.run(request).await
}
