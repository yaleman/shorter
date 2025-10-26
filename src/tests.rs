use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use tower::util::ServiceExt;
use tracing::debug;
use url::Url;

use crate::db::{LinkWithOwner, DB};
use crate::logging::setup_test_logging;
use crate::web::csrf::{generate_csrf_token, validate_csrf_token};
use crate::{build_app, web::CreateLinkApiRequest, AppState};

/// Build a test Axum router instance
async fn get_test_instance() -> (Router, Arc<DB>) {
    setup_test_logging();
    let shared_state = AppState::new_test().await;
    let db = shared_state.db.clone();
    (build_app(shared_state), db)
}

#[tokio::test]
async fn test_post_link() {
    let (app, dbconn) = get_test_instance().await;

    let link_target = "http://example.com/";

    let user = dbconn.create_test_user().await;

    let newlink = CreateLinkApiRequest {
        owner_subject: user.subject,
        name: "test".to_string(),
        target: Url::parse(link_target).expect("Failed to parse URL"),
        tag: Some("cheese".to_string()),
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri("/link")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&newlink).expect("Failed to serialize newlink"),
        ))
        .expect("Failed to build request");

    let response = app
        .clone()
        .oneshot(req)
        .await
        .expect("Failed to process request");

    assert_eq!(response.status(), 200);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");

    let link: LinkWithOwner =
        serde_json::from_slice(&body_bytes).expect("Failed to parse response body");

    assert_eq!(link.name, "test".to_string());

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/{}", &link.tag))
        .body(Body::empty())
        .expect("Failed to build request");
    debug!("pulling tag {}", &link.tag);
    let response = app.oneshot(req).await.expect("Failed to process request");
    dbg!(response.status());
    if !response.status().is_redirection() {
        panic!("{:?}", response.into_body());
    }
    assert_eq!(
        response
            .headers()
            .get("location")
            .expect("Missing location header"),
        link_target
    );
    assert!(response.status().is_redirection());

    // Verify Referrer-Policy header is set to no-referrer
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .expect("Missing referrer-policy header"),
        "no-referrer"
    );
}

#[tokio::test]
/// Ensure that banned tags are actually banned!
async fn test_banned_tag() {
    let (app, dbconn) = get_test_instance().await;

    let user = dbconn.create_test_user().await;

    let link_target = "http://example.com/";
    let newlink = CreateLinkApiRequest {
        owner_subject: user.subject,
        name: "test".to_string(),
        target: Url::parse(link_target).expect("Failed to parse URL"),
        tag: Some("admin".to_string()),
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri("/link")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&newlink).expect("Failed to serialize newlink"),
        ))
        .expect("Failed to build request");

    let response = app
        .clone()
        .oneshot(req)
        .await
        .expect("Failed to process request");
    assert_eq!(response.status(), 400);
}

#[tokio::test]
/// Test that redirect responses include the Referrer-Policy: no-referrer header
async fn test_redirect_referrer_policy_header() {
    let (app, dbconn) = get_test_instance().await;

    let user = dbconn.create_test_user().await;

    // Create a test link
    let link_target = "https://example.com/test-page";
    let test_tag = "test-referrer";

    let newlink = CreateLinkApiRequest {
        owner_subject: user.subject,
        name: "Test Referrer Policy".to_string(),
        target: Url::parse(link_target).expect("Failed to parse URL"),
        tag: Some(test_tag.to_string()),
    };

    let create_req = Request::builder()
        .method(Method::POST)
        .uri("/link")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&newlink).expect("Failed to serialize newlink"),
        ))
        .expect("Failed to build request");

    let create_response = app
        .clone()
        .oneshot(create_req)
        .await
        .expect("Failed to process request");

    assert_eq!(create_response.status(), 200);

    // Test the redirect endpoint
    let redirect_req = Request::builder()
        .method(Method::GET)
        .uri(format!("/{}", test_tag))
        .body(Body::empty())
        .expect("Failed to build request");

    let redirect_response = app
        .oneshot(redirect_req)
        .await
        .expect("Failed to process request");

    // Verify it's a redirect
    assert!(
        redirect_response.status().is_redirection(),
        "Expected redirect status, got {}",
        redirect_response.status()
    );

    // Verify the Location header is correct
    let location = redirect_response
        .headers()
        .get("location")
        .expect("Missing location header")
        .to_str()
        .expect("Invalid location header");

    assert_eq!(location, link_target, "Location header mismatch");

    // Verify the Referrer-Policy header is present and set to no-referrer
    let referrer_policy = redirect_response
        .headers()
        .get("referrer-policy")
        .expect("Missing referrer-policy header")
        .to_str()
        .expect("Invalid referrer-policy header");

    assert_eq!(
        referrer_policy, "no-referrer",
        "Referrer-Policy header should be 'no-referrer'"
    );
}

#[tokio::test]
async fn test_csrf_token_generation() {
    setup_test_logging();
    let app_state = AppState::new_test().await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(app_state.session_pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    let session = tower_sessions::Session::new(None, Arc::new(session_store), None);

    // Test generating a token
    let token = generate_csrf_token(&session)
        .await
        .expect("Failed to generate CSRF token");

    // Verify token is a valid UUID format (36 chars with hyphens)
    assert_eq!(token.len(), 36);
    assert!(token.contains('-'));

    // Verify token is stored in session
    let stored: Option<String> = session
        .get("csrf_token")
        .await
        .expect("Failed to get token from session");
    assert_eq!(stored, Some(token));
}

#[tokio::test]
async fn test_csrf_token_validation_valid() {
    setup_test_logging();
    let app_state = AppState::new_test().await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(app_state.session_pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    let session = tower_sessions::Session::new(None, Arc::new(session_store), None);

    // Generate a token
    let token = generate_csrf_token(&session)
        .await
        .expect("Failed to generate CSRF token");

    // Validate the token
    let result = validate_csrf_token(&session, &token).await;
    assert!(result.is_ok(), "Valid token should pass validation");

    // Verify token was removed from session (one-time use)
    let stored: Option<String> = session
        .get("csrf_token")
        .await
        .expect("Failed to check session");
    assert_eq!(stored, None, "Token should be removed after validation");
}

#[tokio::test]
async fn test_csrf_token_validation_invalid() {
    setup_test_logging();
    let app_state = AppState::new_test().await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(app_state.session_pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    let session = tower_sessions::Session::new(None, Arc::new(session_store), None);

    // Generate a token
    let _token = generate_csrf_token(&session)
        .await
        .expect("Failed to generate CSRF token");

    // Try to validate with wrong token
    let result = validate_csrf_token(&session, "wrong-token").await;
    assert!(result.is_err(), "Invalid token should fail validation");
    if let Err(status) = result {
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "Should return FORBIDDEN status"
        );
    }
}

#[tokio::test]
async fn test_csrf_token_validation_missing() {
    setup_test_logging();
    let app_state = AppState::new_test().await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(app_state.session_pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    let session = tower_sessions::Session::new(None, Arc::new(session_store), None);

    // Try to validate without generating a token first
    let result = validate_csrf_token(&session, "any-token").await;
    assert!(result.is_err(), "Missing token should fail validation");
    if let Err(status) = result {
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "Should return FORBIDDEN status"
        );
    }
}

#[tokio::test]
async fn test_csrf_token_one_time_use() {
    setup_test_logging();
    let app_state = AppState::new_test().await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(app_state.session_pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to migrate session store");

    let session = tower_sessions::Session::new(None, Arc::new(session_store), None);

    // Generate a token
    let token = generate_csrf_token(&session)
        .await
        .expect("Failed to generate CSRF token");

    // First validation should succeed
    let result = validate_csrf_token(&session, &token).await;
    assert!(result.is_ok(), "First validation should succeed");

    // Second validation with same token should fail (one-time use)
    let result = validate_csrf_token(&session, &token).await;
    assert!(
        result.is_err(),
        "Second validation should fail (one-time use)"
    );
    if let Err(status) = result {
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "Should return FORBIDDEN status"
        );
    }
}
