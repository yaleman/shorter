use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use tower::util::ServiceExt;
use tracing::debug;
use url::Url;

use crate::db::{LinkWithOwner, DB};
use crate::logging::setup_test_logging;
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
