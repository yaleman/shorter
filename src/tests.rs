use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use tower::util::ServiceExt;
use url::Url;

use crate::db::{LinkWithOwner, DB};
use crate::logging::setup_test_logging;
use crate::{build_app, AppState, CreateLinkApiRequest};

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
        target: Url::parse(link_target).unwrap(),
        tag: Some("cheese".to_string()),
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri("/link")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&newlink).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();

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
        .unwrap();
    eprintln!("pulling tag {}", &link.tag);
    let response = app.oneshot(req).await.unwrap();
    dbg!(response.status());
    if !response.status().is_redirection() {
        panic!("{:?}", response.into_body());
    }
    assert_eq!(response.headers().get("location").unwrap(), link_target);
    assert!(response.status().is_redirection());
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
        target: Url::parse(link_target).unwrap(),
        tag: Some("admin".to_string()),
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri("/link")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&newlink).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), 400);
}
