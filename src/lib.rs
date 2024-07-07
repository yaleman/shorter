pub mod db;
pub mod error;
pub mod prelude;
#[cfg(test)]
mod tests;
pub mod user;

use std::sync::Arc;

use crate::db::DB;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Json;
use axum::{debug_handler, response::Redirect, Router};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

const BANNED_TAGS: [&str; 3] = ["link", "admin", "preview"];

#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct Link {
    pub id: Uuid,
    pub owner: Uuid,
    pub name: String,
    pub target: Url,
    pub tag: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LinkForm {
    pub owner: Uuid,
    pub name: String,
    pub target: Url,
    pub tag: Option<String>,
}

#[derive(Clone)]
struct AppStateInner {
    db: DB,
}

type AppState = Arc<RwLock<AppStateInner>>;

impl AppStateInner {
    async fn new() -> Option<Arc<RwLock<Self>>> {
        let db = match DB::new("sqlite://shorter.sqlite3?mode=rwc").await {
            Ok(db) => db,
            Err(err) => {
                eprintln!("Error creating DB: {:?}", err);
                return None;
            }
        };
        Some(Arc::new(RwLock::new(AppStateInner { db })))
    }
    #[cfg(test)]
    async fn new_memory() -> Option<Arc<RwLock<Self>>> {
        let db = match DB::new_memory().await {
            Ok(db) => db,
            Err(err) => {
                eprintln!("Error creating DB: {:?}", err);
                return None;
            }
        };
        Some(Arc::new(RwLock::new(AppStateInner { db })))
    }
}

pub(crate) fn build_app(shared_state: AppState) -> Router {
    Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/link", post(create_link))
        .route("/:link/preview", get(link_preview))
        .route("/:link", get(link))
        .with_state(shared_state)
}

pub async fn start_server(listener_addr: &str) {
    let shared_state = match AppStateInner::new().await {
        Some(val) => val,
        None => return,
    };

    let app = build_app(shared_state);
    // build our application with a route

    // `POST /users` goes to `create_user`
    // .route("/users", post(create_user));

    eprintln!("Starting server on http://{}", &listener_addr);
    let listener = tokio::net::TcpListener::bind(listener_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

#[debug_handler]
async fn link(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Result<Redirect, (StatusCode, String)> {
    if BANNED_TAGS.contains(&tag.as_ref()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid tag".to_string()));
    }

    let link = match state.write().await.db.get_link(&tag).await {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Error getting link '{}'  {:?}", &tag, err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting link".to_string(),
            ));
        }
    };
    match link {
        None => {
            return Err((StatusCode::NOT_FOUND, "404 Link Not Found".to_string()));
        }
        Some(link) => {
            return Ok(Redirect::to(link.target.to_string().as_str()));
        }
    }
}

#[debug_handler]
async fn link_preview(Path(link): Path<String>) -> String {
    format!("link_preview: '{}'", &link)
}

#[debug_handler]
async fn create_link(
    State(state): State<AppState>,
    Json(linkform): Json<LinkForm>,
) -> Result<Json<Link>, (StatusCode, String)> {
    // eprintln!("Got form: {:?}", linkform);

    // check if the link already exists by tag
    if let Some(tag) = &linkform.tag {
        if BANNED_TAGS.contains(&tag.as_str()) {
            return Err((StatusCode::BAD_REQUEST, "Invalid tag".to_string()));
        }
    }

    // create the link
    let link = state
        .write()
        .await
        .db
        .create_link(&linkform)
        .await
        .map_err(|err| {
            eprintln!("Failed to save {:?}: {:?}", linkform, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save link".to_string(),
            )
        })?;

    Ok(link.into())
}
