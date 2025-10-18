pub(crate) mod migration;

use std::sync::Arc;

use migration::MigratorTrait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set,
};
use tracing::debug;
use url::Url;

use crate::entities::{link, pkce_state, user};
use crate::error::MyError;

#[derive(Clone)]
pub struct DB {
    pub conn: Arc<DatabaseConnection>,
}

impl DB {
    /// Create new database connection and run migrations
    pub async fn new(database_url: &str) -> Result<Self, MyError> {
        let mut opt = sea_orm::ConnectOptions::new(database_url.to_string());
        opt.max_connections(1) // Use single connection for SQLite
            .min_connections(1)
            .sqlx_logging(false);

        let conn = Database::connect(opt)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        // Run migrations
        migration::Migrator::up(&conn, None)
            .await
            .map_err(|e| MyError::DatabaseError(format!("Migration failed: {}", e)))?;

        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    /// Create database for testing
    #[cfg(test)]
    pub async fn new_test() -> Self {
        use sea_orm::TransactionTrait;

        let db = Self::new("sqlite::memory:")
            .await
            .expect("Failed to get DB");
        // Run migrations

        let db_transaction = db.conn.begin().await.expect("Failed to begin transaction");
        migration::Migrator::up(&db_transaction, None)
            .await
            .map_err(|e| MyError::DatabaseError(format!("Migration failed: {}", e)))
            .expect("Failed to run migrations");
        db_transaction
            .commit()
            .await
            .expect("Failed to commit transaction");
        db
    }

    // ========== Link Operations ==========

    /// Get a link by tag
    pub async fn get_link(&self, tag: &str) -> Result<Option<LinkWithOwner>, MyError> {
        let link = link::Entity::find()
            .filter(link::Column::Tag.eq(tag))
            .one(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        match link {
            Some(l) => {
                let target = Url::parse(&l.target)?;
                Ok(Some(LinkWithOwner {
                    id: l.id,
                    owner_subject: l.owner_subject,
                    name: l.name,
                    target,
                    tag: l.tag,
                }))
            }
            None => Ok(None),
        }
    }

    /// List all links with owner information
    pub async fn list_links(&self) -> Result<Vec<LinkWithOwner>, MyError> {
        let links = link::Entity::find()
            .order_by_asc(link::Column::Tag)
            .all(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for l in links {
            let target = Url::parse(&l.target)?;
            result.push(LinkWithOwner {
                id: l.id.clone(),
                owner_subject: l.owner_subject.clone(),
                name: l.name.clone(),
                target,
                tag: l.tag.clone(),
            });
        }

        Ok(result)
    }

    /// Get a link by ID
    pub async fn get_link_by_id(&self, id: &str) -> Result<Option<LinkWithOwner>, MyError> {
        let link = link::Entity::find_by_id(id.to_string())
            .one(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        match link {
            Some(l) => {
                let target = Url::parse(&l.target)?;
                Ok(Some(LinkWithOwner {
                    id: l.id,
                    owner_subject: l.owner_subject,
                    name: l.name,
                    target,
                    tag: l.tag,
                }))
            }
            None => Ok(None),
        }
    }

    /// Create a new link
    pub async fn create_link(
        &self,
        owner_subject: &str,
        name: &str,
        target: &Url,
        tag: Option<String>,
    ) -> Result<LinkWithOwner, MyError> {
        let id = uuid::Uuid::new_v4().to_string();
        let tag = tag.unwrap_or_else(|| {
            // Generate tag from first 8 chars of UUID
            id.chars().take(8).collect()
        });

        let now = chrono::Utc::now().naive_utc();
        let new_link = link::ActiveModel {
            id: Set(id.clone()),
            owner_subject: Set(owner_subject.to_string()),
            name: Set(name.to_string()),
            target: Set(target.to_string()),
            tag: Set(tag.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        new_link
            .insert(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(LinkWithOwner {
            id,
            owner_subject: owner_subject.to_string(),
            name: name.to_string(),
            target: target.clone(),
            tag,
        })
    }

    /// Update a link
    pub async fn update_link(
        &self,
        id: &str,
        name: &str,
        target: &Url,
        tag: &str,
    ) -> Result<(), MyError> {
        let link = link::Entity::find_by_id(id.to_string())
            .one(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?
            .ok_or_else(|| MyError::Other("Link not found".to_string()))?;

        let mut link: link::ActiveModel = link.into();
        link.name = Set(name.to_string());
        link.target = Set(target.to_string());
        link.tag = Set(tag.to_string());

        link.update(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete a link
    pub async fn delete_link(&self, id: &str) -> Result<(), MyError> {
        link::Entity::delete_by_id(id.to_string())
            .exec(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    // ========== User Operations ==========

    /// Get or create user from OIDC claims
    pub async fn get_or_create_user(
        &self,
        subject: &str,
        email: &str,
        display_name: Option<String>,
    ) -> Result<user::Model, MyError> {
        // Try to find existing user by subject
        if let Some(user) = user::Entity::find()
            .filter(user::Column::Subject.eq(subject))
            .one(&*self.conn)
            .await
            .map_err(|e| {
                debug!("Database error when fetching user: {}", e);
                MyError::DatabaseError(e.to_string())
            })?
        {
            return Ok(user);
        }

        // Create new user
        let now = chrono::Utc::now();
        let new_user = user::ActiveModel {
            subject: Set(subject.to_string()),
            email: Set(email.to_string()),
            display_name: Set(display_name),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let user = new_user
            .save(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;
        let user = user::Model::try_from(user)?;
        Ok(user)
    }

    /// Get user by subject
    pub async fn get_user_by_subject(&self, subject: &str) -> Result<Option<user::Model>, MyError> {
        user::Entity::find()
            .filter(user::Column::Subject.eq(subject))
            .one(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))
    }

    // ========== PKCE State Operations ==========

    /// Store PKCE state for OAuth flow
    pub async fn store_pkce_state(
        &self,
        state: &str,
        code_verifier: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), MyError> {
        let pkce = pkce_state::ActiveModel {
            state: Set(state.to_string()),
            code_verifier: Set(code_verifier.to_string()),
            nonce: Set(nonce.to_string()),
            code_challenge: Set(code_challenge.to_string()),
            redirect_uri: Set(redirect_uri.to_string()),
            expires_at: Set(expires_at.naive_utc()),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };

        pkce.insert(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get PKCE state
    pub async fn get_pkce_state(&self, state: &str) -> Result<Option<pkce_state::Model>, MyError> {
        pkce_state::Entity::find_by_id(state.to_string())
            .one(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))
    }

    /// Delete PKCE state
    pub async fn delete_pkce_state(&self, state: &str) -> Result<(), MyError> {
        pkce_state::Entity::delete_by_id(state.to_string())
            .exec(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Clean up expired PKCE states
    pub async fn cleanup_expired_pkce_states(&self) -> Result<u64, MyError> {
        let now = chrono::Utc::now().naive_utc();
        let result = pkce_state::Entity::delete_many()
            .filter(pkce_state::Column::ExpiresAt.lt(now))
            .exec(&*self.conn)
            .await
            .map_err(|e| MyError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected)
    }

    #[cfg(test)]
    pub(crate) async fn create_test_user(&self) -> user::Model {
        self.get_or_create_user(
            "testuser",
            "testuser@test.com",
            Some("test user".to_string()),
        )
        .await
        .expect("Failed to create test user")
    }
}

/// Link with owner information (for responses)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinkWithOwner {
    pub id: String,
    pub owner_subject: String,
    pub name: String,
    pub target: Url,
    pub tag: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_creation() {
        let db = DB::new_test().await;
        assert!(db.conn.ping().await.is_ok());
    }

    #[tokio::test]
    async fn test_user_operations() {
        let db = DB::new_test().await;

        // Create user
        let user = db
            .get_or_create_user(
                "test_subject",
                "test@example.com",
                Some("Test User".to_string()),
            )
            .await
            .expect("Failed to create user");

        assert_eq!(user.subject, "test_subject");
        assert_eq!(user.email, "test@example.com");

        // Get existing user
        let user2 = db
            .get_or_create_user(
                "test_subject",
                "test@example.com",
                Some("Test User".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(user.id, user2.id);
    }

    #[tokio::test]
    async fn test_link_operations() {
        let db = DB::new_test().await;

        let user = db.create_test_user().await;

        // Create link
        let target = Url::parse("https://example.com").unwrap();
        let link = db
            .create_link(
                &user.subject,
                "Test Link",
                &target,
                Some("test".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(link.tag, "test");
        assert_eq!(link.name, "Test Link");

        // Get link by tag
        let found = db.get_link("test").await.unwrap().unwrap();
        assert_eq!(found.id, link.id);

        // List links
        let links = db.list_links().await.unwrap();
        assert_eq!(links.len(), 1);

        // Update link
        let new_target = Url::parse("https://example.org").unwrap();
        db.update_link(&link.id, "Updated Link", &new_target, "test")
            .await
            .unwrap();

        let updated = db.get_link("test").await.unwrap().unwrap();
        assert_eq!(updated.name, "Updated Link");
        assert_eq!(updated.target.as_str(), "https://example.org/");

        // Delete link
        db.delete_link(&link.id).await.unwrap();
        assert!(db.get_link("test").await.unwrap().is_none());
    }
}
