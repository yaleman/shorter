use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::{Pool, Sqlite, SqliteConnection};
use tracing::error;
use uuid::Uuid;

#[cfg(test)]
use crate::db::create_tables;
use crate::prelude::*;

#[derive(Clone, Deserialize, Serialize, Debug, sqlx::FromRow)]
pub struct User {
    pub id: Option<i64>,
    pub displayname: String,
    pub username: String,
    pub email: String,
    pub disabled: bool,
    pub authref: Option<String>,
    pub admin: bool,
}

impl From<SqliteRow> for User {
    fn from(value: SqliteRow) -> Self {
        use sqlx::Row;
        User {
            id: value.try_get("id").ok(),
            displayname: value.try_get("displayname").unwrap_or_default(),
            username: value.try_get("username").unwrap_or_default(),
            email: value.try_get("email").unwrap_or_default(),
            disabled: value.try_get("disabled").unwrap_or_default(),
            authref: value.try_get("authref").ok(),
            admin: value.try_get("admin").unwrap_or_default(),
        }
    }
}

#[async_trait]
impl DBEntity<Uuid> for User {
    const TABLE: &'static str = "users";

    async fn create_table(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id INTEGER  PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                displayname TEXT,
                email TEXT NOT NULL UNIQUE,
                disabled BOOLEAN,
                authref TEXT,
                admin BOOLEAN,
                UNIQUE(username)
            )",
            Self::TABLE
        ))
        .execute(&mut *pool.acquire().await?)
        .await?;

        Ok(())
    }

    async fn new() -> Result<Self, crate::prelude::MyError> {
        todo!()
    }

    async fn get_by_id(&self, pool: &Pool<Sqlite>, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        let res: User = match sqlx::query(&format!(
            "SELECT id, displayname, username, email, disabled, authref, admin from {} where id=?",
            Self::TABLE
        ))
        .bind(id)
        .fetch_one(&mut *pool.acquire().await?)
        .await
        {
            Ok(res) => res.into(),
            Err(err) => {
                return Err(err);
            }
        };

        Ok(Some(res))
    }

    async fn save_with_txn<'t>(
        &self,
        txn: &mut sqlx::SqliteConnection,
    ) -> Result<Box<Self>, MyError> {
        let query = format!(
            "INSERT INTO {}
            (displayname, username, email, disabled, authref, admin) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (username) DO UPDATE SET
            displayname = excluded.displayname,
            email = excluded.email,
            disabled = excluded.disabled,
            authref = excluded.authref,
            admin = excluded.admin
            ",
            Self::TABLE
        );
        sqlx::query(&query)
            .bind(&self.displayname)
            .bind(&self.username)
            .bind(&self.email)
            .bind(self.disabled)
            .bind(&self.authref)
            .bind(self.admin)
            .execute(&mut *txn)
            .await?;

        // now get the user we just saved
        match self.get_by_username(txn, &self.username).await {
            Ok(val) => match val {
                Some(user) => Ok(Box::new(user)),
                None => {
                    error!(
                        "We just saved the user {:?} but then couldn't find it in the DB?",
                        self
                    );
                    Err(MyError::UserNotFound)
                }
            },
            Err(err) => Err(err),
        }
    }

    /// save the entity to the database
    async fn save(&self, pool: &Pool<Sqlite>) -> Result<Box<Self>, MyError> {
        let mut txn = pool.begin().await?;
        let res = self.save_with_txn(&mut txn).await?;
        txn.commit().await?;
        Ok(res)
    }
}

impl User {
    pub async fn get_by_username(
        &self,
        txn: &mut SqliteConnection,
        username: &str,
    ) -> Result<Option<Self>, MyError> {
        sqlx::query(&format!("SELECT * from {} where username=?", Self::TABLE))
            .bind(username)
            .fetch_optional(&mut *txn)
            .await
            .map(|res| res.map(|row| row.into()))
            .map_err(|err| err.into()) // convert the row into a User
    }
}

#[tokio::test]
async fn test_create_user() {
    let db = DB::new_memory().await.unwrap();

    create_tables(db.dbpool.clone()).await.unwrap();

    let example_user = User {
        id: None,
        displayname: "Test User".to_string(),
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        disabled: false,
        admin: false,
        authref: None,
    };
    dbg!(&example_user);
    if let Err(err) = example_user.save(&db.dbpool).await {
        panic!("Failed to save user: {:?}", err);
    }
}
