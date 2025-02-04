use axum::async_trait;
use sqlx::{Acquire, Pool, Sqlite, SqliteConnection};
use url::Url;
use uuid::Uuid;

use crate::prelude::*;
use crate::user::User;
use crate::{Link, LinkForm};

enum Tables {
    Links,
    People,
}

impl AsRef<str> for Tables {
    fn as_ref(&self) -> &str {
        match self {
            Tables::Links => "links",
            Tables::People => "person",
        }
    }
}

#[derive(Clone)]
pub struct DB {
    pub dbpool: Pool<Sqlite>,
}

impl DB {
    pub async fn new(url: &str) -> Result<Self, MyError> {
        let dbpool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await?;

        create_tables(dbpool.clone()).await?;
        Ok(Self { dbpool })
    }

    pub async fn new_memory() -> Result<Self, MyError> {
        Self::new("sqlite::memory:").await
    }

    /// Get a link by its ID
    pub async fn get_link(&mut self, tag: &str) -> Result<Option<Link>, MyError> {
        let row: (Uuid, Uuid, String, String, String) = match sqlx::query_as(&format!(
            "SELECT id, owner, name, target, tag FROM {} where tag=?1",
            Tables::Links.as_ref()
        ))
        .bind(tag)
        .fetch_one(&self.dbpool)
        .await
        {
            Ok(val) => val,
            Err(err) => {
                if let sqlx::Error::RowNotFound = err {
                    return Ok(None);
                } else {
                    return Err(err.into());
                }
            }
        };

        let target: Url = match row.3.parse() {
            Ok(url) => url,
            Err(err) => return Err(err.into()),
        };

        Ok(Some(Link {
            id: row.0,
            owner: row.1,
            name: row.2,
            target,
            tag: row.4,
        }))
    }

    /// Create a link
    pub async fn create_link(&mut self, linkform: &LinkForm) -> Result<Link, MyError> {
        let id = uuid::Uuid::new_v4();

        let tag = match linkform.tag.clone() {
            Some(tag) => tag.to_owned(),
            None => {
                let tag_slice = id.to_string().clone().as_bytes().split_at(8).0.to_owned();
                String::from_utf8(tag_slice).expect("Failed to generate tag")
            }
        };
        let mut txn = self.dbpool.begin().await?;

        let _rows = sqlx::query(&format!(
            "INSERT INTO {} (id, owner, name, target, tag) VALUES (?1, ?2, ?3, ?4, ?5)",
            Tables::Links.as_ref()
        ))
        .bind(id)
        .bind(linkform.owner)
        .bind(&linkform.name)
        .bind(linkform.target.to_string())
        .bind(&tag)
        .fetch_optional(txn.acquire().await?)
        .await;
        txn.commit().await?;

        Ok(Link {
            id,
            owner: linkform.owner.to_owned(),
            name: linkform.name.to_owned(),
            target: linkform.target.to_owned(),
            tag,
        })
    }

    pub async fn create_user(&mut self, _user: User) -> Result<User, MyError> {
        todo!()
    }
}

pub(crate) async fn create_tables(conn: Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id    TEXT NOT NULL UNIQUE,
            owner    TEXT NOT NULL,
            name  TEXT NOT NULL,
            target  TEXT NOT NULL,
            tag TEXT NOT NULL UNIQUE
        )",
        Tables::Links.as_ref()
    ))
    .execute(&conn)
    .await?;

    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER NOT NULL UNIQUE,
            displayname TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            disabled BOOLEAN,
            authref TEXT,
            admin BOOLEAN
        )",
        Tables::People.as_ref()
    ))
    .execute(&conn)
    .await?;

    User::create_table(&conn).await?;
    Ok(())
}

#[async_trait]
pub trait DBEntity<T>: Send + Sync
where
    Self: Sized + Send + Sync,
{
    const TABLE: &'static str;

    async fn create_table(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error>;
    async fn new() -> Result<Self, MyError>;

    /// save the entity to the database
    async fn save(&self, pool: &Pool<Sqlite>) -> Result<Box<Self>, MyError> {
        let mut txn = pool.begin().await?;
        let res = self.save_with_txn(&mut txn).await?;
        txn.commit().await?;
        Ok(res)
    }

    async fn save_with_txn<'t>(&self, txn: &mut SqliteConnection) -> Result<Box<Self>, MyError>;

    async fn get_by_id(&self, pool: &Pool<Sqlite>, id: T) -> Result<Option<Self>, sqlx::Error>;
}

#[tokio::test]
async fn test_create_tables() {
    let db = DB::new_memory().await.unwrap();
    let conn = db.dbpool.clone();
    create_tables(conn).await.unwrap();
}
