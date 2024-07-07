use url::ParseError;

#[derive(Debug)]
pub enum MyError {
    Other(String),
    DatabaseError(sqlx::Error),
    UserNotFound,
}

impl From<sqlx::Error> for MyError {
    fn from(err: sqlx::Error) -> Self {
        MyError::DatabaseError(err)
    }
}
impl From<uuid::Error> for MyError {
    fn from(err: uuid::Error) -> Self {
        MyError::Other(format!("{:?}", err))
    }
}
impl From<ParseError> for MyError {
    fn from(err: ParseError) -> Self {
        MyError::Other(format!("{:?}", err))
    }
}
