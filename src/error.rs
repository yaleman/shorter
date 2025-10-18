use url::ParseError;

#[derive(Debug)]
pub enum MyError {
    Other(String),
    DatabaseError(String),
    UserNotFound,
    OidcDiscovery(String),
    OidcStateParameterExpired,
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

impl From<sea_orm::DbErr> for MyError {
    fn from(err: sea_orm::DbErr) -> Self {
        MyError::DatabaseError(format!("{:?}", err))
    }
}
