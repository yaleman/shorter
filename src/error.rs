use std::sync::Arc;

use openidconnect::DiscoveryError;
use rustls::crypto::CryptoProvider;
use url::ParseError;

#[derive(Debug)]
pub enum MyError {
    TagExists,
    Io(String),
    Other(String),
    DatabaseError(String),
    UserNotFound,
    OidcDiscovery(String),
    OidcStateParameterExpired,
    Crypto(String),
    Startup(String),
}

impl From<tracing_subscriber::filter::ParseError> for MyError {
    fn from(err: tracing_subscriber::filter::ParseError) -> Self {
        MyError::Startup(format!("Failed to parse log directive: {:?}", err))
    }
}

impl From<DiscoveryError<reqwest::Error>> for MyError {
    fn from(err: DiscoveryError<reqwest::Error>) -> Self {
        MyError::OidcDiscovery(format!("OIDC discovery error: {:?}", err))
    }
}

impl From<std::net::AddrParseError> for MyError {
    fn from(err: std::net::AddrParseError) -> Self {
        MyError::Startup(format!("{:?}", err))
    }
}
impl From<std::io::Error> for MyError {
    fn from(err: std::io::Error) -> Self {
        MyError::Io(format!("{:?}", err))
    }
}

impl From<Arc<CryptoProvider>> for MyError {
    fn from(err: Arc<CryptoProvider>) -> Self {
        MyError::Crypto(format!("{:?}", err))
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

impl From<sea_orm::DbErr> for MyError {
    fn from(err: sea_orm::DbErr) -> Self {
        MyError::DatabaseError(format!("{:?}", err))
    }
}

impl From<openidconnect::ConfigurationError> for MyError {
    fn from(err: openidconnect::ConfigurationError) -> Self {
        MyError::OidcDiscovery(format!("OIDC configuration error: {:?}", err))
    }
}
