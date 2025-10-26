//! OIDC/OAuth2 client with PKCE support
pub mod middleware;

use std::sync::Arc;

use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use tokio::sync::RwLock;
use tracing::{debug, error};

use crate::db::DB;
use crate::error::MyError;

async fn run_discovery(
    issuer_url: &IssuerUrl,
    http_client: reqwest::Client,
) -> Result<CoreProviderMetadata, openidconnect::DiscoveryError<reqwest::Error>> {
    CoreProviderMetadata::discover_async(
        issuer_url.clone(),
        &(move |http_request: http::Request<Vec<u8>>| {
            let http_client = http_client.clone();
            async move {
                let uri = http_request.uri().to_string();
                let response = http_client
                    .request(http_request.method().clone(), &uri)
                    .headers(http_request.headers().clone())
                    .body(http_request.into_body())
                    .send()
                    .await?;

                let status = response.status();
                let body = response.bytes().await?.to_vec();

                // This should never fail as we're providing valid status and body
                let mut res = http::Response::new(body);
                *res.status_mut() = status;
                Ok(res)
            }
        }),
    )
    .await
}

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    provider_metadata: Arc<RwLock<Option<CoreProviderMetadata>>>,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    issuer_url: IssuerUrl,
    http_client: reqwest::Client,
    db: Arc<DB>,
}

impl OAuthClient {
    /// Create new OAuth client from OIDC discovery URL
    pub async fn new(
        discovery_url: &str,
        client_id: &str,
        redirect_uri: &str,
        db: Arc<DB>,
    ) -> Result<Self, MyError> {
        let issuer_url = IssuerUrl::new(discovery_url.to_string())
            .map_err(|e| MyError::OidcDiscovery(format!("Invalid OIDC issuer URL: {}", e)))?;

        let http_client = reqwest::Client::new();

        let provider_metadata = Arc::new(RwLock::new(
            CoreProviderMetadata::discover_async(issuer_url.clone(), &http_client.clone())
                .await
                .map_err(|e| {
                    MyError::OidcDiscovery(format!(
                        "Failed to query OIDC provider: error={e} issuer_url={:?}",
                        issuer_url
                    ))
                })?,
        ));

        let provider_metadata = match run_discovery(&issuer_url, http_client.clone()).await {
            Ok(pm) => Arc::new(RwLock::new(Some(pm))),
            Err(err) => {
                error!(error=%err, "Failed to run OIDC discovery");
                // TODO: this should spawn a task to retry discovery every 30 seconds
                Arc::new(RwLock::new(None))
            }
        };
        let redirect_url = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| MyError::OidcDiscovery(format!("Invalid OIDC redirect URI: {}", e)))?;

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(client_id.to_string()),
            redirect_uri: redirect_url,
            db,
            issuer_url,
            http_client,
        })
    }

    pub async fn update_provider_metadata(&self) -> Result<CoreProviderMetadata, MyError> {
        let existing_pm = self.provider_metadata.read().await.clone();
        match existing_pm {
            Some(provider_metadata) => Ok(provider_metadata.clone()),
            None => {
                let pm = run_discovery(&self.issuer_url, self.http_client.clone())
                    .await
                    .map_err(|err| {
                        error!(error=?err, "Failed to run OIDC discovery");
                        MyError::from(err)
                    })?;
                self.provider_metadata.write().await.replace(pm.clone());
                Ok(pm)
            }
        }
    }

    /// Generate authorization URL with PKCE challenge
    /// Returns (auth_url, csrf_token/state)
    pub async fn generate_auth_url(&self) -> Result<(String, String), MyError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let provider_metadata = match self.provider_metadata.read().await.as_ref() {
            Some(val) => val.clone(),
            None => self.update_provider_metadata().await?,
        };
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge.clone())
            .url();

        // Store PKCE state in database (expires in 10 minutes)
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_minutes(10).ok_or_else(|| {
                MyError::Other("Failed to create PKCE session duration".to_string())
            })?;

        debug!(
            "Storing PKCE state: {}, expires at: {:?}",
            csrf_token.secret(),
            expires_at
        );

        self.db
            .store_pkce_state(
                csrf_token.secret(),
                pkce_verifier.secret(),
                nonce.secret(),
                pkce_challenge.as_str(),
                self.redirect_uri.as_str(),
                expires_at,
            )
            .await
            .inspect_err(|err| {
                error!("Failed to store PKCE state in database: {:?}", err);
            })?;

        debug!("Successfully stored PKCE state: {}", csrf_token.secret());

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Exchange authorization code for tokens and validate
    /// Returns (user_email, user_subject)
    pub async fn exchange_code(
        &self,
        code: &str,
        state: &str,
    ) -> Result<(String, String), MyError> {
        debug!("Looking up PKCE state for: {}", state);

        // Retrieve PKCE state from database
        let pkce_state = self.db.get_pkce_state(state).await?.ok_or_else(|| {
            error!("PKCE state not found in database for state: {}", state);
            MyError::OidcStateParameterExpired
        })?;

        debug!(
            "Found PKCE state, checking expiration. Expires at: {:?}, Now: {:?}",
            pkce_state.expires_at,
            chrono::Utc::now().naive_utc()
        );

        // Check if expired
        if pkce_state.expires_at < chrono::Utc::now().naive_utc() {
            error!(
                "PKCE state expired. Expires at: {:?}, Now: {:?}",
                pkce_state.expires_at,
                chrono::Utc::now().naive_utc()
            );
            self.db.delete_pkce_state(state).await?;
            return Err(MyError::OidcStateParameterExpired);
        }

        let provider_metadata = match self.provider_metadata.read().await.as_ref() {
            Some(val) => val.clone(),
            None => self.update_provider_metadata().await?,
        };
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let pkce_verifier = PkceCodeVerifier::new(pkce_state.code_verifier.clone());

        debug!("Exchanging authorization code for tokens");
        debug!("Redirect URI: {}", self.redirect_uri.as_str());

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&reqwest::Client::new())
            .await
            .map_err(|e| {
                error!("Token exchange error: {:?}", e);
                error!("This usually means:");
                error!(
                    "  1. Redirect URI mismatch - check that {} matches your OIDC provider configuration",
                    self.redirect_uri.as_str()
                );
                error!("  2. Authorization code already used or expired");
                error!("  3. OIDC provider requires client authentication (client_secret) - shorter only supports PKCE");
                MyError::Other(format!("Token exchange failed: {}", e))
            })?;

        // Verify ID token
        let id_token = token_response
            .id_token()
            .ok_or_else(|| MyError::Other("No ID token in response".to_string()))?;

        let nonce = Nonce::new(pkce_state.nonce.clone());
        let claims = id_token
            .claims(&client.id_token_verifier(), &nonce)
            .map_err(|e| MyError::Other(format!("ID token validation failed: {}", e)))?;

        // Extract user info
        let user_email = claims
            .email()
            .map(|e| e.as_str())
            .ok_or_else(|| {
                debug!("ID token claims: {:?}", claims);
                MyError::Other("Email address not found in ID token".to_string())
            })?
            .to_string();
        let user_id = claims.subject().as_str().to_string();

        // Clean up PKCE state
        self.db.delete_pkce_state(state).await?;

        Ok((user_email, user_id))
    }
}
