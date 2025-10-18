//! OIDC/OAuth2 client with PKCE support

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

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    provider_metadata: Arc<RwLock<CoreProviderMetadata>>,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
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

        let provider_metadata = Arc::new(RwLock::new(
            CoreProviderMetadata::discover_async(
                issuer_url.clone(),
                openidconnect::reqwest::async_http_client,
            )
            .await
            .map_err(|e| {
                MyError::OidcDiscovery(format!(
                    "Failed to query OIDC provider: error={e} issuer_url={:?}",
                    issuer_url
                ))
            })?,
        ));

        let redirect_url = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| MyError::OidcDiscovery(format!("Invalid OIDC redirect URI: {}", e)))?;

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(client_id.to_string()),
            redirect_uri: redirect_url,
            db,
        })
    }

    /// Generate authorization URL with PKCE challenge
    /// Returns (auth_url, csrf_token/state)
    pub async fn generate_auth_url(&self) -> Result<(String, String), MyError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let provider_metadata = self.provider_metadata.read().await.clone();
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

        self.db
            .store_pkce_state(
                csrf_token.secret(),
                pkce_verifier.secret(),
                nonce.secret(),
                pkce_challenge.as_str(),
                self.redirect_uri.as_str(),
                expires_at,
            )
            .await?;

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Exchange authorization code for tokens and validate
    /// Returns (user_email, user_subject)
    pub async fn exchange_code(
        &self,
        code: &str,
        state: &str,
    ) -> Result<(String, String), MyError> {
        // Retrieve PKCE state from database
        let pkce_state = self
            .db
            .get_pkce_state(state)
            .await?
            .ok_or(MyError::OidcStateParameterExpired)?;

        // Check if expired
        if pkce_state.expires_at < chrono::Utc::now().naive_utc() {
            self.db.delete_pkce_state(state).await?;
            return Err(MyError::OidcStateParameterExpired);
        }

        let provider_metadata = self.provider_metadata.read().await.clone();
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
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(openidconnect::reqwest::async_http_client)
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
