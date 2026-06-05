use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};

use crate::app::SqlitePool;
use crate::config::OidcConfig;

/// The fully-configured client type after discovery (auth + token endpoints set).
type DiscoveredClient =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

/// Stateless OIDC relying-party client. Discovery runs per login operation, so
/// the client auto-recovers if the IdP was unreachable at boot and always uses
/// fresh signing keys. Login-only: tokens are discarded after id_token
/// verification; the local session owns auth thereafter.
#[derive(Clone)]
pub struct LiwanOidc {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    http: openidconnect::reqwest::Client,
}

pub struct LoginStart {
    pub auth_url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

pub struct VerifiedClaims {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

impl LiwanOidc {
    /// Returns `None` when OIDC is not fully configured.
    pub fn try_new(config: &OidcConfig, base_url: &str) -> Result<Option<Self>> {
        if !config.enabled() {
            return Ok(None);
        }
        // SSRF defense + timeout so a hung IdP can't wedge logins.
        let http = openidconnect::reqwest::Client::builder()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("building OIDC HTTP client")?;
        Ok(Some(Self {
            issuer: config.issuer.clone().expect("enabled implies issuer"),
            client_id: config.client_id.clone().expect("enabled implies client_id"),
            client_secret: config.client_secret.clone().expect("enabled implies client_secret"),
            redirect_uri: config.redirect_uri(base_url),
            scopes: config.scopes.clone(),
            http,
        }))
    }

    async fn build_client(&self) -> Result<DiscoveredClient> {
        let issuer_url = IssuerUrl::new(self.issuer.clone()).context("invalid issuer url")?;
        let metadata =
            CoreProviderMetadata::discover_async(issuer_url, &self.http).await.context("OIDC discovery failed")?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone()).context("invalid redirect uri")?);
        Ok(client)
    }

    pub async fn start_login(&self) -> Result<LoginStart> {
        let client = self.build_client().await?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req =
            client.authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random);
        for scope in &self.scopes {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        let (auth_url, state, nonce) = req.set_pkce_challenge(pkce_challenge).url();
        Ok(LoginStart {
            auth_url: auth_url.to_string(),
            state: state.secret().to_string(),
            nonce: nonce.secret().to_string(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        })
    }

    pub async fn finish_login(
        &self,
        code: String,
        pkce_verifier: String,
        expected_nonce: &str,
    ) -> Result<VerifiedClaims> {
        let client = self.build_client().await?;
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .context("building code exchange")?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.http)
            .await
            .context("code exchange failed at token endpoint")?;

        let id_token = token_response.id_token().context("token endpoint returned no id_token")?;
        let verifier = client.id_token_verifier();
        let nonce = Nonce::new(expected_nonce.to_string());
        let claims = id_token.claims(&verifier, &nonce).context("id_token verification failed")?;

        // Unverified emails are attacker-controlled; never trust them.
        let email = match (claims.email(), claims.email_verified()) {
            (Some(addr), Some(true)) => Some(addr.as_str().to_string()),
            _ => None,
        };
        let preferred_username = claims.preferred_username().map(|u| u.as_str().to_string());
        let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string());

        Ok(VerifiedClaims {
            issuer: claims.issuer().as_str().to_string(),
            subject: claims.subject().as_str().to_string(),
            email,
            preferred_username,
            name,
        })
    }
}

/// Short-lived authorization-code flow state (state / nonce / PKCE verifier).
#[derive(Clone)]
pub struct LiwanOidcState {
    pool: SqlitePool,
}

impl LiwanOidcState {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn create(&self, state: &str, nonce: &str, pkce_verifier: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into oidc_auth_state (state, nonce, pkce_verifier, expires_at) values (?, ?, ?, ?)",
            rusqlite::params![state, nonce, pkce_verifier, expires_at],
        )?;
        Ok(())
    }

    /// Consume the row for `state`: returns `(nonce, pkce_verifier)` if present
    /// and unexpired, then deletes it. Returns `None` otherwise. The
    /// delete-and-return is a single statement, so exactly one concurrent caller
    /// can claim a given `state` (single-use is enforced here, not just by the
    /// IdP's authorization-code reuse handling).
    pub fn take(&self, state: &str) -> Result<Option<(String, String)>> {
        use rusqlite::OptionalExtension;
        let conn = self.pool.get()?;
        let row = conn
            .query_row(
                "delete from oidc_auth_state where state = ? returning nonce, pkce_verifier, expires_at",
                [state],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, DateTime<Utc>>(2)?)),
            )
            .optional()?;
        Ok(match row {
            Some((nonce, verifier, expires_at)) if expires_at > Utc::now() => Some((nonce, verifier)),
            _ => None,
        })
    }

    pub fn cleanup_expired(&self) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute("delete from oidc_auth_state where expires_at <= ?", rusqlite::params![Utc::now()])?;
        Ok(())
    }

    /// Test-only: read the nonce for a state without consuming the row.
    #[cfg(any(test, feature = "__dev"))]
    pub fn peek_nonce(&self, state: &str) -> Option<String> {
        let conn = self.pool.get().ok()?;
        conn.query_row("select nonce from oidc_auth_state where state = ?", [state], |row| row.get::<_, String>(0)).ok()
    }
}
