use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use oauth2::{AuthType, EndpointMaybeSet, EndpointNotSet, EndpointSet};
use openidconnect::{
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, IdTokenFields, IssuerUrl, JsonWebKeySet, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, StandardErrorResponse, StandardTokenResponse, TokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClientAuthMethod, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreProviderMetadata, CoreResponseType, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use serde::{Deserialize, Serialize};

use crate::config::ProviderConfig;

use super::{ExternalIdentity, http};

/// The claims liwan reads beyond the standard set. `extra` keeps the rest of the
/// token so the group claim can be read under whatever name the IdP uses.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ProviderClaims {
    /// Google's Workspace domain.
    #[serde(default)]
    hd: Option<String>,
    /// Microsoft's tenant.
    #[serde(default)]
    tid: Option<String>,
    /// The IdP's session id, for back-channel logout.
    #[serde(default)]
    sid: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl AdditionalClaims for ProviderClaims {}

type ProviderIdTokenFields = IdTokenFields<
    ProviderClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;
type ProviderTokenResponse = StandardTokenResponse<ProviderIdTokenFields, CoreTokenType>;
type ProviderClient = Client<
    ProviderClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    ProviderTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub(super) struct FlowSecret {
    nonce: Nonce,
    verifier: PkceCodeVerifier,
}

impl FlowSecret {
    #[cfg(any(test, feature = "__dev"))]
    pub(super) fn nonce_secret(&self) -> String {
        self.nonce.secret().clone()
    }
}

pub(super) struct Authorization {
    pub(super) url: url::Url,
    pub(super) state: String,
    pub(super) secret: FlowSecret,
}

pub(super) struct Provider {
    client: ProviderClient,
    provider_key: String,
    scopes: Vec<String>,
    groups_claim: Option<String>,
    allow_session_reuse: bool,
    /// The signing keys and algorithms discovery advertised, kept for
    /// back-channel logout tokens. `openidconnect` verifies ID tokens itself but
    /// has no logout-token path, and its JWT types are not public.
    jwks: jsonwebtoken::jwk::JwkSet,
    signing_algorithms: Vec<jsonwebtoken::Algorithm>,
}

impl Provider {
    pub(super) async fn from_config(
        config: &ProviderConfig,
        redirect_url: &str,
        client: &reqwest::Client,
    ) -> Result<Self> {
        let issuer = config.issuer_url()?;
        validate_issuer(&issuer)?;
        let issuer = IssuerUrl::new(issuer)?;
        let metadata = discover(issuer, client).await?;
        let provider_key = metadata.issuer().to_string();
        let jwks = reencode_jwks(metadata.jwks())?;
        let signing_algorithms = metadata
            .id_token_signing_alg_values_supported()
            .iter()
            .filter_map(|algorithm| {
                // The JSON name is the wire name ("RS256", "EdDSA", ...).
                serde_json::to_value(algorithm).ok()?.as_str()?.parse::<jsonwebtoken::Algorithm>().ok()
            })
            .collect::<Vec<_>>();
        let auth_type = token_auth_type(metadata.token_endpoint_auth_methods_supported())?;
        let oidc_client = ProviderClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_auth_type(auth_type)
        .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

        Ok(Self {
            client: oidc_client,
            provider_key,
            scopes: config.effective_scopes(),
            groups_claim: config.groups.as_ref().map(|groups| groups.claim.clone()),
            allow_session_reuse: config.allow_session_reuse,
            jwks,
            signing_algorithms,
        })
    }

    pub(super) fn jwks(&self) -> &jsonwebtoken::jwk::JwkSet {
        &self.jwks
    }

    pub(super) fn signing_algorithms(&self) -> &[jsonwebtoken::Algorithm] {
        &self.signing_algorithms
    }

    /// The issuer discovery reported. Identities are keyed on it rather than on
    /// the config name, so a provider can be renamed without breaking links.
    pub(super) fn provider_key(&self) -> &str {
        &self.provider_key
    }

    pub(super) fn authorize(&self) -> Authorization {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = self
            .client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            // `openid` is implied by the flow and the crate adds it itself.
            if scope != "openid" {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        let request = if self.allow_session_reuse { request } else { request.add_prompt(CoreAuthPrompt::Login) };
        let (url, state, nonce) = request.url();
        Authorization { url, state: state.secret().clone(), secret: FlowSecret { nonce, verifier } }
    }

    pub(super) async fn complete(
        &self,
        code: String,
        secret: FlowSecret,
        http_client: &reqwest::Client,
    ) -> Result<ExternalIdentity> {
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(secret.verifier)
            .request_async(&|request| http::execute(http_client.clone(), request))
            .await?;
        let id_token = token.id_token().context("provider did not return an ID token")?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &secret.nonce)?;
        let additional = claims.additional_claims();

        // An unverified address is attacker-controlled; it must never reach the
        // domain check or a username.
        let email = match (claims.email(), claims.email_verified()) {
            (Some(email), Some(true)) => Some(email.as_str().to_string()),
            _ => None,
        };

        Ok(ExternalIdentity {
            provider_key: self.provider_key.clone(),
            subject: claims.subject().as_str().to_string(),
            email,
            preferred_username: claims.preferred_username().map(|value| value.as_str().to_string()),
            name: claims.name().and_then(|name| name.get(None)).map(|value| value.as_str().to_string()),
            hd: additional.hd.clone(),
            tid: additional.tid.clone(),
            sid: additional.sid.clone(),
            groups: self.groups_claim.as_deref().and_then(|claim| read_groups(&additional.extra, claim)),
        })
    }
}

/// Both crates model RFC 7517, so the key set round-trips through its own JSON.
/// `openidconnect` keeps its JWT types private, so logout tokens are verified
/// with `jsonwebtoken` instead.
fn reencode_jwks(jwks: &JsonWebKeySet<CoreJsonWebKey>) -> Result<jsonwebtoken::jwk::JwkSet> {
    let json = serde_json::to_value(jwks)?;
    // A key type `jsonwebtoken` cannot represent is dropped rather than fatal:
    // it would only ever have been unusable for a logout token anyway.
    let keys = json
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map(|keys| keys.iter().filter_map(|key| serde_json::from_value(key.clone()).ok()).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(jsonwebtoken::jwk::JwkSet { keys })
}

/// An absent claim is `None`; a present one is its string members, with anything
/// else dropped. A lone string is accepted as a one-element list.
fn read_groups(claims: &serde_json::Map<String, serde_json::Value>, claim: &str) -> Option<Vec<String>> {
    match claims.get(claim)? {
        serde_json::Value::Array(values) => {
            Some(values.iter().filter_map(|value| value.as_str().map(str::to_string)).collect())
        }
        serde_json::Value::String(value) => Some(vec![value.clone()]),
        _ => None,
    }
}

async fn discover(issuer: IssuerUrl, client: &reqwest::Client) -> Result<CoreProviderMetadata> {
    // The crate's URL join drops the final segment from path-based issuers such as Keycloak and Microsoft.
    let mut discovery_url = issuer.url().clone();
    let path = format!("{}/.well-known/openid-configuration", discovery_url.path().trim_end_matches('/'));
    discovery_url.set_path(&path);

    let response = http::execute(
        client.clone(),
        ::http::Request::builder()
            .uri(discovery_url.as_str())
            .header(::http::header::ACCEPT, "application/json")
            .body(Vec::new())?,
    )
    .await?;
    if !response.status().is_success() {
        bail!("OIDC discovery failed with status {}", response.status());
    }
    let metadata: CoreProviderMetadata = serde_json::from_slice(response.body())?;
    if metadata.issuer() != &issuer {
        bail!("OIDC discovery issuer does not match the configured issuer");
    }
    validate_server_endpoint(metadata.authorization_endpoint().url(), metadata.issuer())?;
    validate_server_endpoint(metadata.jwks_uri().url(), metadata.issuer())?;
    validate_server_endpoint(
        metadata.token_endpoint().context("provider has no token endpoint")?.url(),
        metadata.issuer(),
    )?;
    let jwks =
        JsonWebKeySet::fetch_async(metadata.jwks_uri(), &|request| http::execute(client.clone(), request)).await?;
    Ok(metadata.set_jwks(jwks))
}

fn validate_server_endpoint(endpoint: &url::Url, issuer: &IssuerUrl) -> Result<()> {
    if endpoint.host_str().and_then(|host| host.parse::<IpAddr>().ok()).is_some_and(is_private_ip)
        && endpoint.host_str() != issuer.url().host_str()
    {
        bail!("OIDC provider endpoint cannot target a private IP address");
    }
    if endpoint.scheme() != "https" {
        // Both ends have to be on this machine: an http endpoint advertised by a
        // loopback issuer is local development, one advertised by a remote
        // issuer is a downgrade.
        if !(endpoint.scheme() == "http" && is_loopback(endpoint) && is_loopback(issuer.url())) {
            bail!("OIDC provider endpoint must use HTTPS");
        }
    }
    Ok(())
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => crate::config::resolves_to_loopback(host, url.port().unwrap_or(80)),
        None => false,
    }
}

fn is_private_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => address.is_loopback() || address.is_unspecified() || address.is_unique_local(),
    }
}

fn token_auth_type(methods: Option<&Vec<CoreClientAuthMethod>>) -> Result<AuthType> {
    match methods {
        None => Ok(AuthType::BasicAuth),
        Some(methods) if methods.contains(&CoreClientAuthMethod::ClientSecretBasic) => Ok(AuthType::BasicAuth),
        Some(methods) if methods.contains(&CoreClientAuthMethod::ClientSecretPost) => Ok(AuthType::RequestBody),
        _ => bail!("provider does not support client secret authentication"),
    }
}

fn validate_issuer(issuer: &str) -> Result<()> {
    let url = url::Url::parse(issuer)?;
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback(&url)) {
        bail!("OIDC issuer must use HTTPS");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("OIDC issuer cannot contain a query or fragment");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_token_auth_methods() {
        assert!(matches!(token_auth_type(None).unwrap(), AuthType::BasicAuth));
        let post = vec![CoreClientAuthMethod::ClientSecretPost];
        assert!(matches!(token_auth_type(Some(&post)).unwrap(), AuthType::RequestBody));
        let private_key = vec![CoreClientAuthMethod::PrivateKeyJwt];
        assert!(token_auth_type(Some(&private_key)).is_err());
    }

    #[test]
    fn reads_the_group_claim_under_its_configured_name() {
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_value(serde_json::json!({
            "groups": ["analytics", 7, "ops"],
            "roles": "admin",
            "teams": 3,
        }))
        .unwrap();

        assert_eq!(read_groups(&claims, "groups"), Some(vec!["analytics".to_string(), "ops".to_string()]));
        assert_eq!(read_groups(&claims, "roles"), Some(vec!["admin".to_string()]));
        assert_eq!(read_groups(&claims, "teams"), None, "a number is not a group list");
        assert_eq!(read_groups(&claims, "absent"), None);
    }

    #[test]
    fn issuer_must_be_https_outside_loopback() {
        assert!(validate_issuer("https://idp.example.com").is_ok());
        assert!(validate_issuer("http://localhost:4444").is_ok());
        assert!(validate_issuer("http://127.0.0.1:4444").is_ok());
        assert!(validate_issuer("http://idp.example.com").is_err());
        assert!(validate_issuer("https://idp.example.com/?a=b").is_err());
    }

    #[test]
    fn an_http_endpoint_needs_a_loopback_issuer_too() {
        let loopback = IssuerUrl::new("http://127.0.0.1:4444".to_string()).unwrap();
        let remote = IssuerUrl::new("https://idp.example.com".to_string()).unwrap();

        assert!(validate_server_endpoint(&url::Url::parse("http://127.0.0.1:4444/token").unwrap(), &loopback).is_ok());
        assert!(validate_server_endpoint(&url::Url::parse("https://idp.example.com/token").unwrap(), &remote).is_ok());

        // A real issuer that hands out a plaintext endpoint is a downgrade.
        assert!(validate_server_endpoint(&url::Url::parse("http://idp.example.com/token").unwrap(), &remote).is_err());
        // And one that points into the local network is an SSRF attempt.
        assert!(validate_server_endpoint(&url::Url::parse("https://10.0.0.5/token").unwrap(), &remote).is_err());
    }
}
