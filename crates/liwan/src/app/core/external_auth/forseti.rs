use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;

use super::{http, keys};

/// The RISC event Forseti sends when a user deletes their account.
const ACCOUNT_PURGED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
/// RFC 8417's media type and `typ`.
pub const SET_CONTENT_TYPE: &str = "application/secevent+jwt";
/// A security event token is a few hundred bytes; anything larger is not one.
pub const MAX_WEBHOOK_BODY: usize = 16 * 1024;
/// How far the token's `iat` may be from now, in either direction.
const MAX_IAT_SKEW: i64 = 300;
/// Forseti retries a delivery for up to 72 hours, so remember it for that long.
const JTI_LIFETIME: Duration = Duration::from_secs(72 * 60 * 60);
/// Dedupe entries are tiny, but the cache must not grow without bound.
const MAX_JTI_ENTRIES: usize = 10_000;

/// The Forseti-specific surfaces, served next to Hydra's OIDC discovery.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ForsetiConfiguration {
    #[serde(default)]
    pub account_management_uri: Option<String>,
    #[serde(default)]
    pub handoff_endpoint: Option<String>,
    #[serde(default)]
    pub handoff_actions_supported: Vec<String>,
    #[serde(default)]
    pub webhook_jwks_uri: Option<String>,
    #[serde(default)]
    pub webhook_events_supported: Vec<String>,
}

/// Fetches `<portal_url>/.well-known/forseti-configuration`.
pub async fn fetch(portal_url: &str, client: &reqwest::Client) -> Result<ForsetiConfiguration> {
    let url = format!("{}/.well-known/forseti-configuration", portal_url.trim_end_matches('/'));
    let response = http::execute(
        client.clone(),
        ::http::Request::builder().uri(&url).header(::http::header::ACCEPT, "application/json").body(Vec::new())?,
    )
    .await?;
    if !response.status().is_success() {
        bail!("Forseti discovery failed with status {}", response.status());
    }
    Ok(serde_json::from_slice(response.body())?)
}

/// Where to send someone to manage their own account. Prefers the handoff
/// endpoint, which lands them on the right page with a way back here.
pub fn manage_url(config: &ForsetiConfiguration, client_id: &str, base_url: &str) -> Option<String> {
    if let Some(handoff) = config.handoff_endpoint.as_deref().and_then(web_url)
        && config.handoff_actions_supported.iter().any(|action| action == "profile")
    {
        let mut url = handoff;
        url.query_pairs_mut()
            .append_pair("referrer", client_id)
            .append_pair("referrer_uri", &format!("{}/settings/me", base_url.trim_end_matches('/')))
            .append_pair("action", "profile");
        return Some(url.to_string());
    }
    config.account_management_uri.as_deref().and_then(web_url).map(|url| url.to_string())
}

/// The dashboard renders this as a link, so a `javascript:` URL out of the
/// portal's document would be script execution on a signed-in page.
fn web_url(value: &str) -> Option<url::Url> {
    let url = url::Url::parse(value).ok()?;
    let loopback = url.host_str().is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    (url.scheme() == "https" || (url.scheme() == "http" && loopback)).then_some(url)
}

/// How often an unknown `kid` may trigger a refetch. Without it, anyone who can
/// reach the webhook can make liwan hammer the portal one request for one.
const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Forseti's webhook signing keys, cached by `kid` as the integration guide asks.
#[derive(Default)]
pub struct WebhookJwks {
    state: Mutex<Option<(JwkSet, Instant)>>,
}

impl WebhookJwks {
    /// The key for `kid`, refetching when it is not in the cache. Forseti
    /// rotates by dropping a new key in, so a miss means "fetch", not "reject" —
    /// but no more often than [`JWKS_REFETCH_INTERVAL`].
    pub async fn key_for(&self, kid: &str, jwks_uri: &str, client: &reqwest::Client) -> Result<DecodingKey> {
        if let Some(key) = self.cached(kid) {
            return Ok(key);
        }
        if !self.may_refetch() {
            bail!("Forseti webhook JWKS has no key {kid}");
        }

        let response = http::execute(
            client.clone(),
            ::http::Request::builder()
                .uri(jwks_uri)
                .header(::http::header::ACCEPT, "application/json")
                .body(Vec::new())?,
        )
        .await?;
        if !response.status().is_success() {
            bail!("Forseti webhook JWKS fetch failed with status {}", response.status());
        }
        let jwks: JwkSet = serde_json::from_slice(response.body())?;
        *self.state.lock().expect("forseti jwks lock poisoned") = Some((jwks, Instant::now()));

        self.cached(kid).with_context(|| format!("Forseti webhook JWKS has no key {kid}"))
    }

    fn cached(&self, kid: &str) -> Option<DecodingKey> {
        let state = self.state.lock().expect("forseti jwks lock poisoned");
        let (jwks, _) = state.as_ref()?;
        keys::select(jwks, Some(kid), Algorithm::EdDSA)
    }

    fn may_refetch(&self) -> bool {
        let state = self.state.lock().expect("forseti jwks lock poisoned");
        state.as_ref().is_none_or(|(_, fetched_at)| fetched_at.elapsed() >= JWKS_REFETCH_INTERVAL)
    }
}

/// The key set signs account deletions, so it has to be as trustworthy as the
/// portal itself: same origin, and over the same transport the portal was
/// validated on. Everything else in the document is advisory; this is not.
pub fn validate_jwks_uri(jwks_uri: &str, portal_url: &str) -> Result<()> {
    let jwks = url::Url::parse(jwks_uri).context("Forseti webhook_jwks_uri is not a URL")?;
    let portal = url::Url::parse(portal_url).context("Forseti portal_url is not a URL")?;
    if jwks.origin() != portal.origin() {
        bail!("Forseti webhook_jwks_uri must share an origin with portal_url");
    }
    Ok(())
}

/// What a valid `account-purged` token told us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPurged {
    pub jti: String,
    pub subject: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// Every rejection is one 400 without a body; the reason stays in the log.
    Invalid(String),
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for WebhookError {}

fn invalid(reason: impl Into<String>) -> WebhookError {
    WebhookError::Invalid(reason.into())
}

#[derive(Debug, Deserialize)]
struct SetClaims {
    iss: String,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    iat: i64,
    jti: String,
    #[serde(default)]
    events: HashMap<String, SetEvent>,
}

#[derive(Debug, Deserialize)]
struct SetEvent {
    #[serde(default)]
    subject: Option<SetSubject>,
}

#[derive(Debug, Deserialize)]
struct SetSubject {
    #[serde(default)]
    subject_type: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

/// The `kid` a token asks to be verified with. Read before verification, so it
/// is not to be trusted for anything but a cache lookup.
pub fn token_kid(token: &str) -> Result<String, WebhookError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("malformed token header"))?;
    if header.alg != Algorithm::EdDSA {
        return Err(invalid("token is not signed with EdDSA"));
    }
    if header.typ.as_deref() != Some(SET_CONTENT_TYPE) {
        return Err(invalid("token typ is not secevent+jwt"));
    }
    header.kid.ok_or_else(|| invalid("token header has no kid"))
}

/// Verifies an `account-purged` security event token against `portal_url` and
/// `client_id`. `now` is a unix timestamp, so tests can move it.
pub fn verify_account_purged(
    token: &str,
    key: &DecodingKey,
    portal_url: &str,
    client_id: &str,
    now: i64,
) -> Result<AccountPurged, WebhookError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    // `iss`, `aud` and `iat` are checked below against the configured values
    // rather than by the library, so the error says which one failed.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let token = jsonwebtoken::decode::<SetClaims>(token, key, &validation)
        .map_err(|error| invalid(format!("signature or claims are invalid: {error}")))?;
    let claims = token.claims;

    if !same_url(&claims.iss, portal_url) {
        return Err(invalid("token issuer does not match the configured portal"));
    }
    if !audience_contains(claims.aud.as_ref(), client_id) {
        return Err(invalid("token audience does not contain the client id"));
    }
    if (now - claims.iat).abs() > MAX_IAT_SKEW {
        return Err(invalid("token iat is outside the accepted window"));
    }

    let event = claims.events.get(ACCOUNT_PURGED).ok_or_else(|| invalid("token carries no account-purged event"))?;
    let subject = event.subject.as_ref().ok_or_else(|| invalid("account-purged event has no subject"))?;
    if subject.subject_type.as_deref() != Some("iss-sub") {
        return Err(invalid("account-purged subject is not an iss-sub identifier"));
    }
    if !subject.iss.as_deref().is_some_and(|iss| same_url(iss, portal_url)) {
        return Err(invalid("account-purged subject issuer does not match the configured portal"));
    }
    let sub = subject
        .sub
        .as_deref()
        .filter(|sub| !sub.is_empty())
        .ok_or_else(|| invalid("account-purged subject has no sub"))?;

    Ok(AccountPurged { jti: claims.jti, subject: sub.to_string() })
}

/// `aud` is a single string or an array of them.
fn audience_contains(aud: Option<&serde_json::Value>, client_id: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == client_id,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str().is_some_and(|value| value == client_id))
        }
        _ => false,
    }
}

/// Issuers differ by a trailing slash more often than they differ in substance.
fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Remembers event ids so a retried delivery is a no-op rather than a second
/// deletion. In memory: the operation is idempotent and Kratos never reuses a
/// subject, so a replay after a restart is harmless.
pub struct JtiCache {
    lifetime: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl JtiCache {
    pub fn new(lifetime: Duration) -> Self {
        Self { lifetime, seen: Mutex::new(HashMap::new()) }
    }

    /// `true` when this id is new, `false` when it has been handled already.
    pub fn insert(&self, jti: &str) -> bool {
        let mut seen = self.seen.lock().expect("jti cache lock poisoned");
        let now = Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < self.lifetime);
        if seen.len() >= MAX_JTI_ENTRIES
            && let Some(oldest) = seen.iter().min_by_key(|(_, at)| **at).map(|(jti, _)| jti.clone())
        {
            seen.remove(&oldest);
        }
        seen.insert(jti.to_string(), now).is_none()
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new(JTI_LIFETIME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    const PORTAL: &str = "https://accounts.example.com";
    const CLIENT_ID: &str = "liwan";
    const KID: &str = "test-key";

    /// RFC 8032's first Ed25519 test vector: the private key as PKCS#8 DER
    /// (`from_ed_pem` needs the `use_pem` feature, which this build leaves off)
    /// and the matching public key as a JWK `x`.
    const ED25519_PKCS8_DER: &str =
        "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": KID, "x": ED25519_PUBLIC_X, "alg": "EdDSA", "use": "sig" }]
        }))
        .expect("valid test jwks")
    }

    fn decoding_key() -> DecodingKey {
        DecodingKey::from_jwk(jwks().find(KID).expect("test key")).expect("decoding key")
    }

    fn sign(claims: serde_json::Value, typ: &str, alg: Algorithm) -> String {
        let mut header = Header::new(alg);
        header.typ = Some(typ.to_string());
        header.kid = Some(KID.to_string());
        let key = EncodingKey::from_ed_der(&hex::decode(ED25519_PKCS8_DER).expect("test key is valid hex"));
        jsonwebtoken::encode(&header, &claims, &key).expect("signed token")
    }

    fn purged_claims(now: i64) -> serde_json::Value {
        json!({
            "iss": PORTAL,
            "aud": CLIENT_ID,
            "iat": now,
            "jti": "f0c8a9e2-3b5d-4e1c-8f9a-1234567890ab",
            "events": {
                ACCOUNT_PURGED: {
                    "subject": { "subject_type": "iss-sub", "iss": PORTAL, "sub": "kratos-identity-id" }
                }
            }
        })
    }

    fn verify(claims: serde_json::Value) -> Result<AccountPurged, WebhookError> {
        let token = sign(claims, SET_CONTENT_TYPE, Algorithm::EdDSA);
        verify_account_purged(&token, &decoding_key(), PORTAL, CLIENT_ID, 1_747_824_225)
    }

    #[test]
    fn accepts_a_valid_account_purged_token() {
        let purged = verify(purged_claims(1_747_824_225)).expect("valid token");
        assert_eq!(purged.subject, "kratos-identity-id");
        assert_eq!(purged.jti, "f0c8a9e2-3b5d-4e1c-8f9a-1234567890ab");
    }

    #[test]
    fn accepts_an_audience_array_and_a_trailing_slash() {
        let mut claims = purged_claims(1_747_824_225);
        claims["aud"] = json!(["other-app", CLIENT_ID]);
        claims["iss"] = json!(format!("{PORTAL}/"));
        assert!(verify(claims).is_ok());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let token = sign(purged_claims(1_747_824_225), SET_CONTENT_TYPE, Algorithm::EdDSA);
        let tampered = format!("{}x", &token[..token.len() - 1]);
        let error = verify_account_purged(&tampered, &decoding_key(), PORTAL, CLIENT_ID, 1_747_824_225).unwrap_err();
        assert!(error.to_string().contains("signature"), "got: {error}");
    }

    #[test]
    fn rejects_the_wrong_issuer_audience_or_age() {
        let mut wrong_issuer = purged_claims(1_747_824_225);
        wrong_issuer["iss"] = json!("https://evil.example");
        assert!(verify(wrong_issuer).unwrap_err().to_string().contains("issuer"));

        let mut wrong_audience = purged_claims(1_747_824_225);
        wrong_audience["aud"] = json!("someone-else");
        assert!(verify(wrong_audience).unwrap_err().to_string().contains("audience"));

        // Both directions: a token from the future is as wrong as a stale one.
        assert!(verify(purged_claims(1_747_824_225 - 301)).unwrap_err().to_string().contains("iat"));
        assert!(verify(purged_claims(1_747_824_225 + 301)).unwrap_err().to_string().contains("iat"));
        assert!(verify(purged_claims(1_747_824_225 - 299)).is_ok());
    }

    #[test]
    fn rejects_a_malformed_event() {
        let mut no_event = purged_claims(1_747_824_225);
        no_event["events"] = json!({ "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked": {} });
        assert!(verify(no_event).unwrap_err().to_string().contains("account-purged event"));

        let mut wrong_subject_type = purged_claims(1_747_824_225);
        wrong_subject_type["events"][ACCOUNT_PURGED]["subject"]["subject_type"] = json!("email");
        assert!(verify(wrong_subject_type).unwrap_err().to_string().contains("iss-sub"));

        let mut foreign_subject_issuer = purged_claims(1_747_824_225);
        foreign_subject_issuer["events"][ACCOUNT_PURGED]["subject"]["iss"] = json!("https://evil.example");
        assert!(verify(foreign_subject_issuer).unwrap_err().to_string().contains("subject issuer"));

        let mut empty_sub = purged_claims(1_747_824_225);
        empty_sub["events"][ACCOUNT_PURGED]["subject"]["sub"] = json!("");
        assert!(verify(empty_sub).unwrap_err().to_string().contains("no sub"));
    }

    #[test]
    fn the_header_must_claim_an_eddsa_security_event_token() {
        let token = sign(purged_claims(1_747_824_225), SET_CONTENT_TYPE, Algorithm::EdDSA);
        assert_eq!(token_kid(&token).unwrap(), KID);

        let wrong_typ = sign(purged_claims(1_747_824_225), "JWT", Algorithm::EdDSA);
        assert!(token_kid(&wrong_typ).unwrap_err().to_string().contains("secevent+jwt"));

        // An HS256 token signed with a key the attacker picked must not even
        // reach key lookup.
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.typ = Some(SET_CONTENT_TYPE.to_string());
        header.kid = Some(KID.to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &purged_claims(1_747_824_225),
            &EncodingKey::from_secret(b"not-the-portal-key"),
        )
        .expect("signed token");
        assert!(token_kid(&forged).unwrap_err().to_string().contains("EdDSA"));
    }

    #[test]
    fn manage_url_prefers_the_handoff_endpoint() {
        let config = ForsetiConfiguration {
            account_management_uri: Some(format!("{PORTAL}/settings")),
            handoff_endpoint: Some(format!("{PORTAL}/handoff")),
            handoff_actions_supported: vec!["2fa".to_string(), "profile".to_string()],
            ..Default::default()
        };
        let url = manage_url(&config, CLIENT_ID, "https://liwan.example.com/").expect("manage url");
        assert!(url.starts_with(&format!("{PORTAL}/handoff?")), "got: {url}");
        assert!(url.contains("referrer=liwan"), "got: {url}");
        assert!(url.contains("referrer_uri=https%3A%2F%2Fliwan.example.com%2Fsettings%2Fme"), "got: {url}");
        assert!(url.contains("action=profile"), "got: {url}");
    }

    #[test]
    fn manage_url_falls_back_and_then_gives_up() {
        // A portal that does not offer the `profile` verb.
        let config = ForsetiConfiguration {
            account_management_uri: Some(format!("{PORTAL}/settings")),
            handoff_endpoint: Some(format!("{PORTAL}/handoff")),
            handoff_actions_supported: vec!["2fa".to_string()],
            ..Default::default()
        };
        assert_eq!(manage_url(&config, CLIENT_ID, "https://liwan.example.com"), Some(format!("{PORTAL}/settings")));

        assert_eq!(manage_url(&ForsetiConfiguration::default(), CLIENT_ID, "https://liwan.example.com"), None);
    }

    #[test]
    fn manage_url_refuses_a_script_url() {
        // The dashboard renders this as an anchor on a signed-in page.
        let config = ForsetiConfiguration {
            handoff_endpoint: Some("javascript:alert(1)".to_string()),
            handoff_actions_supported: vec!["profile".to_string()],
            account_management_uri: Some("javascript:alert(2)".to_string()),
            ..Default::default()
        };
        assert_eq!(manage_url(&config, CLIENT_ID, "https://liwan.example.com"), None);

        // http is only tolerated against loopback, for local development.
        let local = ForsetiConfiguration {
            account_management_uri: Some("http://localhost:4455/settings".to_string()),
            ..Default::default()
        };
        assert!(manage_url(&local, CLIENT_ID, "https://liwan.example.com").is_some());
        let plaintext = ForsetiConfiguration {
            account_management_uri: Some("http://accounts.example.com/settings".to_string()),
            ..Default::default()
        };
        assert_eq!(manage_url(&plaintext, CLIENT_ID, "https://liwan.example.com"), None);
    }

    #[test]
    fn the_webhook_key_set_must_come_from_the_portal_itself() {
        // Those keys are the only thing standing between a stranger and a
        // deleted account, so they are not an arbitrary URL out of a document.
        assert!(validate_jwks_uri(&format!("{PORTAL}/.well-known/webhook-jwks.json"), PORTAL).is_ok());
        assert!(validate_jwks_uri("https://evil.example/keys.json", PORTAL).is_err());
        assert!(validate_jwks_uri("http://accounts.example.com/keys.json", PORTAL).is_err());
        assert!(validate_jwks_uri("http://169.254.169.254/latest/meta-data", PORTAL).is_err());
        assert!(validate_jwks_uri("not-a-url", PORTAL).is_err());
    }

    #[test]
    fn jti_cache_dedupes_and_expires() {
        let cache = JtiCache::new(Duration::from_secs(60));
        assert!(cache.insert("first"));
        assert!(!cache.insert("first"), "a retry of the same delivery is not new");
        assert!(cache.insert("second"));

        let expired = JtiCache::new(Duration::ZERO);
        assert!(expired.insert("first"));
        assert!(expired.insert("first"), "the entry aged out before the second delivery");
    }
}
