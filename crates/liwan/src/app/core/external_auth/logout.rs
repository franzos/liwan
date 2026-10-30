use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::forseti::WebhookError;

/// OpenID Connect Back-Channel Logout 1.0, section 2.4.
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// A logout token is minted and delivered right away; anything older is a replay.
const MAX_IAT_SKEW: i64 = 60;
/// A logout token is a few hundred bytes; anything larger is not one.
pub const MAX_LOGOUT_BODY: usize = 16 * 1024;

fn invalid(reason: impl Into<String>) -> WebhookError {
    WebhookError::Invalid(reason.into())
}

/// What the IdP asked us to end: one device (`sid`), or every session the
/// subject has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    /// Empty when the token carried no `jti`; the caller dedupes on the token.
    pub jti: String,
    pub sid: Option<String>,
    pub sub: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutClaims {
    iss: String,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    iat: i64,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    events: HashMap<String, serde_json::Value>,
    /// Its presence means an ID token is being replayed as a logout token.
    #[serde(default)]
    nonce: Option<serde_json::Value>,
}

/// The algorithm and `kid` a token asks to be verified with, checked against the
/// set the provider advertises. Neither is trusted for anything but a lookup.
pub fn token_header(token: &str, advertised: &[Algorithm]) -> Result<(Algorithm, Option<String>), WebhookError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("malformed logout token header"))?;
    // `none` never parses into `Algorithm`, so an unsigned token dies here.
    if !advertised.contains(&header.alg) {
        return Err(invalid("logout token algorithm is not one the provider advertises"));
    }
    Ok((header.alg, header.kid))
}

/// Verifies a back-channel logout token against the provider's own signing keys.
/// `algorithm` is the one the token named, already checked against what the
/// provider advertises; `now` is a unix timestamp, so tests can move it.
pub fn verify_logout_token(
    token: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
    issuer: &str,
    client_id: &str,
    now: i64,
) -> Result<LogoutRequest, WebhookError> {
    // One algorithm, not the whole advertised list: `jsonwebtoken` refuses the
    // token if *any* entry belongs to a different family than the key, so an IdP
    // that advertises a mixed set would never verify at all. The token's own
    // algorithm was checked against that set in `token_header`.
    let mut validation = Validation::new(algorithm);
    // `iss`, `aud`, `iat` and `exp` are all checked below against the configured
    // values, so the error says which one failed.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let claims = jsonwebtoken::decode::<LogoutClaims>(token, key, &validation)
        .map_err(|error| invalid(format!("logout token signature or claims are invalid: {error}")))?
        .claims;

    if claims.iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(invalid("logout token issuer does not match the provider"));
    }
    if !audience_contains(claims.aud.as_ref(), client_id) {
        return Err(invalid("logout token audience does not contain the client id"));
    }
    if (now - claims.iat).abs() > MAX_IAT_SKEW {
        return Err(invalid("logout token iat is outside the accepted window"));
    }
    // The final spec lists `exp` as a logout token claim; honour it when it is there.
    if claims.exp.is_some_and(|exp| exp <= now) {
        return Err(invalid("logout token has expired"));
    }
    if claims.nonce.is_some() {
        return Err(invalid("logout token carries a nonce"));
    }
    if !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
        return Err(invalid("logout token carries no back-channel logout event"));
    }

    let sid = claims.sid.filter(|sid| !sid.is_empty());
    let sub = claims.sub.filter(|sub| !sub.is_empty());
    if sid.is_none() && sub.is_none() {
        return Err(invalid("logout token has neither sub nor sid"));
    }

    Ok(LogoutRequest { jti: claims.jti.unwrap_or_default(), sid, sub })
}

fn audience_contains(aud: Option<&serde_json::Value>, client_id: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == client_id,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str().is_some_and(|value| value == client_id))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::core::external_auth::keys;
    use jsonwebtoken::{EncodingKey, Header, jwk::JwkSet};
    use serde_json::json;

    const ISSUER: &str = "https://idp.example.com";
    const CLIENT_ID: &str = "liwan";
    const KID: &str = "test-key";
    const NOW: i64 = 1_747_824_225;

    /// RFC 8032's first Ed25519 test vector. The real thing is usually RS256,
    /// but the code path is the same and this keeps the fixture to two lines.
    const ED25519_PKCS8_DER: &str =
        "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": KID, "x": ED25519_PUBLIC_X, "alg": "EdDSA", "use": "sig" }]
        }))
        .expect("valid test jwks")
    }

    /// A realistic IdP advertises several, spanning key families.
    fn advertised() -> Vec<Algorithm> {
        vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
    }

    fn sign(claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_string());
        let key = EncodingKey::from_ed_der(&hex::decode(ED25519_PKCS8_DER).expect("test key is valid hex"));
        jsonwebtoken::encode(&header, &claims, &key).expect("signed token")
    }

    fn logout_claims() -> serde_json::Value {
        json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": NOW,
            "jti": "logout-1",
            "sid": "idp-session-1",
            "sub": "sub-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
        })
    }

    fn verify(claims: serde_json::Value) -> Result<LogoutRequest, WebhookError> {
        verify_token(&sign(claims))
    }

    fn verify_token(token: &str) -> Result<LogoutRequest, WebhookError> {
        let (algorithm, kid) = token_header(token, &advertised())?;
        let key = keys::select(&jwks(), kid.as_deref(), algorithm).expect("test key");
        verify_logout_token(token, &key, algorithm, ISSUER, CLIENT_ID, NOW)
    }

    #[test]
    fn accepts_a_valid_logout_token() {
        let request = verify(logout_claims()).expect("valid token");
        assert_eq!(request.sid.as_deref(), Some("idp-session-1"));
        assert_eq!(request.sub.as_deref(), Some("sub-1"));
        assert_eq!(request.jti, "logout-1");
    }

    #[test]
    fn accepts_either_identifier_on_its_own() {
        let mut only_sid = logout_claims();
        only_sid.as_object_mut().unwrap().remove("sub");
        assert_eq!(verify(only_sid).unwrap().sub, None);

        let mut only_sub = logout_claims();
        only_sub.as_object_mut().unwrap().remove("sid");
        assert_eq!(verify(only_sub).unwrap().sid, None);

        let mut neither = logout_claims();
        neither.as_object_mut().unwrap().remove("sid");
        neither.as_object_mut().unwrap().remove("sub");
        assert!(verify(neither).unwrap_err().to_string().contains("neither sub nor sid"));

        // An empty string is not an identifier.
        let mut empty = logout_claims();
        empty["sid"] = json!("");
        empty["sub"] = json!("");
        assert!(verify(empty).unwrap_err().to_string().contains("neither sub nor sid"));
    }

    #[test]
    fn verifies_against_an_idp_that_advertises_several_algorithms() {
        // Keycloak, Authentik and Zitadel all advertise a mixed list. Passing
        // that whole list to `jsonwebtoken` makes every token fail its family
        // check, which would leave back-channel logout quietly broken.
        assert!(advertised().len() > 1 && advertised().contains(&Algorithm::RS256));
        assert!(verify(logout_claims()).is_ok());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let token = sign(logout_claims());
        let tampered = format!("{}x", &token[..token.len() - 1]);
        let error = verify_token(&tampered).unwrap_err();
        assert!(error.to_string().contains("signature"), "got: {error}");
    }

    #[test]
    fn rejects_an_algorithm_the_provider_does_not_advertise() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let forged =
            jsonwebtoken::encode(&header, &logout_claims(), &EncodingKey::from_secret(b"guessed")).expect("token");
        let error = token_header(&forged, &[Algorithm::EdDSA]).unwrap_err();
        assert!(error.to_string().contains("algorithm"), "got: {error}");

        // Even when the IdP does advertise HS256, its key set holds no HMAC key
        // to verify one with.
        let (algorithm, kid) = token_header(&forged, &advertised_with_hs256()).expect("header is well formed");
        assert!(keys::select(&jwks(), kid.as_deref(), algorithm).is_none());

        // `none` does not even parse as an algorithm, so it cannot get further.
        let unsigned = format!(
            "{}.{}.",
            base64_url(br#"{"alg":"none","typ":"JWT"}"#),
            base64_url(logout_claims().to_string().as_bytes())
        );
        assert!(token_header(&unsigned, &advertised()).is_err());
    }

    fn advertised_with_hs256() -> Vec<Algorithm> {
        vec![Algorithm::HS256, Algorithm::RS256, Algorithm::EdDSA]
    }

    #[test]
    fn rejects_the_wrong_issuer_audience_or_age() {
        let mut wrong_issuer = logout_claims();
        wrong_issuer["iss"] = json!("https://evil.example");
        assert!(verify(wrong_issuer).unwrap_err().to_string().contains("issuer"));

        let mut wrong_audience = logout_claims();
        wrong_audience["aud"] = json!("someone-else");
        assert!(verify(wrong_audience).unwrap_err().to_string().contains("audience"));

        let mut stale = logout_claims();
        stale["iat"] = json!(NOW - 61);
        assert!(verify(stale).unwrap_err().to_string().contains("iat"));

        let mut from_the_future = logout_claims();
        from_the_future["iat"] = json!(NOW + 61);
        assert!(verify(from_the_future).unwrap_err().to_string().contains("iat"));

        let mut expired = logout_claims();
        expired["exp"] = json!(NOW - 1);
        assert!(verify(expired).unwrap_err().to_string().contains("expired"));

        // An `exp` still in the future is fine, and a missing one is too.
        let mut valid_exp = logout_claims();
        valid_exp["exp"] = json!(NOW + 60);
        assert!(verify(valid_exp).is_ok());

        // A trailing slash on the issuer is not a different issuer.
        let mut slashed = logout_claims();
        slashed["iss"] = json!(format!("{ISSUER}/"));
        assert!(verify(slashed).is_ok());
    }

    #[test]
    fn rejects_an_id_token_replayed_as_a_logout_token() {
        let mut with_nonce = logout_claims();
        with_nonce["nonce"] = json!("n-0S6_WzA2Mj");
        assert!(verify(with_nonce).unwrap_err().to_string().contains("nonce"));

        let mut no_event = logout_claims();
        no_event["events"] = json!({ "http://schemas.openid.net/event/some-other-thing": {} });
        assert!(verify(no_event).unwrap_err().to_string().contains("back-channel logout event"));
    }

    fn base64_url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for index in 0..chunk.len() + 1 {
                out.push(ALPHABET[(n >> (18 - 6 * index)) as usize & 0x3f] as char);
            }
        }
        out
    }
}
