use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse},
};

/// An Ed25519 public key is 32 bytes, which is 43 unpadded base64url characters.
const ED25519_X_LEN: usize = 43;

/// Turns a JWK into a verifier for `algorithm`, if the key is actually meant for
/// that job.
///
/// `DecodingKey::from_jwk` believes whatever the JWK says, and `jsonwebtoken`'s
/// EdDSA verifier slices the key bytes to 32 without checking the length first,
/// so a short `x` from a hostile or broken key set would panic the process.
/// Everything the key set declares about itself is checked here instead.
pub fn verifier_for(jwk: &Jwk, algorithm: Algorithm) -> Option<DecodingKey> {
    if jwk.common.public_key_use.as_ref().is_some_and(|key_use| *key_use != PublicKeyUse::Signature) {
        return None;
    }
    // A key that names its own algorithm may only be used for that one.
    if let Some(declared) = jwk.common.key_algorithm
        && declared.to_string() != format!("{algorithm:?}")
    {
        return None;
    }

    // The key type has to be the one the algorithm actually uses. Without this,
    // an RSA key could be handed to an EdDSA verifier and vice versa.
    match (&jwk.algorithm, algorithm) {
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        ) => {}
        (AlgorithmParameters::EllipticCurve(_), Algorithm::ES256 | Algorithm::ES384) => {}
        (AlgorithmParameters::OctetKeyPair(key), Algorithm::EdDSA) => {
            if key.curve != EllipticCurve::Ed25519 || key.x.len() != ED25519_X_LEN {
                return None;
            }
        }
        // A shared secret is never a public verification key, and neither
        // receiver verifies anything symmetric.
        _ => return None,
    }

    DecodingKey::from_jwk(jwk).ok()
}

/// The key a `kid` names, or the only usable signing key when the token names
/// none. An unknown `kid` is `None`, never "try them all".
pub fn select(jwks: &JwkSet, kid: Option<&str>, algorithm: Algorithm) -> Option<DecodingKey> {
    match kid {
        Some(kid) => verifier_for(jwks.find(kid)?, algorithm),
        None => {
            let mut usable = jwks.keys.iter().filter_map(|jwk| verifier_for(jwk, algorithm));
            let only = usable.next()?;
            usable.next().is_none().then_some(only)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn jwks(keys: serde_json::Value) -> JwkSet {
        serde_json::from_value(json!({ "keys": keys })).expect("valid jwks")
    }

    fn ed25519(extra: serde_json::Value) -> serde_json::Value {
        let mut key = json!({ "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": ED25519_PUBLIC_X });
        let target = key.as_object_mut().unwrap();
        for (name, value) in extra.as_object().cloned().unwrap_or_default() {
            target.insert(name, value);
        }
        key
    }

    #[test]
    fn accepts_a_signing_key_that_matches_the_algorithm() {
        let declared = jwks(json!([ed25519(json!({ "use": "sig", "alg": "EdDSA" }))]));
        assert!(select(&declared, Some("k1"), Algorithm::EdDSA).is_some());
        // No `use` and no `alg` is the common case and stays acceptable.
        let bare = jwks(json!([ed25519(json!({}))]));
        assert!(select(&bare, Some("k1"), Algorithm::EdDSA).is_some());
    }

    #[test]
    fn refuses_a_key_meant_for_something_else() {
        // An encryption key is not a verification key, even with the right kid.
        let encryption = jwks(json!([ed25519(json!({ "use": "enc" }))]));
        assert!(select(&encryption, Some("k1"), Algorithm::EdDSA).is_none());

        // A key pinned to another algorithm cannot be borrowed for this one.
        let pinned = jwks(json!([ed25519(json!({ "alg": "RS256" }))]));
        assert!(select(&pinned, Some("k1"), Algorithm::EdDSA).is_none());

        // A P-256 key is an elliptic curve key, not an Ed25519 one.
        let wrong_curve = jwks(json!([{
            "kty": "EC", "crv": "P-256", "kid": "k1",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }]));
        assert!(select(&wrong_curve, Some("k1"), Algorithm::EdDSA).is_none());

        // A symmetric secret published in a JWKS is never a verification key.
        let symmetric = jwks(json!([{ "kty": "oct", "kid": "k1", "k": "c2VjcmV0" }]));
        assert!(select(&symmetric, Some("k1"), Algorithm::HS256).is_none());
    }

    #[test]
    fn refuses_a_malformed_ed25519_key() {
        // `jsonwebtoken` slices the key bytes to 32 without checking, which
        // would abort the process rather than return an error.
        let truncated = jwks(json!([{ "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "AA" }]));
        assert!(select(&truncated, Some("k1"), Algorithm::EdDSA).is_none());
    }

    #[test]
    fn an_unknown_kid_matches_nothing() {
        let keys = jwks(json!([ed25519(json!({}))]));
        assert!(select(&keys, Some("some-other-key"), Algorithm::EdDSA).is_none());
        // One usable key and no `kid` is unambiguous.
        assert!(select(&keys, None, Algorithm::EdDSA).is_some());
    }

    #[test]
    fn several_keys_and_no_kid_is_ambiguous() {
        let two = jwks(json!([ed25519(json!({ "kid": "k1" })), ed25519(json!({ "kid": "k2" })),]));
        assert!(select(&two, None, Algorithm::EdDSA).is_none());

        // Unless only one of them could have signed it.
        let mixed = jwks(json!([ed25519(json!({ "kid": "k1" })), ed25519(json!({ "kid": "k2", "use": "enc" })),]));
        assert!(select(&mixed, None, Algorithm::EdDSA).is_some());
    }
}
