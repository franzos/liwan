use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use liwan::{app::Liwan, config::ProviderConfig};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

use super::TestClient;

/// The mock IdP signs id_tokens with HS256 using the client secret (standard
/// OIDC symmetric signing), so login needs no key material at all. Its JWKS
/// carries one fixed Ed25519 key, used only for back-channel logout tokens.
pub const TEST_CLIENT_SECRET: &str = "secret";
pub const TEST_CLIENT_ID: &str = "liwan";

/// RFC 8032's first Ed25519 test vector, as PKCS#8 DER and as a JWK `x`.
const ED25519_PKCS8_DER: &str =
    "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const LOGOUT_KID: &str = "logout-key";
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

pub const STATE_COOKIE: &str = "liwan-external-auth-state";

/// What the mock IdP will say about the next person to sign in.
#[derive(Clone)]
pub struct MockIdp {
    pub issuer: String,
    pub nonce: Arc<Mutex<String>>,
    sub: Arc<Mutex<String>>,
    email: Arc<Mutex<Option<String>>>,
    email_verified: Arc<Mutex<bool>>,
    name: Arc<Mutex<Option<String>>>,
    groups: Arc<Mutex<Option<Vec<String>>>>,
    sid: Arc<Mutex<Option<String>>>,
    extra: Arc<Mutex<Map<String, Value>>>,
}

impl MockIdp {
    pub fn set_sub(&self, sub: &str) -> &Self {
        *self.sub.lock().unwrap() = sub.to_string();
        self
    }

    pub fn set_email(&self, email: Option<&str>, verified: bool) -> &Self {
        *self.email.lock().unwrap() = email.map(str::to_string);
        *self.email_verified.lock().unwrap() = verified;
        self
    }

    pub fn set_name(&self, name: Option<&str>) -> &Self {
        *self.name.lock().unwrap() = name.map(str::to_string);
        self
    }

    pub fn set_groups(&self, groups: Option<&[&str]>) -> &Self {
        *self.groups.lock().unwrap() = groups.map(|groups| groups.iter().map(|g| (*g).to_string()).collect());
        self
    }

    pub fn set_sid(&self, sid: Option<&str>) -> &Self {
        *self.sid.lock().unwrap() = sid.map(str::to_string);
        self
    }

    /// Adds a claim to every id_token from here on; `null` removes it again.
    pub fn set_claim(&self, name: &str, value: Value) -> &Self {
        let mut extra = self.extra.lock().unwrap();
        if value.is_null() {
            extra.remove(name);
        } else {
            extra.insert(name.to_string(), value);
        }
        self
    }

    /// Mints a back-channel logout token signed with the key in the JWKS.
    /// A `null` in `overrides` removes that claim.
    pub fn logout_token(&self, overrides: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer,
            "aud": TEST_CLIENT_ID,
            "iat": now,
            "jti": format!("logout-{}", unique_suffix()),
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        });
        let target = claims.as_object_mut().expect("claims object");
        for (key, value) in overrides.as_object().cloned().unwrap_or_default() {
            if value.is_null() {
                target.remove(&key);
            } else {
                target.insert(key, value);
            }
        }

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(LOGOUT_KID.to_string());
        let key = EncodingKey::from_ed_der(&hex::decode(ED25519_PKCS8_DER).expect("test key is valid hex"));
        encode(&header, &claims, &key).expect("signed logout token")
    }
}

fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).to_string()
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks", idp.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        // HS256 signs the id_tokens; EdDSA signs the logout tokens.
        "id_token_signing_alg_values_supported": ["HS256", "EdDSA"],
        "scopes_supported": ["openid", "email", "profile", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "email", "email_verified", "name", "groups", "sid"]
    }))
}

async fn jwks() -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": LOGOUT_KID,
            "x": ED25519_PUBLIC_X, "alg": "EdDSA", "use": "sig"
        }]
    }))
}

async fn token(State(idp): State<MockIdp>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": idp.issuer,
        "aud": TEST_CLIENT_ID,
        "sub": *idp.sub.lock().unwrap(),
        "exp": now + 300,
        "iat": now,
        "nonce": *idp.nonce.lock().unwrap(),
    });
    if let Some(name) = idp.name.lock().unwrap().clone() {
        claims["name"] = json!(name);
    }
    if let Some(email) = idp.email.lock().unwrap().clone() {
        claims["email"] = json!(email);
        claims["email_verified"] = json!(*idp.email_verified.lock().unwrap());
    }
    if let Some(groups) = idp.groups.lock().unwrap().clone() {
        claims["groups"] = json!(groups);
    }
    if let Some(sid) = idp.sid.lock().unwrap().clone() {
        claims["sid"] = json!(sid);
    }
    for (name, value) in idp.extra.lock().unwrap().iter() {
        claims[name] = value.clone();
    }

    let id_token =
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(TEST_CLIENT_SECRET.as_bytes()))
            .unwrap();
    Json(json!({
        "access_token": "test-access-token",
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": 300
    }))
}

/// Binds an in-process mock OIDC provider on a loopback port.
pub async fn spawn_mock_idp() -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let idp = MockIdp {
        issuer: format!("http://127.0.0.1:{}", addr.port()),
        nonce: Arc::new(Mutex::new(String::new())),
        sub: Arc::new(Mutex::new("sub-abc".to_string())),
        // No email by default: without the `email` scope an IdP sends none, and
        // the username then derives from `name`. The domain tests set one.
        email: Arc::new(Mutex::new(None)),
        email_verified: Arc::new(Mutex::new(false)),
        name: Arc::new(Mutex::new(Some("José Müller".to_string()))),
        groups: Arc::new(Mutex::new(None)),
        sid: Arc::new(Mutex::new(Some("idp-session-1".to_string()))),
        extra: Arc::new(Mutex::new(Map::new())),
    };
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    idp
}

/// A provider table entry pointing at `issuer`, with the test client credentials.
pub fn provider(issuer: &str) -> ProviderConfig {
    ProviderConfig {
        issuer: Some(issuer.to_string()),
        client_id: TEST_CLIENT_ID.to_string(),
        client_secret: TEST_CLIENT_SECRET.to_string(),
        ..Default::default()
    }
}

pub fn state_cookie(response: &axum_test::TestResponse) -> Option<String> {
    super::cookies(response).into_iter().find(|cookie| cookie.name() == STATE_COOKIE).map(|c| c.value().to_string())
}

pub fn location(response: &axum_test::TestResponse) -> String {
    response.headers().get("location").and_then(|value| value.to_str().ok()).unwrap_or_default().to_string()
}

pub fn session_cookie(response: &axum_test::TestResponse) -> Option<String> {
    super::cookies(response)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-session" && !cookie.value().is_empty())
        .map(|cookie| cookie.value().to_string())
}

/// The cookie header a browser would send after this sign-in response.
pub fn session_headers(response: &axum_test::TestResponse) -> Vec<(String, String)> {
    let cookies: Vec<_> = super::cookies(response)
        .into_iter()
        .filter(|cookie| matches!(cookie.name(), "liwan-session" | "liwan-username") && !cookie.value().is_empty())
        .collect();
    assert_eq!(cookies.len(), 2, "a sign-in sets the session and username cookies");
    vec![("cookie".to_string(), super::cookie_header(&cookies))]
}

/// Drives the whole authorization-code flow and returns the callback response.
/// Stamps the server's own nonce onto the mock so its id_token verifies.
pub async fn run_flow(
    app: &Arc<Liwan>,
    idp: &MockIdp,
    client: &TestClient,
    provider_name: &str,
    return_to: &str,
) -> axum_test::TestResponse {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("provider", provider_name)
        .append_pair("returnTo", return_to)
        .finish();
    let start = client.get(&format!("/api/dashboard/auth/external/start?{query}")).await;
    let state = state_cookie(&start).expect("state cookie");
    *idp.nonce.lock().unwrap() = app.external_auth.peek_nonce(&state).expect("pending flow");

    client
        .get_with_headers(
            &format!("/api/dashboard/auth/external/callback?code=abc&state={state}"),
            vec![("cookie".to_string(), format!("{STATE_COOKIE}={state}"))],
        )
        .await
}
