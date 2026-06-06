mod common;

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use common::{TestClient, cookies, events};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use liwan::app::Liwan;
use liwan::config::{Config, OidcRegistration};
use serde_json::{Value, json};

// The mock IdP signs id_tokens with HS256 using the client secret (standard
// OIDC symmetric signing). openidconnect's confidential-client verifier checks
// the HMAC with the same secret, so no JWKS/RSA key material is needed.
const TEST_CLIENT_SECRET: &str = "secret";

#[derive(Clone)]
struct MockState {
    issuer: String,
    client_id: String,
    nonce: Arc<Mutex<String>>,
    sub: Arc<Mutex<String>>,
    email: Arc<Mutex<Option<String>>>,
    email_verified: Arc<Mutex<bool>>,
}

async fn discovery(State(s): State<MockState>) -> Json<Value> {
    Json(json!({
        "issuer": s.issuer,
        "authorization_endpoint": format!("{}/authorize", s.issuer),
        "token_endpoint": format!("{}/token", s.issuer),
        "jwks_uri": format!("{}/jwks", s.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "email", "email_verified", "name", "preferred_username"]
    }))
}

async fn jwks() -> Json<Value> {
    // HS256 doesn't use JWKS, but the discovery doc still advertises a jwks_uri.
    Json(json!({ "keys": [] }))
}

async fn token(State(s): State<MockState>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": s.issuer,
        "aud": s.client_id,
        "sub": *s.sub.lock().unwrap(),
        "exp": now + 300,
        "iat": now,
        "nonce": *s.nonce.lock().unwrap(),
        "name": "Alice Example",
        "preferred_username": "alice"
    });
    if let Some(email) = s.email.lock().unwrap().clone() {
        claims["email"] = json!(email);
        claims["email_verified"] = json!(*s.email_verified.lock().unwrap());
    }
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(TEST_CLIENT_SECRET.as_bytes());
    let id_token = encode(&header, &claims, &key).unwrap();
    Json(json!({
        "access_token": "test-access-token",
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": 300
    }))
}

/// Bind an in-process mock OIDC provider, returning its issuer URL and state.
async fn spawn_mock_idp() -> MockState {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = MockState {
        issuer: format!("http://127.0.0.1:{}", addr.port()),
        client_id: "liwan".to_string(),
        nonce: Arc::new(Mutex::new(String::new())),
        sub: Arc::new(Mutex::new("sub-abc".to_string())),
        email: Arc::new(Mutex::new(Some("alice@example.com".to_string()))),
        email_verified: Arc::new(Mutex::new(true)),
    };
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    state
}

fn oidc_app(issuer: &str) -> Arc<Liwan> {
    oidc_app_with(issuer, OidcRegistration::Open, &[])
}

fn oidc_app_with(issuer: &str, registration: OidcRegistration, allowed_domains: &[&str]) -> Arc<Liwan> {
    let mut config = Config::default();
    config.base_url = "http://localhost:9042".to_string();
    config.oidc.issuer = Some(issuer.to_string());
    config.oidc.client_id = Some("liwan".to_string());
    config.oidc.client_secret = Some("secret".to_string());
    config.oidc.registration = registration;
    config.oidc.allowed_domains = allowed_domains.iter().map(|d| d.to_string()).collect();
    Liwan::new_memory(config).unwrap()
}

fn location(res: &axum_test::TestResponse) -> String {
    res.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

/// Drive the full authorization-code flow (login redirect → callback) and return
/// the callback response. Stamps the server-generated nonce onto the mock.
async fn run_oidc_flow(app: &Arc<Liwan>, mock: &MockState, client: &TestClient) -> axum_test::TestResponse {
    let res = client.get("/api/dashboard/auth/oidc/login").await;
    let set = cookies(&res);
    let state = set.iter().find(|c| c.name() == "liwan-oidc-state").expect("state cookie").value().to_string();
    let nonce = app.oidc_state.peek_nonce(&state).expect("nonce row");
    *mock.nonce.lock().unwrap() = nonce;
    client
        .get_with_headers(
            &format!("/api/dashboard/auth/oidc/callback?code=abc&state={state}"),
            vec![("cookie".to_string(), format!("liwan-oidc-state={state}"))],
        )
        .await
}

#[tokio::test]
async fn oidc_full_login_provisions_user_and_session() {
    let mock = spawn_mock_idp().await;
    let app = oidc_app(&mock.issuer);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    // 1. Start login -> redirect to the IdP, sets state cookie + DB row.
    let res = client.get("/api/dashboard/auth/oidc/login").await;
    let set = cookies(&res);
    let state = set.iter().find(|c| c.name() == "liwan-oidc-state").expect("state cookie").value().to_string();
    assert!(location(&res).starts_with(&format!("{}/authorize", mock.issuer)), "auth redirect: {}", location(&res));

    // The RP-generated nonce lives server-side; read it and stamp the mock so
    // its id_token echoes the value the verifier expects.
    let nonce = app.oidc_state.peek_nonce(&state).expect("nonce row");
    *mock.nonce.lock().unwrap() = nonce;

    // 2. Callback -> provisions the user + session, redirects to "/".
    let res = client
        .get_with_headers(
            &format!("/api/dashboard/auth/oidc/callback?code=abc&state={state}"),
            vec![("cookie".to_string(), format!("liwan-oidc-state={state}"))],
        )
        .await;

    assert_eq!(location(&res), "/", "callback should redirect home");
    let set = cookies(&res);
    assert!(set.iter().any(|c| c.name() == "liwan-session" && !c.value().is_empty()), "session cookie set");

    let users = app.users.all().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].auth, liwan::app::models::AuthMethod::Oidc);
    assert_eq!(users[0].email.as_deref(), Some("alice@example.com"));
    assert!(users[0].projects.is_empty());
}

/// Exercise discovery + code exchange + id_token verification in isolation.
#[tokio::test]
async fn oidc_finish_login_verifies_claims() {
    let mock = spawn_mock_idp().await;
    let app = oidc_app(&mock.issuer);
    let oidc = app.oidc.clone().unwrap();
    let start = oidc.start_login().await.expect("start_login");
    *mock.nonce.lock().unwrap() = start.nonce.clone();
    let claims = oidc.finish_login("abc".to_string(), start.pkce_verifier, &start.nonce).await.expect("finish_login");
    assert_eq!(claims.subject, "sub-abc");
    assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
    assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
}

#[tokio::test]
async fn oidc_login_404_when_disabled() {
    let app = common::app(); // default config -> OIDC disabled
    let (tx, _rx) = events();
    let client = TestClient::new(app, tx);
    let res = client.get("/api/dashboard/auth/oidc/login").await;
    assert_eq!(res.status_code(), 404);
}

#[tokio::test]
async fn oidc_callback_state_mismatch_redirects_with_error() {
    // Issuer need not be reachable: state validation fails before any discovery.
    let app = oidc_app("http://127.0.0.1:1");
    let (tx, _rx) = events();
    let client = TestClient::new(app, tx);
    let res = client.get("/api/dashboard/auth/oidc/callback?code=x&state=y").await;
    assert!(location(&res).contains("/login?error=state_mismatch"), "got: {}", location(&res));
}

#[tokio::test]
async fn oidc_closed_rejects_new_subject() {
    let mock = spawn_mock_idp().await;
    let app = oidc_app_with(&mock.issuer, OidcRegistration::Closed, &[]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/login?error=registration_closed", "got: {}", location(&res));
    assert!(app.users.all().unwrap().is_empty(), "no user should be provisioned");
}

#[tokio::test]
async fn oidc_closed_allows_existing_subject() {
    let mock = spawn_mock_idp().await;
    let app = oidc_app_with(&mock.issuer, OidcRegistration::Closed, &[]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    // Pre-existing user matched on issuer+subject logs in despite closed registration.
    app.users.provision_oidc(&mock.issuer, "sub-abc", Some("alice@example.com"), Some("alice"), None).unwrap();

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/", "existing user should log in");
    assert!(cookies(&res).iter().any(|c| c.name() == "liwan-session" && !c.value().is_empty()), "session set");
}

#[tokio::test]
async fn oidc_allowlist_provisions_allowed_domain() {
    let mock = spawn_mock_idp().await;
    let app = oidc_app_with(&mock.issuer, OidcRegistration::DomainAllowlist, &["example.com"]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/", "allowed domain should be provisioned");
    assert_eq!(app.users.all().unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_allowlist_rejects_disallowed_domain() {
    let mock = spawn_mock_idp().await;
    *mock.email.lock().unwrap() = Some("eve@nope.net".to_string());
    let app = oidc_app_with(&mock.issuer, OidcRegistration::DomainAllowlist, &["example.com"]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/login?error=domain_not_allowed", "got: {}", location(&res));
    assert!(app.users.all().unwrap().is_empty());
}

#[tokio::test]
async fn oidc_allowlist_rejects_subdomain() {
    let mock = spawn_mock_idp().await;
    *mock.email.lock().unwrap() = Some("eve@sub.example.com".to_string());
    let app = oidc_app_with(&mock.issuer, OidcRegistration::DomainAllowlist, &["example.com"]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/login?error=domain_not_allowed", "got: {}", location(&res));
}

#[tokio::test]
async fn oidc_allowlist_rejects_unverified_email() {
    let mock = spawn_mock_idp().await;
    *mock.email_verified.lock().unwrap() = false;
    let app = oidc_app_with(&mock.issuer, OidcRegistration::DomainAllowlist, &["example.com"]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/login?error=email_not_verified", "got: {}", location(&res));
    assert!(app.users.all().unwrap().is_empty());
}

#[tokio::test]
async fn oidc_allowlist_rejects_absent_email() {
    // No email claim at all (distinct from present-but-unverified above).
    let mock = spawn_mock_idp().await;
    *mock.email.lock().unwrap() = None;
    let app = oidc_app_with(&mock.issuer, OidcRegistration::DomainAllowlist, &["example.com"]);
    let (tx, _rx) = events();
    let client = TestClient::new(app.clone(), tx);

    let res = run_oidc_flow(&app, &mock, &client).await;
    assert_eq!(location(&res), "/login?error=email_not_verified", "got: {}", location(&res));
    assert!(app.users.all().unwrap().is_empty());
}
