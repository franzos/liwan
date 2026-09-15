use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use liwan::{
    app::{Liwan, models::UserRole},
    config::{Config, GroupsConfig, ProviderConfig, Registration},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

mod common;

/// The mock IdP signs id_tokens with HS256 using the client secret (standard
/// OIDC symmetric signing), so login needs no key material at all. Its JWKS
/// carries one fixed Ed25519 key, used only for back-channel logout tokens.
const TEST_CLIENT_SECRET: &str = "secret";
const TEST_CLIENT_ID: &str = "liwan";

/// RFC 8032's first Ed25519 test vector, as PKCS#8 DER and as a JWK `x`.
const ED25519_PKCS8_DER: &str =
    "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const LOGOUT_KID: &str = "logout-key";
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// What the mock IdP will say about the next person to sign in.
#[derive(Clone)]
struct MockIdp {
    issuer: String,
    nonce: Arc<Mutex<String>>,
    sub: Arc<Mutex<String>>,
    email: Arc<Mutex<Option<String>>>,
    email_verified: Arc<Mutex<bool>>,
    name: Arc<Mutex<Option<String>>>,
    groups: Arc<Mutex<Option<Vec<String>>>>,
    sid: Arc<Mutex<Option<String>>>,
}

impl MockIdp {
    fn set_sub(&self, sub: &str) -> &Self {
        *self.sub.lock().unwrap() = sub.to_string();
        self
    }

    fn set_email(&self, email: Option<&str>, verified: bool) -> &Self {
        *self.email.lock().unwrap() = email.map(str::to_string);
        *self.email_verified.lock().unwrap() = verified;
        self
    }

    fn set_name(&self, name: Option<&str>) -> &Self {
        *self.name.lock().unwrap() = name.map(str::to_string);
        self
    }

    fn set_groups(&self, groups: Option<&[&str]>) -> &Self {
        *self.groups.lock().unwrap() = groups.map(|groups| groups.iter().map(|g| (*g).to_string()).collect());
        self
    }

    fn set_sid(&self, sid: Option<&str>) -> &Self {
        *self.sid.lock().unwrap() = sid.map(str::to_string);
        self
    }

    /// Mints a back-channel logout token signed with the key in the JWKS.
    /// A `null` in `overrides` removes that claim.
    fn logout_token(&self, overrides: Value) -> String {
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
async fn spawn_mock_idp() -> MockIdp {
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
fn provider(issuer: &str) -> ProviderConfig {
    ProviderConfig {
        issuer: Some(issuer.to_string()),
        client_id: TEST_CLIENT_ID.to_string(),
        client_secret: TEST_CLIENT_SECRET.to_string(),
        ..Default::default()
    }
}

fn app_with(providers: &[(&str, ProviderConfig)]) -> Arc<Liwan> {
    let app = Liwan::new_memory(config_with(providers)).unwrap();
    // Onboarding hides SSO entirely, so every test starts past it.
    app.users.create("setup-admin", "correct-horse-battery", UserRole::Admin, &[]).unwrap();
    app.onboarding.clear();
    app
}

fn config_with(providers: &[(&str, ProviderConfig)]) -> Config {
    let mut config = Config::default();
    config.base_url = "https://liwan.example.com".to_string();
    // Several logins in one test come from one "client", which the default
    // burst of 5 would throttle. `start_is_rate_limited` sets its own.
    config.rate_limit.auth_burst = 50;
    for (name, provider) in providers {
        config.oidc.providers.insert((*name).to_string(), provider.clone());
    }
    config
}

fn state_cookie(response: &axum_test::TestResponse) -> Option<String> {
    common::cookies(response)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-external-auth-state")
        .map(|cookie| cookie.value().to_string())
}

fn location(response: &axum_test::TestResponse) -> String {
    response.headers().get("location").and_then(|value| value.to_str().ok()).unwrap_or_default().to_string()
}

fn session_cookie(response: &axum_test::TestResponse) -> Option<String> {
    common::cookies(response)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-session" && !cookie.value().is_empty())
        .map(|cookie| cookie.value().to_string())
}

fn signed_in(app: &Liwan, session: &str) -> bool {
    app.sessions.get(session).unwrap().is_some()
}

fn create_project(app: &Liwan, id: &str) {
    app.projects
        .create(
            &liwan::app::models::Project {
                id: id.to_string(),
                display_name: id.to_string(),
                public: false,
                unlisted: false,
                secret: None,
            },
            &[],
        )
        .unwrap();
}

/// Drives the whole authorization-code flow and returns the callback response.
/// Stamps the server's own nonce onto the mock so its id_token verifies.
async fn run_flow(
    app: &Arc<Liwan>,
    idp: &MockIdp,
    client: &common::TestClient,
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
            vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))],
        )
        .await
}

// -- metadata and start -------------------------------------------------------

#[tokio::test]
async fn metadata_is_empty_during_onboarding() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = Liwan::new_memory(config_with(&[("company", provider(&idp.issuer))]))?;
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // Until the first admin exists, SSO would let the IdP claim the instance.
    client.get("/api/dashboard/auth/external").await.assert_json(&json!({ "providers": [] }));
    client.get("/api/dashboard/auth/external/start?provider=company").await.assert_status_not_found();

    app.users.create("admin", "correct-horse-battery", UserRole::Admin, &[])?;
    app.onboarding.clear();
    client.get("/api/dashboard/auth/external").await.assert_json(&json!({
        "providers": [{ "name": "company", "kind": "oidc", "displayName": "OpenID Connect" }]
    }));
    Ok(())
}

#[tokio::test]
async fn metadata_is_empty_without_providers() -> Result<()> {
    let app = app_with(&[]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    client.get("/api/dashboard/auth/external").await.assert_json(&json!({ "providers": [] }));
    client.get("/api/dashboard/auth/external/start?provider=company").await.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn start_targets_the_named_provider() -> Result<()> {
    let first = spawn_mock_idp().await;
    let second = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&first.issuer)), ("partner", provider(&second.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let response = client.get("/api/dashboard/auth/external").await;
    assert_eq!(response.json::<Value>()["providers"].as_array().expect("providers").len(), 2);

    for (name, issuer) in [("company", &first.issuer), ("partner", &second.issuer)] {
        let response =
            client.get(&format!("/api/dashboard/auth/external/start?provider={name}&returnTo=%2Fsettings")).await;
        response.assert_status_see_other();
        let target = location(&response);
        assert!(target.starts_with(&format!("{issuer}/authorize")), "{name} went to {target}");

        let query: HashMap<_, _> = url::Url::parse(&target)?.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("https://liwan.example.com/api/dashboard/auth/external/callback")
        );
        assert_eq!(query.get("code_challenge_method").map(String::as_str), Some("S256"));
        assert!(query.contains_key("code_challenge"));
        assert!(query.contains_key("nonce"));
        assert_eq!(query.get("prompt"), None, "allow_session_reuse defaults to true");

        let cookie = common::cookies(&response)
            .into_iter()
            .find(|cookie| cookie.name() == "liwan-external-auth-state")
            .expect("state cookie");
        assert_eq!(Some(cookie.value()), query.get("state").map(String::as_str));
        assert!(cookie.http_only().unwrap_or(false));
        assert!(cookie.secure().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(cookie::SameSite::Lax));
    }

    client.get("/api/dashboard/auth/external/start?provider=nope").await.assert_status_not_found();
    client.get("/api/dashboard/auth/external/start").await.assert_status_bad_request();
    Ok(())
}

#[tokio::test]
async fn start_requests_the_configured_scopes() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[(
        "company",
        ProviderConfig {
            scopes: vec!["openid".to_string(), "email".to_string(), "groups".to_string()],
            ..provider(&idp.issuer)
        },
    )]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let response = client.get("/api/dashboard/auth/external/start?provider=company").await;
    let query: HashMap<_, _> = url::Url::parse(&location(&response))?.query_pairs().into_owned().collect();
    let scopes = query.get("scope").expect("scope parameter").split(' ').collect::<Vec<_>>();
    assert!(scopes.contains(&"openid") && scopes.contains(&"email") && scopes.contains(&"groups"), "got: {scopes:?}");
    assert!(!scopes.contains(&"profile"), "profile was not configured, got: {scopes:?}");
    Ok(())
}

#[tokio::test]
async fn start_forces_reauthentication_when_session_reuse_is_off() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", ProviderConfig { allow_session_reuse: false, ..provider(&idp.issuer) })]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let response = client.get("/api/dashboard/auth/external/start?provider=company").await;
    response.assert_status_see_other();
    let query: HashMap<_, _> = url::Url::parse(&location(&response))?.query_pairs().into_owned().collect();
    assert_eq!(query.get("prompt").map(String::as_str), Some("login"));
    Ok(())
}

#[tokio::test]
async fn start_rejects_an_off_origin_return_path() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    client
        .get("/api/dashboard/auth/external/start?provider=company&returnTo=https%3A%2F%2Fevil.example")
        .await
        .assert_status_bad_request();
    Ok(())
}

#[tokio::test]
async fn start_is_rate_limited() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let mut config = config_with(&[("company", provider(&idp.issuer))]);
    config.rate_limit.auth_burst = 2;
    let app = Liwan::new_memory(config)?;
    app.users.create("admin", "correct-horse-battery", UserRole::Admin, &[])?;
    app.onboarding.clear();
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    for _ in 0..2 {
        client.get("/api/dashboard/auth/external/start?provider=company").await.assert_status_see_other();
    }
    client.get("/api/dashboard/auth/external/start?provider=company").await.assert_status_too_many_requests();
    Ok(())
}

#[tokio::test]
async fn callback_reports_a_state_mismatch() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let start = client.get("/api/dashboard/auth/external/start?provider=company").await;
    let state = state_cookie(&start).expect("state cookie");

    client
        .get_with_headers(
            "/api/dashboard/auth/external/callback?state=wrong&code=unused",
            vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))],
        )
        .await
        .assert_header("location", "/login?externalAuthError=state_mismatch");

    // Without the cookie at all there is nothing to compare against.
    client
        .get("/api/dashboard/auth/external/callback?state=anything&code=unused")
        .await
        .assert_header("location", "/login?externalAuthError=state_mismatch");

    // The provider said no before we got as far as a code.
    let callback = client
        .get_with_headers(
            &format!("/api/dashboard/auth/external/callback?state={state}&error=access_denied"),
            vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))],
        )
        .await;
    callback.assert_header("location", "/login?externalAuthError=provider_error");
    let cleared = common::cookies(&callback)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-external-auth-state")
        .expect("state cookie removal");
    assert_eq!(cleared.value(), "", "the state cookie is cleared once the flow is over");
    Ok(())
}

// -- the full flow ------------------------------------------------------------

#[tokio::test]
async fn full_login_provisions_a_user_and_a_session() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let response = run_flow(&app, &idp, &client, "company", "/settings").await;
    assert_eq!(location(&response), "/settings", "returnTo is honoured");
    assert!(session_cookie(&response).is_some(), "a session cookie is set");

    // The username is transliterated from the claims; no password is set.
    let user = app.users.get("jose-muller")?;
    assert_eq!(user.role, UserRole::User);
    assert!(user.projects.is_empty(), "a new SSO user has no project access");
    assert!(!app.users.check_login("jose-muller", "anything")?);

    // The identity is keyed on the discovered issuer, not on the config name.
    let account = app.external_auth.account_for("jose-muller").await?.expect("external account");
    assert_eq!(account.provider_name, "company");
    assert_eq!(account.display_name, "OpenID Connect");
    assert_eq!(account.manage_url, None, "only Forseti advertises one");

    // A second sign-in of the same subject lands on the same account.
    assert_eq!(location(&run_flow(&app, &idp, &client, "company", "/").await), "/");
    assert_eq!(app.users.all()?.len(), 2, "the setup admin and the one SSO user");
    Ok(())
}

#[tokio::test]
async fn login_requires_the_nonce_the_server_issued() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let start = client.get("/api/dashboard/auth/external/start?provider=company").await;
    let state = state_cookie(&start).expect("state cookie");
    // An id_token minted for somebody else's login attempt.
    *idp.nonce.lock().unwrap() = "a-nonce-we-never-issued".to_string();

    client
        .get_with_headers(
            &format!("/api/dashboard/auth/external/callback?code=abc&state={state}"),
            vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))],
        )
        .await
        .assert_header("location", "/login?externalAuthError=unavailable");
    assert_eq!(app.users.all()?.len(), 1, "nobody was provisioned");
    Ok(())
}

#[tokio::test]
async fn a_flow_is_single_use() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let start = client.get("/api/dashboard/auth/external/start?provider=company").await;
    let state = state_cookie(&start).expect("state cookie");
    *idp.nonce.lock().unwrap() = app.external_auth.peek_nonce(&state).expect("pending flow");
    let headers = vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))];
    let path = format!("/api/dashboard/auth/external/callback?code=abc&state={state}");

    assert_eq!(location(&client.get_with_headers(&path, headers.clone()).await), "/");
    // Replaying the same code and state gets nothing: the flow is consumed.
    client.get_with_headers(&path, headers).await.assert_header("location", "/login?externalAuthError=unavailable");
    Ok(())
}

#[tokio::test]
async fn an_sso_admin_cannot_set_a_local_password() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let response = run_flow(&app, &idp, &client, "company", "/").await;
    let session = session_cookie(&response).expect("session cookie");
    app.users.update("jose-muller", UserRole::Admin, &[])?;

    // A local password on an SSO account outlives IdP deactivation and MFA.
    let response = client
        .put_with_headers(
            "/api/dashboard/user/jose-muller/password",
            json!({ "password": "a-new-local-password" }),
            vec![("cookie".to_string(), format!("liwan-session={session}; liwan-username=jose-muller"))],
        )
        .await;
    response.assert_status_conflict();
    assert!(!app.users.check_login("jose-muller", "a-new-local-password")?);
    Ok(())
}

#[tokio::test]
async fn closed_registration_only_lets_existing_accounts_in() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", ProviderConfig { registration: Registration::Closed, ..provider(&idp.issuer) })]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_sub("stranger");
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=registration_closed");
    assert_eq!(app.users.all()?.len(), 1, "nobody was provisioned");

    // Someone linked ahead of time gets in regardless of the policy.
    app.users.create("known", "correct-horse-battery", UserRole::User, &[])?;
    app.external_auth.link("known", &idp.issuer, "stranger", false)?;
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    assert!(session_cookie(&response).is_some());
    Ok(())
}

#[tokio::test]
async fn allowed_domains_are_checked_on_every_login() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[(
        "company",
        ProviderConfig { allowed_domains: vec!["example.com".to_string()], ..provider(&idp.issuer) },
    )]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_email(Some("alice@Example.COM"), true);
    assert_eq!(location(&run_flow(&app, &idp, &client, "company", "/").await), "/");

    for (label, email, verified, expected) in [
        ("another domain", Some("bob@other.net"), true, "domain_not_allowed"),
        // A subdomain is a different domain.
        ("a subdomain", Some("eve@sub.example.com"), true, "domain_not_allowed"),
        // An unverified address is attacker-controlled.
        ("an unverified address", Some("mallory@example.com"), false, "email_not_verified"),
        ("no address at all", None, false, "email_not_verified"),
    ] {
        idp.set_sub(&format!("sub-{expected}-{label}")).set_email(email, verified);
        run_flow(&app, &idp, &client, "company", "/")
            .await
            .assert_header("location", &format!("/login?externalAuthError={expected}"));
    }

    // Only the first, allowed login produced an account.
    assert_eq!(app.users.all()?.len(), 2);

    // The check applies to a returning user too, not only at sign-up.
    idp.set_sub("sub-abc").set_email(Some("alice@revoked.example"), true);
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=domain_not_allowed");
    Ok(())
}

#[tokio::test]
async fn the_groups_gate_keeps_non_members_out() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig { allowed: vec!["analytics".to_string()], ..Default::default() };
    let app = app_with(&[("company", ProviderConfig { groups: Some(groups), ..provider(&idp.issuer) })]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["sales"]));
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=access_denied");

    // An absent claim counts as no groups.
    idp.set_groups(None);
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=access_denied");
    assert_eq!(app.users.all()?.len(), 1);

    idp.set_groups(Some(&["sales", "analytics"]));
    assert_eq!(location(&run_flow(&app, &idp, &client, "company", "/").await), "/");
    Ok(())
}

#[tokio::test]
async fn groups_drive_the_role_and_project_access() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        admin: vec!["liwan-admins".to_string()],
        projects: [
            ("marketing".to_string(), vec!["blog".to_string(), "gone".to_string()]),
            ("eng".to_string(), vec!["app".to_string()]),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let app = app_with(&[("company", ProviderConfig { groups: Some(groups), ..provider(&idp.issuer) })]);
    create_project(&app, "blog");
    create_project(&app, "app");
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["liwan-admins", "marketing"]));
    run_flow(&app, &idp, &client, "company", "/").await;
    let user = app.users.get("jose-muller")?;
    assert_eq!(user.role, UserRole::Admin);
    assert_eq!(user.projects, vec!["blog".to_string()], "a project that does not exist is dropped");

    // The IdP is authoritative on every login, including losing the admin group.
    idp.set_groups(Some(&["eng"]));
    run_flow(&app, &idp, &client, "company", "/").await;
    let user = app.users.get("jose-muller")?;
    assert_eq!(user.role, UserRole::User);
    assert_eq!(user.projects, vec!["app".to_string()]);
    Ok(())
}

#[tokio::test]
async fn group_mapping_leaves_a_linked_password_account_alone() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig { admin: vec!["liwan-admins".to_string()], ..Default::default() };
    let app = app_with(&[("company", ProviderConfig { groups: Some(groups), ..provider(&idp.issuer) })]);
    create_project(&app, "blog");
    app.users.create("franz", "correct-horse-battery", UserRole::Admin, &["blog"])?;
    app.external_auth.link("franz", &idp.issuer, "sub-abc", false)?;
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // No admin group, yet the locally created admin keeps everything.
    idp.set_groups(Some(&["nobody"]));
    assert_eq!(location(&run_flow(&app, &idp, &client, "company", "/").await), "/");
    let user = app.users.get("franz")?;
    assert_eq!(user.role, UserRole::Admin);
    assert_eq!(user.projects, vec!["blog".to_string()]);
    assert!(app.users.check_login("franz", "correct-horse-battery")?);
    Ok(())
}

#[tokio::test]
async fn two_providers_are_two_identities() -> Result<()> {
    let first = spawn_mock_idp().await;
    let second = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&first.issuer)), ("partner", provider(&second.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // The same subject string at two issuers is two different people.
    first.set_sub("shared-subject").set_name(Some("First Person"));
    second.set_sub("shared-subject").set_name(Some("Second Person"));

    assert_eq!(location(&run_flow(&app, &first, &client, "company", "/").await), "/");
    assert_eq!(location(&run_flow(&app, &second, &client, "partner", "/").await), "/");

    assert!(app.users.get("first-person").is_ok());
    assert!(app.users.get("second-person").is_ok());
    assert_eq!(app.external_auth.account_for("first-person").await?.expect("account").provider_name, "company");
    assert_eq!(app.external_auth.account_for("second-person").await?.expect("account").provider_name, "partner");
    Ok(())
}

// -- back-channel logout ------------------------------------------------------

async fn post_logout_token(client: &common::TestClient, provider: &str, token: &str) -> axum_test::TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new()).append_pair("logout_token", token).finish();
    client.post_form(&format!("/api/dashboard/auth/external/{provider}/backchannel-logout"), &body).await
}

/// Signs in twice from two "devices", returning both session cookies.
async fn two_sessions(app: &Arc<Liwan>, idp: &MockIdp, client: &common::TestClient) -> (String, String) {
    idp.set_sid(Some("idp-session-1"));
    let laptop = session_cookie(&run_flow(app, idp, client, "company", "/").await).expect("first session");
    idp.set_sid(Some("idp-session-2"));
    let phone = session_cookie(&run_flow(app, idp, client, "company", "/").await).expect("second session");
    assert_ne!(laptop, phone);
    (laptop, phone)
}

#[tokio::test]
async fn logout_with_a_sid_ends_that_device_only() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    let (laptop, phone) = two_sessions(&app, &idp, &client).await;

    let token = idp.logout_token(json!({ "sid": "idp-session-1" }));
    post_logout_token(&client, "company", &token).await.assert_status_ok();

    assert!(!signed_in(&app, &laptop), "the device the IdP signed out is gone");
    assert!(signed_in(&app, &phone), "the other device is untouched");
    Ok(())
}

#[tokio::test]
async fn logout_with_only_a_sub_ends_every_session() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    let (laptop, phone) = two_sessions(&app, &idp, &client).await;

    let token = idp.logout_token(json!({ "sub": "sub-abc" }));
    post_logout_token(&client, "company", &token).await.assert_status_ok();

    assert!(!signed_in(&app, &laptop));
    assert!(!signed_in(&app, &phone));
    Ok(())
}

#[tokio::test]
async fn a_logout_token_that_does_not_verify_changes_nothing() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    let (laptop, phone) = two_sessions(&app, &idp, &client).await;

    let now = chrono::Utc::now().timestamp();
    let cases: Vec<(&str, String)> = vec![
        ("wrong issuer", idp.logout_token(json!({ "sid": "idp-session-1", "iss": "https://evil.example" }))),
        ("wrong audience", idp.logout_token(json!({ "sid": "idp-session-1", "aud": "someone-else" }))),
        ("stale iat", idp.logout_token(json!({ "sid": "idp-session-1", "iat": now - 120 }))),
        ("expired", idp.logout_token(json!({ "sid": "idp-session-1", "exp": now - 1 }))),
        ("missing event", idp.logout_token(json!({ "sid": "idp-session-1", "events": { "something/else": {} } }))),
        // An ID token replayed as a logout token.
        ("nonce present", idp.logout_token(json!({ "sid": "idp-session-1", "nonce": "n-0S6_WzA2Mj" }))),
        ("neither sub nor sid", idp.logout_token(json!({}))),
    ];

    for (name, token) in cases {
        let response = post_logout_token(&client, "company", &token).await;
        assert_eq!(response.status_code(), 400, "{name} should be refused");
        assert!(response.text().is_empty(), "{name} leaked a body");
        assert!(signed_in(&app, &laptop) && signed_in(&app, &phone), "{name} ended a session");
    }

    // A token the IdP never signed.
    let real = idp.logout_token(json!({ "sid": "idp-session-1" }));
    let tampered = format!("{}x", &real[..real.len() - 1]);
    post_logout_token(&client, "company", &tampered).await.assert_status_bad_request();
    assert!(signed_in(&app, &laptop) && signed_in(&app, &phone));
    Ok(())
}

#[tokio::test]
async fn a_replayed_logout_token_is_accepted_but_does_nothing() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    let (laptop, phone) = two_sessions(&app, &idp, &client).await;

    let token = idp.logout_token(json!({ "sid": "idp-session-1" }));
    post_logout_token(&client, "company", &token).await.assert_status_ok();
    assert!(!signed_in(&app, &laptop));

    // The same delivery again must not reach forward and end a newer session.
    idp.set_sid(Some("idp-session-1"));
    let replacement = session_cookie(&run_flow(&app, &idp, &client, "company", "/").await).expect("new session");
    post_logout_token(&client, "company", &token).await.assert_status_ok();
    assert!(signed_in(&app, &replacement), "a retried delivery must not end a session started since");
    assert!(signed_in(&app, &phone));
    Ok(())
}

#[tokio::test]
async fn logout_404s_for_a_provider_nobody_configured() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let token = idp.logout_token(json!({ "sid": "idp-session-1" }));
    post_logout_token(&client, "nope", &token).await.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn a_password_login_carries_no_idp_session_id() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = app_with(&[("company", provider(&idp.issuer))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let cookies = common::login(&client, "setup-admin", "correct-horse-battery").await;
    let password_session =
        cookies.iter().find(|cookie| cookie.name() == "liwan-session").expect("session").value().to_string();
    let (laptop, _phone) = two_sessions(&app, &idp, &client).await;

    // A logout token for the SSO session must not reach the password session.
    let token = idp.logout_token(json!({ "sid": "idp-session-1" }));
    post_logout_token(&client, "company", &token).await.assert_status_ok();
    assert!(!signed_in(&app, &laptop));
    assert!(signed_in(&app, &password_session), "a password login is not the IdP's to end");
    Ok(())
}

// -- the rest of the surface --------------------------------------------------

#[tokio::test]
async fn me_has_no_external_account_for_a_password_user() -> Result<()> {
    let app = app_with(&[]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);
    let cookies = common::login(&client, "setup-admin", "correct-horse-battery").await;

    let response = client
        .get_with_headers("/api/dashboard/auth/me", vec![("cookie".to_string(), common::cookie_header(&cookies))])
        .await;
    response.assert_status_success();
    let body: Value = response.json();
    assert_eq!(body["username"], "setup-admin");
    assert_eq!(body["externalAccount"], Value::Null);
    Ok(())
}

#[tokio::test]
async fn the_settings_api_is_gone() -> Result<()> {
    let app = app_with(&[]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);
    let cookies = common::cookie_header(&common::login(&client, "setup-admin", "correct-horse-battery").await);

    // Providers come from the config file; there is no admin surface for them.
    client
        .get_with_headers("/api/dashboard/admin/auth", vec![("cookie".to_string(), cookies)])
        .await
        .assert_status_not_found();
    Ok(())
}
