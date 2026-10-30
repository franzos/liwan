use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use liwan::{
    app::{Liwan, models::UserRole},
    config::{Config, GroupsConfig, ProviderConfig, ProviderKind},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

mod common;

/// A mock Forseti: the OIDC surface Hydra serves, plus the two documents Forseti
/// serves itself. id_tokens are HS256 against the client secret; the webhook and
/// logout tokens are EdDSA against the fixed key below.
const TEST_CLIENT_SECRET: &str = "secret";
const TEST_CLIENT_ID: &str = "liwan";

/// RFC 8032's first Ed25519 test vector, as PKCS#8 DER and as a JWK `x`.
const ED25519_PKCS8_DER: &str =
    "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const WEBHOOK_KID: &str = "webhook-key";
const ACCOUNT_PURGED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
const SET_CONTENT_TYPE: &str = "application/secevent+jwt";

#[derive(Clone)]
struct MockForseti {
    issuer: String,
    nonce: Arc<Mutex<String>>,
    sub: Arc<Mutex<String>>,
    groups: Arc<Mutex<Option<Vec<String>>>>,
    /// When set, `/.well-known/forseti-configuration` answers 500.
    configuration_broken: Arc<AtomicBool>,
    /// How many times the portal document has been asked for.
    configuration_hits: Arc<AtomicU64>,
}

impl MockForseti {
    fn set_sub(&self, sub: &str) -> &Self {
        *self.sub.lock().unwrap() = sub.to_string();
        self
    }

    fn set_groups(&self, groups: Option<&[&str]>) -> &Self {
        *self.groups.lock().unwrap() = groups.map(|groups| groups.iter().map(|g| (*g).to_string()).collect());
        self
    }

    /// Mints an `account-purged` security event token. A `null` in `overrides`
    /// removes that claim; `typ` and `alg` override the JOSE header.
    fn purge_token(&self, subject: &str, overrides: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer,
            "aud": TEST_CLIENT_ID,
            "iat": now,
            "jti": format!("purge-{}", unique_suffix()),
            "events": {
                ACCOUNT_PURGED: {
                    "subject": { "subject_type": "iss-sub", "iss": self.issuer, "sub": subject }
                }
            },
        });
        let target = claims.as_object_mut().expect("claims object");
        for (key, value) in overrides.as_object().cloned().unwrap_or_default() {
            if key == "typ" || key == "alg" {
                continue;
            }
            if value.is_null() {
                target.remove(&key);
            } else {
                target.insert(key, value);
            }
        }

        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(overrides["typ"].as_str().unwrap_or(SET_CONTENT_TYPE).to_string());
        header.kid = Some(WEBHOOK_KID.to_string());
        let key = EncodingKey::from_ed_der(&hex::decode(ED25519_PKCS8_DER).expect("test key is valid hex"));
        encode(&header, &claims, &key).expect("signed security event token")
    }
}

fn unique_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).to_string()
}

async fn discovery(State(portal): State<MockForseti>) -> Json<Value> {
    Json(json!({
        "issuer": portal.issuer,
        "authorization_endpoint": format!("{}/authorize", portal.issuer),
        "token_endpoint": format!("{}/token", portal.issuer),
        "jwks_uri": format!("{}/jwks", portal.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256", "EdDSA"],
        "scopes_supported": ["openid", "email", "profile", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    }))
}

async fn forseti_configuration(
    State(portal): State<MockForseti>,
) -> std::result::Result<Json<Value>, axum::http::StatusCode> {
    portal.configuration_hits.fetch_add(1, Ordering::Relaxed);
    if portal.configuration_broken.load(Ordering::Relaxed) {
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(json!({
        "issuer": portal.issuer,
        "forseti_version": "0.1.0",
        "account_management_uri": format!("{}/settings", portal.issuer),
        "handoff_endpoint": format!("{}/handoff", portal.issuer),
        "handoff_actions_supported": ["2fa", "password", "profile", "sessions"],
        "webhook_jwks_uri": format!("{}/.well-known/webhook-jwks.json", portal.issuer),
        "webhook_events_supported": [ACCOUNT_PURGED]
    })))
}

async fn webhook_jwks() -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": WEBHOOK_KID,
            "x": ED25519_PUBLIC_X, "alg": "EdDSA", "use": "sig"
        }]
    }))
}

async fn jwks() -> Json<Value> {
    Json(json!({ "keys": [] }))
}

async fn token(State(portal): State<MockForseti>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": portal.issuer,
        "aud": TEST_CLIENT_ID,
        "sub": *portal.sub.lock().unwrap(),
        "exp": now + 300,
        "iat": now,
        "nonce": *portal.nonce.lock().unwrap(),
        "name": "Liwan Tester",
        "email": "tester@example.com",
        "email_verified": true,
    });
    if let Some(groups) = portal.groups.lock().unwrap().clone() {
        claims["groups"] = json!(groups);
    }

    let id_token =
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(TEST_CLIENT_SECRET.as_bytes()))
            .unwrap();
    Json(json!({ "access_token": "t", "id_token": id_token, "token_type": "bearer", "expires_in": 300 }))
}

async fn spawn_mock_forseti() -> MockForseti {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let portal = MockForseti {
        issuer: format!("http://127.0.0.1:{}", addr.port()),
        nonce: Arc::new(Mutex::new(String::new())),
        sub: Arc::new(Mutex::new("kratos-identity-id".to_string())),
        groups: Arc::new(Mutex::new(None)),
        configuration_broken: Arc::new(AtomicBool::new(false)),
        configuration_hits: Arc::new(AtomicU64::new(0)),
    };
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/forseti-configuration", get(forseti_configuration))
        .route("/.well-known/webhook-jwks.json", get(webhook_jwks))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(portal.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    portal
}

fn forseti_provider(issuer: &str, groups: Option<GroupsConfig>) -> ProviderConfig {
    ProviderConfig {
        kind: ProviderKind::Forseti,
        issuer: Some(issuer.to_string()),
        client_id: TEST_CLIENT_ID.to_string(),
        client_secret: TEST_CLIENT_SECRET.to_string(),
        groups,
        ..Default::default()
    }
}

fn app_with(providers: &[(&str, ProviderConfig)]) -> Arc<Liwan> {
    let mut config = Config::default();
    config.base_url = "https://liwan.example.com".to_string();
    config.rate_limit.auth_burst = 50;
    for (name, provider) in providers {
        config.oidc.providers.insert((*name).to_string(), provider.clone());
    }
    let app = Liwan::new_memory(config).unwrap();
    app.users.create("setup-admin", "correct-horse-battery", UserRole::Admin).unwrap();
    app.onboarding.clear();
    app
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

async fn run_flow(
    app: &Arc<Liwan>,
    portal: &MockForseti,
    client: &common::TestClient,
    provider: &str,
) -> axum_test::TestResponse {
    let start = client.get(&format!("/api/dashboard/auth/external/start?provider={provider}")).await;
    let state = common::cookies(&start)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-external-auth-state")
        .expect("state cookie")
        .value()
        .to_string();
    *portal.nonce.lock().unwrap() = app.external_auth.peek_nonce(&state).expect("pending flow");

    client
        .get_with_headers(
            &format!("/api/dashboard/auth/external/callback?code=abc&state={state}"),
            vec![("cookie".to_string(), format!("liwan-external-auth-state={state}"))],
        )
        .await
}

async fn post_purge(client: &common::TestClient, provider: &str, token: &str) -> axum_test::TestResponse {
    client
        .post_raw(
            &format!("/api/dashboard/auth/external/{provider}/account-deletion"),
            SET_CONTENT_TYPE,
            token.as_bytes(),
        )
        .await
}

#[tokio::test]
async fn a_forseti_provider_asks_for_groups_and_offers_a_manage_link() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, Some(GroupsConfig::default())))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // `kind = "forseti"` with a groups table asks for the `groups` scope.
    let start = client.get("/api/dashboard/auth/external/start?provider=company").await;
    let query: std::collections::HashMap<_, _> =
        url::Url::parse(&location(&start))?.query_pairs().into_owned().collect();
    let scopes = query.get("scope").expect("scope parameter").split(' ').collect::<Vec<_>>();
    assert!(scopes.contains(&"groups"), "got: {scopes:?}");

    let response = run_flow(&app, &portal, &client, "company").await;
    let session = session_cookie(&response).expect("session cookie");

    // `/auth/me` carries the handoff link built from the portal's own document.
    let me = client
        .get_with_headers(
            "/api/dashboard/auth/me",
            vec![("cookie".to_string(), format!("liwan-session={session}; liwan-username=tester"))],
        )
        .await;
    me.assert_status_success();
    let account = me.json::<Value>()["externalAccount"].clone();
    assert_eq!(account["provider"], "Forseti");
    let manage_url = account["manageUrl"].as_str().expect("manage url");
    assert!(manage_url.starts_with(&format!("{}/handoff?", portal.issuer)), "got: {manage_url}");
    assert!(manage_url.contains("referrer=liwan"), "got: {manage_url}");
    assert!(manage_url.contains("action=profile"), "got: {manage_url}");
    assert!(manage_url.contains("referrer_uri=https%3A%2F%2Fliwan.example.com%2Fsettings%2Fme"), "got: {manage_url}");
    Ok(())
}

#[tokio::test]
async fn forseti_groups_drive_the_role_and_teams() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let groups = GroupsConfig {
        admin: vec!["liwan-admins".to_string()],
        teams: [("liwan-admins".to_string(), vec!["ops".to_string()])].into(),
        ..Default::default()
    };
    let app = app_with(&[("company", forseti_provider(&portal.issuer, Some(groups)))]);
    app.teams.create_with_id("ops", "Ops")?;
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    portal.set_groups(Some(&["liwan-admins"]));
    let response = run_flow(&app, &portal, &client, "company").await;
    assert_eq!(app.users.get("tester")?.role, UserRole::Admin);
    let me = client.get_with_headers("/api/dashboard/auth/me", common::mock_idp::session_headers(&response)).await;
    assert_eq!(me.json::<Value>()["role"], "admin");
    let ops = app.teams.all()?.into_iter().find(|team| team.id == "ops").expect("ops team");
    assert_eq!(ops.users, ["tester"]);

    portal.set_groups(Some(&[]));
    run_flow(&app, &portal, &client, "company").await;
    assert_eq!(app.users.get("tester")?.role, UserRole::User);
    assert!(app.teams.all()?.iter().all(|team| team.users.is_empty()));
    Ok(())
}

#[tokio::test]
async fn the_deletion_webhook_removes_an_sso_only_account() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let response = run_flow(&app, &portal, &client, "company").await;
    let session = session_cookie(&response).expect("session cookie");
    assert!(app.users.get("tester").is_ok());

    let token = portal.purge_token("kratos-identity-id", json!({}));
    let response = post_purge(&client, "company", &token).await;
    response.assert_status_ok();
    assert_eq!(response.headers().get("cache-control").and_then(|value| value.to_str().ok()), Some("no-store"));

    assert!(app.users.get("tester").is_err(), "the account is gone");
    assert!(app.sessions.get(&session)?.is_none(), "and so are its sessions");
    Ok(())
}

#[tokio::test]
async fn the_deletion_webhook_only_unlinks_an_account_with_a_password() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // An account that predates SSO, attached with `link-oidc`.
    app.users.create("franz", "correct-horse-battery", UserRole::Admin)?;
    app.external_auth.link("franz", &portal.issuer, "kratos-identity-id", false)?;
    let response = run_flow(&app, &portal, &client, "company").await;
    assert_eq!(location(&response), "/");

    let token = portal.purge_token("kratos-identity-id", json!({}));
    post_purge(&client, "company", &token).await.assert_status_ok();

    // Losing the IdP must not lose an account that can still sign in locally.
    let user = app.users.get("franz")?;
    assert_eq!(user.role, UserRole::Admin);
    assert!(app.users.check_login("franz", "correct-horse-battery")?);
    assert!(app.external_auth.account_for("franz").await?.is_none(), "the link is gone");
    Ok(())
}

#[tokio::test]
async fn an_unknown_subject_is_accepted_and_ignored() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    run_flow(&app, &portal, &client, "company").await;

    // Already gone, or never ours: either way there is nothing to retry.
    let token = portal.purge_token("somebody-else", json!({}));
    post_purge(&client, "company", &token).await.assert_status_ok();
    assert!(app.users.get("tester").is_ok());
    Ok(())
}

#[tokio::test]
async fn a_repeated_delivery_is_accepted_once() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    run_flow(&app, &portal, &client, "company").await;

    let token = portal.purge_token("kratos-identity-id", json!({}));
    post_purge(&client, "company", &token).await.assert_status_ok();
    assert!(app.users.get("tester").is_err());

    // Forseti retries until it gets a 2xx; the retry must not delete a fresh
    // account that happens to have taken the name since.
    app.users.create("tester", "correct-horse-battery", UserRole::User)?;
    post_purge(&client, "company", &token).await.assert_status_ok();
    assert!(app.users.get("tester").is_ok(), "the retry was a no-op");
    Ok(())
}

#[tokio::test]
async fn a_security_event_token_that_does_not_verify_changes_nothing() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);
    run_flow(&app, &portal, &client, "company").await;

    let now = chrono::Utc::now().timestamp();
    let subject = "kratos-identity-id";
    let cases: Vec<(&str, String)> = vec![
        ("wrong issuer", portal.purge_token(subject, json!({ "iss": "https://evil.example" }))),
        ("wrong audience", portal.purge_token(subject, json!({ "aud": "someone-else" }))),
        ("stale iat", portal.purge_token(subject, json!({ "iat": now - 600 }))),
        ("iat in the future", portal.purge_token(subject, json!({ "iat": now + 600 }))),
        ("wrong typ", portal.purge_token(subject, json!({ "typ": "JWT" }))),
        ("missing event", portal.purge_token(subject, json!({ "events": { "something/else": {} } }))),
    ];

    for (name, token) in cases {
        let response = post_purge(&client, "company", &token).await;
        assert_eq!(response.status_code(), 400, "{name} should be refused");
        assert!(response.text().is_empty(), "{name} leaked a body");
        assert!(app.users.get("tester").is_ok(), "{name} deleted the account");
    }

    // A token nobody signed, and one with the wrong content type.
    let real = portal.purge_token(subject, json!({}));
    let tampered = format!("{}x", &real[..real.len() - 1]);
    post_purge(&client, "company", &tampered).await.assert_status_bad_request();
    client
        .post_raw("/api/dashboard/auth/external/company/account-deletion", "application/json", real.as_bytes())
        .await
        .assert_status_bad_request();
    assert!(app.users.get("tester").is_ok());
    Ok(())
}

#[tokio::test]
async fn the_webhook_is_only_offered_by_a_forseti_provider() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[
        ("company", forseti_provider(&portal.issuer, None)),
        (
            "plain",
            ProviderConfig {
                issuer: Some(portal.issuer.clone()),
                client_id: TEST_CLIENT_ID.to_string(),
                client_secret: TEST_CLIENT_SECRET.to_string(),
                ..Default::default()
            },
        ),
    ]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app, tx);

    let token = portal.purge_token("kratos-identity-id", json!({}));
    post_purge(&client, "nobody", &token).await.assert_status_not_found();
    // A generic OIDC provider has no portal to have sent this.
    post_purge(&client, "plain", &token).await.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn a_portal_without_a_reachable_document_still_signs_people_in() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    portal.configuration_broken.store(true, Ordering::Relaxed);
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // The extras go quiet; login does not.
    let response = run_flow(&app, &portal, &client, "company").await;
    assert_eq!(location(&response), "/");
    let session = session_cookie(&response).expect("session cookie");

    let me = client
        .get_with_headers(
            "/api/dashboard/auth/me",
            vec![("cookie".to_string(), format!("liwan-session={session}; liwan-username=tester"))],
        )
        .await;
    assert_eq!(me.json::<Value>()["externalAccount"]["manageUrl"], Value::Null);

    // Without the document there is no key set, so nothing can be verified.
    let token = portal.purge_token("kratos-identity-id", json!({}));
    post_purge(&client, "company", &token).await.assert_status_not_found();
    assert!(app.users.get("tester").is_ok());
    Ok(())
}

#[tokio::test]
async fn a_second_subject_at_the_same_portal_is_a_second_account() -> Result<()> {
    let portal = spawn_mock_forseti().await;
    let app = app_with(&[("company", forseti_provider(&portal.issuer, None))]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    run_flow(&app, &portal, &client, "company").await;
    portal.set_sub("another-identity-id");
    run_flow(&app, &portal, &client, "company").await;
    assert_eq!(app.users.all()?.len(), 3, "the setup admin plus two people");

    // Deleting one leaves the other alone.
    let token = portal.purge_token("kratos-identity-id", json!({}));
    post_purge(&client, "company", &token).await.assert_status_ok();
    assert_eq!(app.users.all()?.len(), 2);
    Ok(())
}
