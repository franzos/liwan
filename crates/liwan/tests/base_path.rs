use anyhow::Result;
use axum_extra::extract::cookie::Cookie;
use common::mock_idp::{MockIdp, STATE_COOKIE, location, provider, session_headers, spawn_mock_idp};
use liwan::{
    app::{Liwan, models::UserRole},
    config::Config,
};
use std::sync::Arc;

mod common;

#[test]
fn validates_base_url_path() {
    let config = Config::load(None, [("LIWAN_BASE_URL", "https://example.com/liwan")]).unwrap();
    assert_eq!(config.base_path(), "/liwan");
    assert_eq!(config.path("/login"), "/liwan/login");
    let mut setup = config.public_url("/setup").unwrap();
    setup.query_pairs_mut().append_pair("t", "a+b/c");
    assert_eq!(setup.as_str(), "https://example.com/liwan/setup?t=a%2Bb%2Fc");
    let uppercase = Config::load(None, [("LIWAN_BASE_URL", "HTTPS://example.com/liwan")]).unwrap();
    assert!(uppercase.secure());
    assert_eq!(Config::default().base_path(), "");
    assert_eq!(Config::default().path("/login"), "/login");
    for url in [
        "https://example.com/liwan/",
        "https://example.com/liwan?x=1",
        "https://example.com/liwan#fragment",
        "https://example.com/liwan/../other",
        "https://example.com//liwan",
    ] {
        assert!(Config::load(None, [("LIWAN_BASE_URL", url)]).is_err(), "{url}");
    }
}

fn sub_path_app(idp: &MockIdp) -> Arc<Liwan> {
    let mut config = Config::default();
    config.base_url = "https://liwan.example.com/liwan".to_string();
    config.rate_limit.auth_burst = 50;
    config.oidc.providers.insert("company".to_string(), provider(&idp.issuer));
    let app = Liwan::new_memory(config).unwrap();
    app.users.create("setup-admin", "correct-horse-battery", UserRole::Admin).unwrap();
    app.onboarding.clear();
    app
}

/// Starts a flow under the sub-path and returns the state cookie the browser got.
async fn start(app: &Liwan, idp: &MockIdp, client: &common::TestClient, return_to: &str) -> Cookie<'static> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("provider", "company")
        .append_pair("returnTo", return_to)
        .finish();
    let response = client.get(&format!("/liwan/api/dashboard/auth/external/start?{query}")).await;
    response.assert_status_see_other();
    let target = url::Url::parse(&location(&response)).unwrap();
    let redirect_uri = target.query_pairs().find(|(key, _)| key == "redirect_uri").map(|(_, value)| value.into_owned());
    assert_eq!(redirect_uri.as_deref(), Some("https://liwan.example.com/liwan/api/dashboard/auth/external/callback"));

    let cookie = common::cookies(&response).into_iter().find(|cookie| cookie.name() == STATE_COOKIE).expect("state");
    *idp.nonce.lock().unwrap() = app.external_auth.peek_nonce(cookie.value()).expect("pending flow");
    cookie
}

async fn callback(client: &common::TestClient, state: &Cookie<'_>, extra: &str) -> axum_test::TestResponse {
    client
        .get_with_headers(
            &format!("/liwan/api/dashboard/auth/external/callback?code=abc&state={}{extra}", state.value()),
            vec![("cookie".to_string(), format!("{STATE_COOKIE}={}", state.value()))],
        )
        .await
}

#[tokio::test]
async fn sso_signs_in_under_a_sub_path() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = sub_path_app(&idp);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    let state = start(&app, &idp, &client, "/liwan/settings").await;
    // A browser only sends the cookie back to a path under this one.
    assert_eq!(state.path(), Some("/liwan/api/dashboard/auth/external/callback"));

    let response = callback(&client, &state, "").await;
    assert_eq!(location(&response), "/liwan/settings");
    let session = common::cookies(&response)
        .into_iter()
        .find(|cookie| cookie.name() == "liwan-session" && !cookie.value().is_empty())
        .expect("session cookie");
    assert_eq!(session.path(), Some("/liwan/api/dashboard"));
    let me = client.get_with_headers("/liwan/api/dashboard/auth/me", session_headers(&response)).await;
    me.assert_status_success();
    assert_eq!(me.json::<serde_json::Value>()["username"], "jose-muller");

    // The default return path is the sub-path root, not the host root.
    let state = start(&app, &idp, &client, "/").await;
    assert_eq!(location(&callback(&client, &state, "").await), "/liwan/");

    client
        .get("/liwan/api/dashboard/auth/external/start?provider=company&returnTo=%2Fsettings")
        .await
        .assert_status_bad_request();
    Ok(())
}

#[tokio::test]
async fn sso_errors_redirect_into_the_sub_path() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let app = sub_path_app(&idp);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // With a valid state cookie, so the redirect comes from past the state check.
    let state = start(&app, &idp, &client, "/liwan/").await;
    let response = callback(&client, &state, "&error=access_denied").await;
    assert_eq!(location(&response), "/liwan/login?externalAuthError=provider_error");
    let cleared = common::cookies(&response).into_iter().find(|cookie| cookie.name() == STATE_COOKIE).expect("removal");
    assert_eq!((cleared.value(), cleared.path()), ("", Some("/liwan/api/dashboard/auth/external/callback")));

    // The same flow cannot be finished afterwards.
    assert_eq!(location(&callback(&client, &state, "").await), "/liwan/login?externalAuthError=unavailable");

    client
        .get("/liwan/api/dashboard/auth/external/callback?state=anything&code=unused")
        .await
        .assert_header("location", "/liwan/login?externalAuthError=state_mismatch");
    Ok(())
}
