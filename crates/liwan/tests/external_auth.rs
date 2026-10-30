use anyhow::Result;
use common::mock_idp::{
    MockIdp, location, provider, run_flow, session_cookie, session_headers, spawn_mock_idp, state_cookie,
};
use liwan::{
    app::{
        Liwan,
        models::{AccessScope, Project, ProjectVisibility, UserRole},
    },
    config::{Config, GroupsConfig, ProviderConfig, Registration},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

mod common;

fn app_with(providers: &[(&str, ProviderConfig)]) -> Arc<Liwan> {
    let app = Liwan::new_memory(config_with(providers)).unwrap();
    // Onboarding hides SSO entirely, so every test starts past it.
    app.users.create("setup-admin", "correct-horse-battery", UserRole::Admin).unwrap();
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

fn signed_in(app: &Liwan, session: &str) -> bool {
    app.sessions.get(session).unwrap().is_some()
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

    app.users.create("admin", "correct-horse-battery", UserRole::Admin)?;
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
    app.users.create("admin", "correct-horse-battery", UserRole::Admin)?;
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
    let session = session_cookie(&response).expect("a session cookie is set");

    // The username is transliterated from the claims; no password is set.
    let user = app.users.get("jose-muller")?;
    assert_eq!(user.role, UserRole::User);
    let access = app.sessions.get(&session)?.expect("session resolves").access;
    assert!(
        matches!(&access.projects, AccessScope::Selected(ids) if ids.is_empty()),
        "a new SSO user has no project access"
    );
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
            "/api/dashboard/auth/me/password",
            json!({ "password": "a-new-local-password", "currentPassword": "anything" }),
            vec![("cookie".to_string(), format!("liwan-session={session}; liwan-username=jose-muller"))],
        )
        .await;
    response.assert_status_conflict();
    assert!(!app.users.check_login("jose-muller", "a-new-local-password")?);

    // Nor can another admin set one for it.
    app.users.create("admin", "correct-horse-battery", UserRole::Admin)?;
    let cookies = common::login(&client, "admin", "correct-horse-battery").await;
    let response = client
        .put_with_headers(
            "/api/dashboard/user/jose-muller/password",
            json!({ "password": "a-new-local-password" }),
            vec![("cookie".to_string(), common::cookie_header(&cookies))],
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
    app.users.create("known", "correct-horse-battery", UserRole::User)?;
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

// -- group mapping ------------------------------------------------------------

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn team_mapping(pairs: &[(&str, &[&str])]) -> std::collections::BTreeMap<String, Vec<String>> {
    pairs.iter().map(|(group, teams)| ((*group).to_string(), strings(teams))).collect()
}

/// An app whose `company` provider carries `groups`, with each `(team, project)`
/// created up front: a private project that only that team can read.
fn mapped_app(idp: &MockIdp, groups: GroupsConfig, teams: &[(&str, &str)]) -> Arc<Liwan> {
    let app = app_with(&[("company", ProviderConfig { groups: Some(groups), ..provider(&idp.issuer) })]);
    for (team, project) in teams {
        app.teams.create_with_id(team, team).unwrap();
        app.projects
            .create(
                &Project {
                    id: (*project).to_string(),
                    display_name: (*project).to_string(),
                    visibility: ProjectVisibility::Private,
                    secret: None,
                },
                &[],
            )
            .unwrap();
        app.teams.update(team, team, &[], &AccessScope::Selected(vec![(*project).to_string()]), None).unwrap();
    }
    app
}

fn teams_of(app: &Liwan, username: &str) -> Vec<String> {
    let mut teams: Vec<String> = app
        .teams
        .all()
        .unwrap()
        .into_iter()
        .filter(|team| team.users.iter().any(|user| user == username))
        .map(|team| team.id)
        .collect();
    teams.sort();
    teams
}

async fn me(client: &common::TestClient, headers: &[(String, String)]) -> axum_test::TestResponse {
    client.get_with_headers("/api/dashboard/auth/me", headers.to_vec()).await
}

/// The project ids the dashboard lists for this session.
async fn visible_projects(client: &common::TestClient, headers: &[(String, String)]) -> Vec<String> {
    let response = client.get_with_headers("/api/dashboard/projects", headers.to_vec()).await;
    response.assert_status_success();
    let mut ids: Vec<String> = response.json::<Value>()["projects"]
        .as_array()
        .expect("projects")
        .iter()
        .map(|project| project["id"].as_str().expect("project id").to_string())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn the_groups_gate_keeps_non_members_out() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        allowed: strings(&["analytics"]),
        teams: team_mapping(&[("analytics", &["marketing"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
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
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    assert_eq!(teams_of(&app, "jose-muller"), ["marketing"]);
    assert_eq!(visible_projects(&client, &session_headers(&response)).await, ["blog"]);
    Ok(())
}

#[tokio::test]
async fn groups_drive_the_role_and_team_membership() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        admin: strings(&["liwan-admins"]),
        teams: team_mapping(&[("blog-team", &["marketing"]), ("app", &["eng"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog"), ("eng", "app")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["liwan-admins", "app"]));
    let first = session_headers(&run_flow(&app, &idp, &client, "company", "/").await);
    assert_eq!(teams_of(&app, "jose-muller"), ["eng"]);
    assert_eq!(me(&client, &first).await.json::<Value>()["role"], "admin");

    // Both the role and the team set are replaced, not added to.
    idp.set_groups(Some(&["blog-team"]));
    let second = session_headers(&run_flow(&app, &idp, &client, "company", "/").await);
    assert_eq!(teams_of(&app, "jose-muller"), ["marketing"]);
    assert_eq!(app.users.get("jose-muller")?.role, UserRole::User);
    assert_eq!(me(&client, &second).await.json::<Value>()["role"], "user");
    assert_eq!(visible_projects(&client, &second).await, ["blog"]);
    assert_eq!(visible_projects(&client, &first).await, ["blog"], "the earlier session follows the account");
    Ok(())
}

#[tokio::test]
async fn the_default_team_is_joined_on_first_login() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig { default_team: Some("everyone".to_string()), ..Default::default() };
    let app = mapped_app(&idp, groups, &[("everyone", "handbook"), ("staff", "payroll")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // No groups claim at all: the default team does not depend on one.
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    let headers = session_headers(&response);
    assert_eq!(teams_of(&app, "jose-muller"), ["everyone"]);
    assert_eq!(me(&client, &headers).await.json::<Value>()["username"], "jose-muller");
    assert_eq!(visible_projects(&client, &headers).await, ["handbook"]);
    Ok(())
}

#[tokio::test]
async fn unknown_team_ids_are_skipped_not_fatal() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        default_team: Some("nowhere".to_string()),
        teams: team_mapping(&[("blog-team", &["ghost", "marketing"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["blog-team"]));
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    assert_eq!(teams_of(&app, "jose-muller"), ["marketing"]);
    assert_eq!(visible_projects(&client, &session_headers(&response)).await, ["blog"]);
    assert!(app.teams.all()?.iter().all(|team| team.id == "marketing"), "no team was created on the fly");
    Ok(())
}

#[tokio::test]
async fn a_removed_group_revokes_access_on_the_next_login() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig { teams: team_mapping(&[("blog-team", &["marketing"])]), ..Default::default() };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["blog-team"]));
    let first = session_headers(&run_flow(&app, &idp, &client, "company", "/").await);
    assert_eq!(visible_projects(&client, &first).await, ["blog"]);

    // Without an allowed-groups gate the login still succeeds, with nothing in it.
    idp.set_groups(Some(&["sales"]));
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    assert!(teams_of(&app, "jose-muller").is_empty());
    assert!(visible_projects(&client, &session_headers(&response)).await.is_empty());
    assert!(visible_projects(&client, &first).await.is_empty(), "the earlier session lost the project too");
    Ok(())
}

#[tokio::test]
async fn group_mapping_leaves_a_linked_password_account_alone() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        admin: strings(&["liwan-admins"]),
        teams: team_mapping(&[("blog-team", &["marketing"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    app.users.create("franz", "correct-horse-battery", UserRole::Admin)?;
    app.teams.create_with_id("editors", "Editors")?;
    app.users.update("franz", UserRole::Admin, &strings(&["editors"]))?;
    app.external_auth.link("franz", &idp.issuer, "sub-abc", false)?;
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // No admin group, and a group mapped elsewhere, yet the local admin keeps everything.
    idp.set_groups(Some(&["blog-team"]));
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    assert_eq!(app.users.get("franz")?.role, UserRole::Admin);
    assert_eq!(teams_of(&app, "franz"), ["editors"]);
    assert_eq!(me(&client, &session_headers(&response)).await.json::<Value>()["role"], "admin");
    assert!(app.users.check_login("franz", "correct-horse-battery")?);
    Ok(())
}

#[tokio::test]
async fn groups_overage_is_rejected_with_its_own_code() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig { teams: team_mapping(&[("blog-team", &["marketing"])]), ..Default::default() };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    // Entra's distributed-claims form: the list lives behind a Graph call.
    idp.set_groups(None).set_claim("_claim_names", json!({ "groups": "src1" })).set_claim(
        "_claim_sources",
        json!({ "src1": { "endpoint": "https://graph.microsoft.com/v1.0/me/getMemberObjects" } }),
    );
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    response.assert_header("location", "/login?externalAuthError=groups_incomplete");
    assert_eq!(session_cookie(&response), None);
    assert_eq!(app.users.all()?.len(), 1, "nobody was provisioned");
    Ok(())
}

#[tokio::test]
async fn overage_is_ignored_without_a_mapping() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let plain = spawn_mock_idp().await;
    let app = app_with(&[
        (
            "company",
            ProviderConfig {
                groups: Some(GroupsConfig { default_team: Some("everyone".to_string()), ..Default::default() }),
                ..provider(&idp.issuer)
            },
        ),
        ("plain", provider(&plain.issuer)),
    ]);
    app.teams.create_with_id("everyone", "Everyone")?;
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    plain.set_name(Some("Plain Person"));
    for mock in [&idp, &plain] {
        mock.set_claim("hasgroups", json!(true)).set_claim("_claim_names", json!({ "groups": "src1" }));
    }

    // A default team alone does not read the list, so its absence changes nothing.
    let response = run_flow(&app, &idp, &client, "company", "/").await;
    assert_eq!(location(&response), "/");
    me(&client, &session_headers(&response)).await.assert_status_success();
    assert_eq!(teams_of(&app, "jose-muller"), ["everyone"]);

    let response = run_flow(&app, &plain, &client, "plain", "/").await;
    assert_eq!(location(&response), "/");
    me(&client, &session_headers(&response)).await.assert_status_success();
    assert!(teams_of(&app, "plain-person").is_empty());
    Ok(())
}

#[tokio::test]
async fn a_rejected_login_ends_sessions_and_teams() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        allowed: strings(&["analytics"]),
        teams: team_mapping(&[("analytics", &["marketing"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["analytics"]));
    let first = session_headers(&run_flow(&app, &idp, &client, "company", "/").await);
    me(&client, &first).await.assert_status_success();
    assert_eq!(visible_projects(&client, &first).await, ["blog"]);

    idp.set_groups(Some(&["sales"]));
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=access_denied");
    me(&client, &first).await.assert_status_unauthorized();
    assert!(teams_of(&app, "jose-muller").is_empty());
    Ok(())
}

#[tokio::test]
async fn an_incomplete_group_list_rejects_without_revoking() -> Result<()> {
    let idp = spawn_mock_idp().await;
    let groups = GroupsConfig {
        allowed: strings(&["analytics"]),
        teams: team_mapping(&[("analytics", &["marketing"])]),
        ..Default::default()
    };
    let app = mapped_app(&idp, groups, &[("marketing", "blog")]);
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    idp.set_groups(Some(&["analytics"]));
    let first = session_headers(&run_flow(&app, &idp, &client, "company", "/").await);

    // An overage marker is an IdP or config problem, not a statement about the person.
    idp.set_groups(None).set_claim("hasgroups", json!(true));
    run_flow(&app, &idp, &client, "company", "/")
        .await
        .assert_header("location", "/login?externalAuthError=groups_incomplete");
    me(&client, &first).await.assert_status_success();
    assert_eq!(teams_of(&app, "jose-muller"), ["marketing"]);
    assert_eq!(visible_projects(&client, &first).await, ["blog"]);
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
