use aide::{
    UseApi,
    axum::{ApiRouter, IntoApiResponse, routing::*},
};
use anyhow::Context;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use http::{StatusCode, header};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use crate::{
    PASSWORD_MIN_LENGTH,
    app::models::UserRole,
    utils::hash::session_token,
    web::{
        MaybeSessionId, RouterState,
        session::{
            Auth, LOGOUT_COOKIES, MAX_SESSION_AGE, OIDC_STATE_COOKIE, OIDC_STATE_COOKIE_NAME, PUBLIC_COOKIE,
            SESSION_COOKIE,
        },
        webext::{ApiResult, AxumErrExt, empty_response, http_bail},
    },
};

pub fn router() -> ApiRouter<RouterState> {
    let limiter = GovernorConfigBuilder::default().per_second(2).burst_size(5).finish().expect("valid governor config");

    let governor_limiter = limiter.limiter().clone();
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_hours(1));
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    ApiRouter::new()
        .layer(GovernorLayer::new(limiter))
        .api_route("/auth/me", get(me))
        .api_route("/auth/setup", post(setup))
        .api_route("/auth/login", post(login))
        .api_route("/auth/logout", post(logout))
        // Plain axum routes (browser redirects, not part of the documented JSON API).
        .route("/auth/oidc/login", axum::routing::get(oidc_login))
        .route("/auth/oidc/callback", axum::routing::get(oidc_callback))
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SetupRequest {
    pub token: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, JsonSchema)]
pub struct MeResponse {
    pub username: String,
    pub role: UserRole,
}

async fn me(Auth(user): Auth) -> UseApi<impl IntoApiResponse, Json<MeResponse>> {
    ([(header::CACHE_CONTROL, "private")], Json(MeResponse { username: user.username, role: user.role })).into()
}

async fn setup(app: State<RouterState>, Json(params): Json<SetupRequest>) -> ApiResult<impl IntoApiResponse> {
    let token = app.onboarding.token().http_status(StatusCode::INTERNAL_SERVER_ERROR)?.clone();

    if token != Some(params.token) {
        http_bail!(StatusCode::UNAUTHORIZED, "invalid setup token");
    }

    if params.password.len() < PASSWORD_MIN_LENGTH {
        http_bail!(StatusCode::BAD_REQUEST, "password must be at least 8 characters long");
    }

    app.users
        .create(&params.username, &params.password, UserRole::Admin, &[])
        .http_err("failed to create user", StatusCode::INTERNAL_SERVER_ERROR)?;

    app.onboarding.clear().context("onboarding lock poisoned").http_status(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(empty_response())
}

async fn login(
    app: State<RouterState>,
    cookies: CookieJar,
    Json(params): Json<LoginRequest>,
) -> ApiResult<impl IntoApiResponse> {
    let username = params.username.clone();

    let app2 = app.clone();
    let authorized =
        spawn_blocking(move || app2.users.check_login(&params.username, &params.password).unwrap_or(false))
            .await
            .unwrap_or(false);

    if !(authorized) {
        http_bail!(StatusCode::UNAUTHORIZED, "invalid username or password");
    }

    let session_id = session_token();
    let expires = Utc::now() + MAX_SESSION_AGE;
    app.sessions.create(&session_id, &username, expires).http_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut public_cookie = PUBLIC_COOKIE.clone();
    let mut session_cookie = SESSION_COOKIE.clone();
    public_cookie.set_secure(app.config.secure());
    public_cookie.set_value(username.clone());
    session_cookie.set_secure(app.config.secure());
    session_cookie.set_value(session_id);

    let cookies = cookies.add(public_cookie).add(session_cookie);
    Ok((cookies, empty_response()))
}

async fn logout(
    app: State<RouterState>,
    MaybeSessionId(session_id): MaybeSessionId,
) -> ApiResult<impl IntoApiResponse> {
    if let Some(session_id) = session_id {
        let _ = app.sessions.delete(&session_id);
    }
    Ok((LOGOUT_COOKIES.clone(), empty_response()))
}

#[derive(Deserialize, JsonSchema)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Begin the OIDC authorization-code flow: store transient state server-side,
/// set the Lax state cookie, and redirect to the IdP. 404 when OIDC is disabled.
async fn oidc_login(app: State<RouterState>, cookies: CookieJar) -> ApiResult<Response> {
    let Some(oidc) = app.oidc.as_ref() else {
        return Err(StatusCode::NOT_FOUND.into());
    };
    let _ = app.oidc_state.cleanup_expired();

    let start = match oidc.start_login().await {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(?err, "OIDC discovery/login start failed");
            return Ok((cookies, Redirect::to("/login?error=oidc_unavailable")).into_response());
        }
    };

    let expires = Utc::now() + chrono::Duration::seconds(600);
    app.oidc_state
        .create(&start.state, &start.nonce, &start.pkce_verifier, expires)
        .http_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut cookie = OIDC_STATE_COOKIE.clone();
    cookie.set_secure(app.config.secure());
    cookie.set_value(start.state.clone());

    Ok((cookies.add(cookie), Redirect::to(&start.auth_url)).into_response())
}

/// Handle the IdP redirect: validate state, exchange the code, verify the
/// id_token, provision/find the local user, and mint a local session. Failures
/// redirect to `/login?error=<code>` with details logged server-side.
async fn oidc_callback(
    app: State<RouterState>,
    cookies: CookieJar,
    Query(params): Query<CallbackParams>,
) -> ApiResult<Response> {
    if app.oidc.is_none() {
        return Err(StatusCode::NOT_FOUND.into());
    }

    // Read the incoming state cookie BEFORE adding the removal cookie of the
    // same name (otherwise `get` would return the cleared value).
    let cookie_state = cookies.get(OIDC_STATE_COOKIE_NAME).map(|c| c.value().to_string());

    // Clear the state cookie regardless of outcome.
    let mut clear = OIDC_STATE_COOKIE.clone();
    clear.set_secure(app.config.secure());
    clear.make_removal();
    let cookies = cookies.add(clear);

    fn fail(cookies: CookieJar, code: &str) -> Response {
        (cookies, Redirect::to(&format!("/login?error={code}"))).into_response()
    }

    if params.error.is_some() {
        return Ok(fail(cookies, "idp_error"));
    }

    let (Some(code), Some(query_state), Some(cookie_state)) = (params.code, params.state, cookie_state) else {
        return Ok(fail(cookies, "state_mismatch"));
    };
    if query_state != cookie_state {
        return Ok(fail(cookies, "state_mismatch"));
    }

    let Some((nonce, pkce_verifier)) =
        app.oidc_state.take(&query_state).http_status(StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Ok(fail(cookies, "state_mismatch"));
    };

    let oidc = app.oidc.as_ref().expect("checked above");
    let claims = match oidc.finish_login(code, pkce_verifier, &nonce).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(?err, "OIDC token exchange / id_token verification failed");
            return Ok(fail(cookies, "token_exchange_failed"));
        }
    };

    let app2 = app.app.clone();
    let user = match spawn_blocking(move || {
        app2.users.provision_oidc(
            &claims.issuer,
            &claims.subject,
            claims.email.as_deref(),
            claims.preferred_username.as_deref(),
            claims.name.as_deref(),
        )
    })
    .await
    {
        Ok(Ok(u)) => u,
        Ok(Err(err)) => {
            tracing::warn!(?err, "OIDC user provisioning failed");
            return Ok(fail(cookies, "provisioning_failed"));
        }
        Err(err) => {
            tracing::warn!(?err, "OIDC provisioning task panicked");
            return Ok(fail(cookies, "provisioning_failed"));
        }
    };

    let session_id = session_token();
    let expires = Utc::now() + MAX_SESSION_AGE;
    app.sessions.create(&session_id, &user.username, expires).http_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut public_cookie = PUBLIC_COOKIE.clone();
    let mut session_cookie = SESSION_COOKIE.clone();
    public_cookie.set_secure(app.config.secure());
    public_cookie.set_value(user.username.clone());
    session_cookie.set_secure(app.config.secure());
    session_cookie.set_value(session_id);

    Ok((cookies.add(public_cookie).add(session_cookie), Redirect::to("/")).into_response())
}
