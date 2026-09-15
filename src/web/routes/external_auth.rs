use std::{sync::LazyLock, time::Duration};

use aide::{
    UseApi,
    axum::{ApiRouter, IntoApiResponse, routing::*},
};
use axum::{
    Json,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use http::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use crate::{
    app::{ExternalAuthError, MAX_LOGOUT_BODY, MAX_WEBHOOK_BODY, SET_CONTENT_TYPE},
    config::{Config, ProviderKind},
    web::{
        RouterState,
        session::issue_external_session,
        webext::{ApiResult, ClientIpKeyExtractor, http_bail},
    },
};

const STATE_COOKIE_NAME: &str = "liwan-external-auth-state";

/// Deliveries an IdP may make up front, before the one-per-second refill applies.
const WEBHOOK_BURST: u32 = 60;

static STATE_COOKIE: LazyLock<Cookie<'static>> = LazyLock::new(|| {
    let mut cookie = Cookie::new(STATE_COOKIE_NAME, "");
    cookie.set_http_only(true);
    cookie.set_max_age(Some(Duration::from_secs(10 * 60).try_into().unwrap()));
    cookie.set_path("/api/dashboard/auth/external/callback");
    cookie.set_same_site(SameSite::Lax);
    cookie
});

static STATE_COOKIE_REMOVAL: LazyLock<Cookie<'static>> = LazyLock::new(|| {
    let mut cookie = STATE_COOKIE.clone();
    cookie.make_removal();
    cookie
});

/// Where a failed sign-in lands. The code drives the message the login page
/// shows; the reason behind it stays in the server log.
fn error_redirect(code: &str) -> String {
    format!("/login?externalAuthError={code}")
}

pub fn router(config: &Config) -> ApiRouter<RouterState> {
    let start_limiter = GovernorConfigBuilder::default()
        .per_second(config.rate_limit.auth_period_seconds)
        .burst_size(config.rate_limit.auth_burst)
        .key_extractor(ClientIpKeyExtractor::new(config))
        .finish()
        .expect("valid governor config");
    let callback_limiter = GovernorConfigBuilder::default()
        .per_second(config.rate_limit.auth_period_seconds)
        .burst_size(config.rate_limit.auth_burst)
        .key_extractor(ClientIpKeyExtractor::new(config))
        .finish()
        .expect("valid governor config");
    // The two receivers are server to server: one IdP address delivers for
    // everybody, and a mass logout or a bulk deletion is a legitimate burst.
    // They authenticate by signature, so the limit is only there to bound the
    // work an unsigned flood can cause.
    let webhook_limiter = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(WEBHOOK_BURST)
        .key_extractor(ClientIpKeyExtractor::new(config))
        .finish()
        .expect("valid governor config");
    let governors =
        [start_limiter.limiter().clone(), callback_limiter.limiter().clone(), webhook_limiter.limiter().clone()];
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_hours(1));
        loop {
            interval.tick().await;
            for governor in &governors {
                governor.retain_recent();
            }
        }
    });

    ApiRouter::new()
        .api_route("/auth/external", get(metadata))
        .merge(ApiRouter::new().api_route("/auth/external/start", get(start)).layer(GovernorLayer::new(start_limiter)))
        .merge(
            ApiRouter::new()
                .api_route("/auth/external/callback", get(callback))
                .layer(GovernorLayer::new(callback_limiter)),
        )
        .merge(
            ApiRouter::new()
                .api_route("/auth/external/{provider}/account-deletion", post(account_deletion))
                .api_route("/auth/external/{provider}/backchannel-logout", post(backchannel_logout))
                // Refuse an oversized body before it is buffered rather than
                // after: these take no authentication at all.
                .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY.max(MAX_LOGOUT_BODY)))
                .layer(GovernorLayer::new(webhook_limiter)),
        )
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExternalAuthProviderMetadata {
    name: String,
    kind: ProviderKind,
    display_name: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExternalAuthMetadata {
    providers: Vec<ExternalAuthProviderMetadata>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct StartQuery {
    provider: String,
    #[serde(default = "default_return_to")]
    return_to: String,
}

#[derive(Deserialize, JsonSchema)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

fn default_return_to() -> String {
    "/".to_string()
}

async fn metadata(app: State<RouterState>) -> UseApi<impl IntoApiResponse, Json<ExternalAuthMetadata>> {
    // Offering SSO before the first admin exists would let the IdP claim the
    // instance, so it stays hidden until setup is done.
    let onboarded = app.onboarding.token().is_none();
    let providers = if onboarded {
        app.external_auth
            .providers()
            .map(|(name, provider)| ExternalAuthProviderMetadata {
                name: name.clone(),
                kind: provider.kind,
                display_name: provider.display_name().to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };
    Json(ExternalAuthMetadata { providers }).into()
}

async fn start(
    app: State<RouterState>,
    cookies: CookieJar,
    Query(query): Query<StartQuery>,
) -> ApiResult<UseApi<Response, ()>> {
    if app.onboarding.token().is_some() {
        http_bail!(StatusCode::NOT_FOUND, "external authentication is unavailable");
    }
    let start = match app.external_auth.begin(&query.provider, &query.return_to).await {
        Ok(start) => start,
        Err(ExternalAuthError::UnknownProvider) => {
            http_bail!(StatusCode::NOT_FOUND, "external authentication is unavailable")
        }
        Err(error) => {
            tracing::warn!(provider = %query.provider, %error, "external authentication start failed");
            http_bail!(StatusCode::BAD_REQUEST, "external authentication is unavailable");
        }
    };
    let mut state_cookie = STATE_COOKIE.clone();
    state_cookie.set_secure(app.config.secure());
    state_cookie.set_value(start.state);
    Ok((cookies.add(state_cookie), Redirect::to(start.authorization_url.as_str())).into_response().into())
}

async fn callback(
    app: State<RouterState>,
    cookies: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> UseApi<Response, ()> {
    let cookie_state = cookies.get(STATE_COOKIE_NAME).map(|cookie| cookie.value().to_string());
    let Some(cookie_state) = cookie_state else {
        tracing::debug!("external authentication callback has no state cookie");
        return (cookies, Redirect::to(&error_redirect("state_mismatch"))).into_response().into();
    };
    if query.state.as_deref() != Some(cookie_state.as_str()) {
        tracing::debug!("external authentication callback has an invalid state");
        return (cookies, Redirect::to(&error_redirect("state_mismatch"))).into_response().into();
    }

    let mut removal = STATE_COOKIE_REMOVAL.clone();
    removal.set_secure(app.config.secure());
    let cookies = cookies.add(removal);
    if query.error.is_some() {
        app.external_auth.cancel(&cookie_state);
        tracing::debug!(provider_error = ?query.error, "external authentication callback was rejected");
        return (cookies, Redirect::to(&error_redirect("provider_error"))).into_response().into();
    }
    let Some(code) = query.code else {
        app.external_auth.cancel(&cookie_state);
        tracing::debug!("external authentication callback has no authorization code");
        return (cookies, Redirect::to(&error_redirect("provider_error"))).into_response().into();
    };

    let response = match app.external_auth.finish(&cookie_state, code).await {
        Ok(login) => match issue_external_session(&app, cookies.clone(), &login.username, login.sid.as_deref()) {
            Ok(cookies) => (cookies, Redirect::to(&login.return_to)).into_response(),
            Err(error) => {
                tracing::error!(%error, "failed to create external authentication session");
                (cookies, Redirect::to(&error_redirect("unavailable"))).into_response()
            }
        },
        Err(error) => {
            tracing::warn!(%error, "external authentication callback failed");
            (cookies, Redirect::to(&error_redirect(error.code()))).into_response()
        }
    };
    response.into()
}

/// Forseti's RISC receiver. Server to server: no cookies, no session, and every
/// rejection is one 400 without a body.
async fn account_deletion(
    app: State<RouterState>,
    Path(provider): Path<String>,
    headers: http::HeaderMap,
    body: Bytes,
) -> UseApi<Response, ()> {
    if !content_type_is(&headers, SET_CONTENT_TYPE) || body.len() > MAX_WEBHOOK_BODY {
        return empty(StatusCode::BAD_REQUEST).into();
    }

    match app.external_auth.handle_account_purged(&provider, &body).await {
        Ok(()) => empty(StatusCode::OK).into(),
        Err(ExternalAuthError::UnknownProvider) => empty(StatusCode::NOT_FOUND).into(),
        Err(error) => {
            tracing::warn!(%provider, %error, "account deletion webhook rejected");
            empty(StatusCode::BAD_REQUEST).into()
        }
    }
}

/// The OpenID Connect back-channel logout receiver. Server to server: the
/// caller's own cookies are never read or touched.
async fn backchannel_logout(
    app: State<RouterState>,
    Path(provider): Path<String>,
    headers: http::HeaderMap,
    body: Bytes,
) -> UseApi<Response, ()> {
    if !content_type_is(&headers, "application/x-www-form-urlencoded") || body.len() > MAX_LOGOUT_BODY {
        return empty(StatusCode::BAD_REQUEST).into();
    }
    let Some(token) = url::form_urlencoded::parse(&body)
        .find(|(name, _)| name == "logout_token")
        .map(|(_, value)| value.into_owned())
    else {
        return empty(StatusCode::BAD_REQUEST).into();
    };

    match app.external_auth.handle_backchannel_logout(&provider, &token).await {
        Ok(()) => empty(StatusCode::OK).into(),
        Err(ExternalAuthError::UnknownProvider) => empty(StatusCode::NOT_FOUND).into(),
        Err(error) => {
            tracing::warn!(%provider, %error, "back-channel logout rejected");
            empty(StatusCode::BAD_REQUEST).into()
        }
    }
}

/// Compares the media type, ignoring any parameters after it.
fn content_type_is(headers: &http::HeaderMap, expected: &str) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

/// Both receivers answer with a status and nothing else: an unauthenticated
/// caller learns whether the delivery was accepted, and not one thing more.
fn empty(status: StatusCode) -> Response {
    (status, [(http::header::CACHE_CONTROL, "no-store")]).into_response()
}
