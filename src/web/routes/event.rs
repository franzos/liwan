use crate::app::models::{
    FilterType, GeoDetail, IngestDropRule, IngestFilter, ResolvedCollectionSettings, VisitorGroupMode, hostname_allowed,
};
use crate::app::{Liwan, models::Event};
use crate::utils::hash::{visitor_group_id, visitor_group_id_cidr, visitor_group_id_fallback};
use crate::utils::ingest::{Utm, clean_referrer, extract_utm, normalize_url};
use crate::utils::referrer::{Referrer, process_referer};
use crate::utils::useragent;
use crate::web::RouterState;
use crate::web::webext::{ApiResult, AxumErrExt, ClientIp, empty_response};

use aide::axum::routing::post;
use aide::axum::{ApiRouter, IntoApiResponse};
use anyhow::{Context, Result};
use axum::Json;
use axum::extract::State;
use axum_extra::TypedHeader;
use chrono::Utc;
use http::StatusCode;
use schemars::JsonSchema;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use url::Url;

pub fn router() -> ApiRouter<RouterState> {
    let limiter =
        GovernorConfigBuilder::default().per_second(2).burst_size(10).finish().expect("valid governor config");
    let governor_limiter = limiter.limiter().clone();

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_hours(1));
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    ApiRouter::new().layer(GovernorLayer::new(limiter)).route("/event", post(event_handler))
}

#[derive(serde::Deserialize, JsonSchema)]
struct EventRequest {
    entity_id: String,
    name: String,
    url: String,
    referrer: Option<String>,
    screen_width: Option<String>,
    orientation: Option<String>,
}

impl EventRequest {
    fn validate(&self) -> Result<()> {
        if self.entity_id.trim().is_empty() {
            anyhow::bail!("entity_id cannot be empty");
        }
        if self.name.trim().is_empty() {
            anyhow::bail!("name cannot be empty");
        }

        if self.entity_id.len() > 255 {
            anyhow::bail!("entity_id cannot be longer than 255 characters");
        }

        if self.name.len() > 255 {
            anyhow::bail!("name cannot be longer than 255 characters");
        }

        if self.screen_width.as_deref().is_some_and(|w| w.len() > 20) {
            anyhow::bail!("screen_width cannot be longer than 20 characters");
        }

        if self.orientation.as_deref().is_some_and(|o| o.len() > 20) {
            anyhow::bail!("orientation cannot be longer than 20 characters");
        }

        if self.referrer.as_deref().is_some_and(|r| r.len() > 256) {
            anyhow::bail!("referrer cannot be longer than 256 characters");
        }

        if self.url.len() > 2048 {
            anyhow::bail!("url cannot be longer than 2048 characters");
        }

        Ok(())
    }
}

static EXISTING_ENTITIES: LazyLock<quick_cache::sync::Cache<String, ()>> =
    LazyLock::new(|| quick_cache::sync::Cache::new(512));

async fn event_handler(
    state: State<RouterState>,
    ClientIp(ip): ClientIp,
    TypedHeader(user_agent): TypedHeader<headers::UserAgent>,
    Json(event): Json<EventRequest>,
) -> ApiResult<impl IntoApiResponse> {
    let url = Url::from_str(&event.url).context("invalid url").http_err("invalid url", StatusCode::BAD_REQUEST)?;
    let app = state.app.clone();
    let events = state.events.clone();
    event.validate().context("invalid event").http_err("invalid event", StatusCode::BAD_REQUEST)?;

    // run the event processing in the background
    let res = tokio::task::spawn_blocking(move || process_event(app, event, url, ip, user_agent))
        .await
        .http_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    match res {
        Ok(Some(event)) => {
            if events.send_timeout(event, std::time::Duration::from_secs(2)).await.is_err() {
                tracing::warn!("Failed to send event, channel full");
            }
        }
        // event was filtered out, do nothing
        Ok(None) => {}
        Err(e) => tracing::warn!("Failed to process event: {:?}", e),
    };

    Ok(empty_response())
}

fn process_event(
    app: Arc<Liwan>,
    event: EventRequest,
    mut url: Url,
    ip: Option<IpAddr>,
    user_agent: headers::UserAgent,
) -> Result<Option<Event>> {
    let referrer = match process_referer(event.referrer.as_deref()) {
        Referrer::Fqdn(fqdn) => Some(fqdn),
        Referrer::Unknown(r) => r,
        Referrer::Spammer => return Ok(None),
        Referrer::Local => return Ok(None),
    };
    let referrer = clean_referrer(referrer);

    if EXISTING_ENTITIES.get(&event.entity_id).is_none() {
        if !app.entities.exists(&event.entity_id).unwrap_or(false) {
            return Ok(None);
        }
        EXISTING_ENTITIES.insert(event.entity_id.clone(), ());
    }

    let settings = app.settings.resolved_for_entity(&event.entity_id);
    let fqdn = url.host_str().unwrap_or_default().to_string();
    if !hostname_allowed(&fqdn, &settings.allowed_hostnames) {
        return Ok(None);
    }

    if useragent::is_crawler_header(user_agent.as_str()) {
        return Ok(None);
    }

    // we delay the user agent parsing as much as possible since it's by far the most expensive operation
    let client = useragent::parse(user_agent.as_str());
    if client.is_bot() {
        return Ok(None);
    }

    let visitor_group_id =
        resolve_visitor_group_id(&settings, ip, user_agent.as_str(), &app.events.get_salt()?, &event.entity_id);

    #[cfg(feature = "geoip")]
    let (country, city) = match settings.track_geo {
        GeoDetail::None => (None, None),
        GeoDetail::Country => ip
            .and_then(|ip| app.geoip.lookup(&ip).ok())
            .map(|lookup| (lookup.country_code, None))
            .unwrap_or((None, None)),
        GeoDetail::City => ip
            .and_then(|ip| app.geoip.lookup(&ip).ok())
            .map(|lookup| (lookup.country_code, lookup.city))
            .unwrap_or((None, None)),
    };

    #[cfg(not(feature = "geoip"))]
    let (country, city) = (None, None);

    let utm = if settings.track_utm_params { extract_utm(&mut url) } else { Utm::default() };
    let (path, fqdn) = normalize_url(url);

    let event = Event {
        visitor_group_id,
        referrer,
        country,
        city,
        mobile: Some(client.is_mobile()),
        browser: client.ua_family,
        platform: client.os_family,
        created_at: Utc::now(),
        entity_id: event.entity_id,
        event: event.name,
        fqdn: fqdn.into(),
        path: path.into(),
        utm_campaign: utm.campaign,
        utm_content: utm.content,
        utm_medium: utm.medium,
        utm_source: utm.source,
        utm_term: utm.term,
        screen_width: event.screen_width,
        orientation: event.orientation,
        track_sessions: settings.track_sessions,
    };

    if settings.ingest_drop_rules.iter().any(|rule| rule.matches(&event)) {
        return Ok(None);
    }

    Ok(Some(event))
}

fn resolve_visitor_group_id(
    settings: &ResolvedCollectionSettings,
    ip: Option<IpAddr>,
    user_agent: &str,
    daily_salt: &str,
    entity_id: &str,
) -> String {
    match (settings.visitor_group_mode, ip) {
        (VisitorGroupMode::RandomPerRequest, _) | (_, None) => visitor_group_id_fallback(),
        (VisitorGroupMode::Accurate, Some(ip)) => visitor_group_id(&ip, user_agent, daily_salt, entity_id),
        (mode, Some(ip)) => {
            let Some((ipv4_prefix, ipv6_prefix)) = mode.cidr_prefixes() else {
                return visitor_group_id_fallback();
            };
            visitor_group_id_cidr(&ip, ipv4_prefix, ipv6_prefix, daily_salt, entity_id)
        }
    }
}
