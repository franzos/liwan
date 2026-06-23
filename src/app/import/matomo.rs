use std::num::NonZeroU32;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, NaiveDate, TimeDelta, Utc};
use matomo::{ActionDetail, ApiErrorKind, Auth, DateRange, Limit, MatomoClient, Params, Period, Visit};
use reqwest::StatusCode;
use url::Url;

use crate::app::import::ImportStats;
use crate::app::models::{Event, GeoDetail, ResolvedCollectionSettings};
use crate::utils::hash::visitor_group_id_import;
use crate::utils::ingest::{Utm, clean_referrer, extract_utm, is_local_host, normalize_url};
use crate::utils::referrer::{Referrer, process_referer};

/// Build a Matomo API client for the given instance and auth token
pub fn client(base_url: &str, token: &str) -> Result<MatomoClient> {
    MatomoClient::builder()
        .base_url(base_url)
        .auth(Auth::token(token))
        .build()
        .context("failed to create Matomo client")
}

/// Retry schedule for transient Matomo failures (rate limits, gateway errors, timeouts)
#[derive(Clone, Copy)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub cap: Duration,
}

fn is_retryable(err: &matomo::Error) -> bool {
    match err {
        matomo::Error::Http(e) => {
            e.is_timeout()
                || matches!(
                    e.status(),
                    Some(
                        StatusCode::TOO_MANY_REQUESTS
                            | StatusCode::BAD_GATEWAY
                            | StatusCode::SERVICE_UNAVAILABLE
                            | StatusCode::GATEWAY_TIMEOUT
                    )
                )
        }
        matomo::Error::Api { kind: ApiErrorKind::RateLimited, .. } => true,
        _ => false,
    }
}

fn backoff_delay(attempt: u32, base: Duration, cap: Duration) -> Duration {
    let factor = 2u32.checked_pow(attempt);
    let delay = factor.and_then(|f| base.checked_mul(f)).unwrap_or(cap);
    delay.min(cap)
}

/// Fetch one page of `Live.getLastVisitsDetails` for the chunk `(lo, hi]`; an empty page means done
pub async fn fetch_page(
    client: &MatomoClient,
    id_site: u64,
    (lo, hi): (DateTime<Utc>, DateTime<Utc>),
    page_size: NonZeroU32,
    offset: u32,
    policy: RetryPolicy,
) -> Result<Vec<Visit>> {
    let id_site = u32::try_from(id_site).with_context(|| format!("site id {id_site} out of range"))?;
    // the ±1 day absorbs site-local-vs-UTC skew; minTimestamp and the mapping's window filter do the exact cut
    let from = ymd((lo - TimeDelta::days(1)).date_naive());
    let to = ymd((hi + TimeDelta::days(1)).date_naive());

    let params = Params::new()
        .id_site(id_site)
        .period(Period::Range(DateRange::ymd(from, to)))
        .limit(Limit::Count(page_size))
        .offset(offset)
        .set("minTimestamp", lo.timestamp().to_string());

    let mut attempt = 0u32;
    loop {
        match client.call_typed::<Vec<Visit>>("Live.getLastVisitsDetails", &params).await {
            Ok(visits) => return Ok(visits),
            Err(err) if is_retryable(&err) && attempt < policy.max_retries => {
                let delay = backoff_delay(attempt, policy.base_delay, policy.cap);
                tracing::warn!(
                    "site {id_site} offset {offset}: transient error on attempt {}, retrying in {:.1}s: {err}",
                    attempt + 1,
                    delay.as_secs_f64()
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("Live.getLastVisitsDetails failed for site {id_site} at offset {offset}")
                });
            }
        }
    }
}

fn ymd(date: NaiveDate) -> (u16, u8, u8) {
    (date.year() as u16, date.month() as u8, date.day() as u8)
}

/// Map one visit to pageview events within `(lo, hi]`, mirroring the live ingest pipeline
pub fn map_visit(
    visit: &Visit,
    entity_id: &str,
    settings: &ResolvedCollectionSettings,
    (lo, hi): (DateTime<Utc>, DateTime<Utc>),
    drop_local_urls: bool,
    stats: &mut ImportStats,
) -> Vec<Event> {
    stats.visits_fetched += 1;

    let Some(visitor_id) = visit.visitor_id.as_deref().filter(|id| !id.is_empty()) else {
        for detail in &visit.action_details {
            if matches!(detail, ActionDetail::Action(_)) {
                stats.actions_seen += 1;
                stats.skipped_no_visitor_id += 1;
            }
        }
        return Vec::new();
    };
    let visitor_group_id = visitor_group_id_import(visitor_id, entity_id);

    let referrer = match process_referer(visit.referrer_url.as_deref()) {
        Referrer::Fqdn(fqdn) => Some(fqdn),
        Referrer::Unknown(referrer) => referrer,
        Referrer::Spammer | Referrer::Local => {
            for detail in &visit.action_details {
                if matches!(detail, ActionDetail::Action(_)) {
                    stats.actions_seen += 1;
                    stats.referrer_spam += 1;
                }
            }
            return Vec::new();
        }
    };
    let referrer = clean_referrer(referrer);

    let country = non_empty(visit.country_code.as_deref()).map(|code| code.to_ascii_uppercase());
    let (country, city) = match settings.track_geo {
        GeoDetail::None => (None, None),
        GeoDetail::Country => (country, None),
        GeoDetail::City => (country, non_empty(visit.city.as_deref())),
    };

    let mobile = map_mobile(visit.device_type.as_deref());
    let platform = map_platform(visit.operating_system_name.as_deref());
    let browser = non_empty(visit.browser_name.as_deref());

    let mut events = Vec::new();
    for detail in &visit.action_details {
        let ActionDetail::Action(action) = detail else { continue };
        stats.actions_seen += 1;

        let (Some(url), Some(timestamp)) = (action.url.as_deref(), action.timestamp) else {
            stats.skipped_malformed += 1;
            continue;
        };
        let Some(created_at) = DateTime::from_timestamp(timestamp, 0) else {
            stats.skipped_malformed += 1;
            continue;
        };
        if created_at <= lo || created_at > hi {
            stats.out_of_window += 1;
            continue;
        }
        let Ok(mut url) = Url::parse(url) else {
            stats.skipped_malformed += 1;
            continue;
        };

        let utm = if settings.track_utm_params { extract_utm(&mut url) } else { Utm::default() };
        let (path, fqdn) = normalize_url(url);

        if drop_local_urls && is_local_host(&fqdn) {
            stats.skipped_local_url += 1;
            continue;
        }

        let event = Event {
            entity_id: entity_id.to_string(),
            visitor_group_id: visitor_group_id.clone(),
            event: "pageview".to_string(),
            created_at,
            fqdn: fqdn.into(),
            path: path.into(),
            referrer: referrer.clone(),
            platform: platform.clone(),
            browser: browser.clone(),
            mobile,
            country: country.clone(),
            city: city.clone(),
            utm_source: utm.source,
            utm_medium: utm.medium,
            utm_campaign: utm.campaign,
            utm_content: utm.content,
            utm_term: utm.term,
            screen_width: None,
            orientation: None,
            track_sessions: settings.track_sessions,
        };

        if settings.ingest_drop_rules.iter().any(|rule| rule.matches(&event)) {
            stats.dropped_by_rule += 1;
            continue;
        }

        stats.events_imported += 1;
        events.push(event);
    }
    events
}

fn map_mobile(device_type: Option<&str>) -> Option<bool> {
    match device_type? {
        "Smartphone" | "Tablet" | "Phablet" | "Feature phone" => Some(true),
        "Desktop" | "Console" | "TV" | "Car Browser" => Some(false),
        _ => None,
    }
}

fn map_platform(name: Option<&str>) -> Option<String> {
    let name = name?.trim();
    if name.is_empty() {
        return None;
    }
    let base = match name.rsplit_once(' ') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit() || c == '.') => head,
        _ => name,
    };
    let base = match base {
        "Mac" | "Mac OS X" => "macOS",
        "GNU/Linux" => "Linux",
        other => other,
    };
    Some(base.to_string())
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|v| !v.is_empty()).map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::models::{DataRetention, FilterType, IngestDropRule, IngestFilter, VisitorGroupMode};

    const FIXTURE: &str = include_str!("fixtures/live_visits.json");

    const LO: i64 = 1_714_521_600; // 2024-05-01T00:00:00Z
    const HI: i64 = 1_717_200_000; // 2024-06-01T00:00:00Z

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        (DateTime::from_timestamp(LO, 0).unwrap(), DateTime::from_timestamp(HI, 0).unwrap())
    }

    fn settings() -> ResolvedCollectionSettings {
        ResolvedCollectionSettings {
            visitor_group_mode: VisitorGroupMode::Accurate,
            track_sessions: true,
            track_utm_params: true,
            track_geo: GeoDetail::City,
            data_retention: DataRetention::All,
            ingest_drop_rules: Vec::new(),
            allowed_hostnames: Vec::new(),
        }
    }

    fn visits() -> Vec<Visit> {
        serde_json::from_str(FIXTURE).expect("fixture deserializes into Vec<Visit>")
    }

    fn map_first(settings: &ResolvedCollectionSettings) -> (Vec<Event>, ImportStats) {
        let mut stats = ImportStats::default();
        let events = map_visit(&visits()[0], "blog", settings, window(), false, &mut stats);
        (events, stats)
    }

    #[test]
    fn backoff_is_exponential_and_clamped() {
        let base = Duration::from_secs(2);
        let cap = Duration::from_secs(60);
        let schedule: Vec<u64> = (0..=6).map(|a| backoff_delay(a, base, cap).as_secs()).collect();
        assert_eq!(schedule, vec![2, 4, 8, 16, 32, 60, 60]);
        // an attempt large enough to overflow the multiplication saturates to cap
        assert_eq!(backoff_delay(64, base, cap), cap);
    }

    #[test]
    fn is_retryable_classifies_constructible_variants() {
        // Http-status branch verified against the live instance; reqwest::Error isn't constructible in tests
        let rate_limited = matomo::Error::Api {
            message: "rate limit exceeded".to_string(),
            method: "Live.getLastVisitsDetails",
            kind: ApiErrorKind::RateLimited,
        };
        assert!(is_retryable(&rate_limited));

        let auth = matomo::Error::Api {
            message: "token_auth invalid".to_string(),
            method: "Live.getLastVisitsDetails",
            kind: ApiErrorKind::Auth,
        };
        assert!(!is_retryable(&auth));

        let non_json = matomo::Error::NonJsonBody { method: "Live.getLastVisitsDetails", body: "<html>".to_string() };
        assert!(!is_retryable(&non_json));

        assert!(!is_retryable(&matomo::Error::Config("bad url".to_string())));
    }

    #[test]
    fn uses_per_action_timestamps_not_server_timestamp() {
        let (events, _) = map_first(&settings());
        assert_eq!(events[0].created_at.timestamp(), 1_715_000_000);
        assert!(events.iter().all(|event| event.created_at.timestamp() != 1_714_999_999));
    }

    #[test]
    fn normalizes_url_and_extracts_utm() {
        let (events, _) = map_first(&settings());
        let event = &events[0];
        assert_eq!(event.path.as_deref(), Some("/blog/post"));
        assert_eq!(event.fqdn.as_deref(), Some("www.mysite.com"));
        assert_eq!(event.utm_source.as_deref(), Some("newsletter"));
        assert_eq!(event.utm_medium.as_deref(), Some("email"));
        assert_eq!(event.utm_campaign, None);
        assert_eq!(event.event, "pageview");
        assert!(event.track_sessions);
    }

    #[test]
    fn cleans_referrer() {
        let (events, _) = map_first(&settings());
        assert!(events.iter().all(|event| event.referrer.as_deref() == Some("search-engine-example.com")));
    }

    #[test]
    fn visitor_ids_are_prefixed_and_deterministic() {
        let (events, _) = map_first(&settings());
        let id = &events[0].visitor_group_id;
        assert!(id.starts_with("i_"));
        assert_eq!(id.len(), 16);
        assert_eq!(id, &visitor_group_id_import("1234567890abcdef", "blog"));
        assert_ne!(id, &visitor_group_id_import("1234567890abcdef", "docs"));
    }

    #[test]
    fn window_filter_is_half_open() {
        let (events, stats) = map_first(&settings());
        let timestamps: Vec<i64> = events.iter().map(|event| event.created_at.timestamp()).collect();
        assert_eq!(timestamps, vec![1_715_000_000, HI]);
        assert_eq!(stats.visits_fetched, 1);
        assert_eq!(stats.actions_seen, 5);
        assert_eq!(stats.events_imported, 2);
        assert_eq!(stats.out_of_window, 2);
        assert_eq!(stats.dropped_by_rule, 0);
    }

    #[test]
    fn utm_gating_keeps_url_cleanup() {
        let (events, _) = map_first(&ResolvedCollectionSettings { track_utm_params: false, ..settings() });
        assert_eq!(events[0].utm_source, None);
        assert_eq!(events[0].utm_medium, None);
        assert_eq!(events[0].path.as_deref(), Some("/blog/post"));
    }

    #[test]
    fn geo_gating_follows_resolved_detail() {
        let (events, _) = map_first(&settings());
        assert_eq!(events[0].country.as_deref(), Some("DE"));
        assert_eq!(events[0].city.as_deref(), Some("Berlin"));

        let (events, _) = map_first(&ResolvedCollectionSettings { track_geo: GeoDetail::Country, ..settings() });
        assert_eq!(events[0].country.as_deref(), Some("DE"));
        assert_eq!(events[0].city, None);

        let (events, _) = map_first(&ResolvedCollectionSettings { track_geo: GeoDetail::None, ..settings() });
        assert_eq!(events[0].country, None);
        assert_eq!(events[0].city, None);
    }

    #[test]
    fn drop_rules_apply_and_count() {
        let rule = IngestDropRule {
            filters: vec![IngestFilter {
                dimension: "path".to_string(),
                filter_type: FilterType::Equal,
                value: Some("/blog/post".to_string()),
            }],
        };
        let (events, stats) = map_first(&ResolvedCollectionSettings { ingest_drop_rules: vec![rule], ..settings() });
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path.as_deref(), Some("/at-hi"));
        assert_eq!(stats.dropped_by_rule, 1);
        assert_eq!(stats.events_imported, 1);
    }

    #[test]
    fn device_vocab() {
        let (events, _) = map_first(&settings());
        assert_eq!(events[0].mobile, Some(true));
        assert_eq!(events[0].platform.as_deref(), Some("macOS"));
        assert_eq!(events[0].browser.as_deref(), Some("Safari"));

        assert_eq!(map_mobile(Some("Desktop")), Some(false));
        assert_eq!(map_mobile(Some("Feature phone")), Some(true));
        assert_eq!(map_mobile(Some("Wearable")), None);
        assert_eq!(map_mobile(None), None);

        assert_eq!(map_platform(Some("Windows 10")).as_deref(), Some("Windows"));
        assert_eq!(map_platform(Some("Mac OS X")).as_deref(), Some("macOS"));
        assert_eq!(map_platform(Some("GNU/Linux")).as_deref(), Some("Linux"));
        assert_eq!(map_platform(Some("")), None);
        assert_eq!(map_platform(None), None);
    }

    #[test]
    fn skips_visits_with_spammer_or_local_referrer() {
        let visits = visits();
        let mut stats = ImportStats::default();
        let spam_events = map_visit(&visits[2], "blog", &settings(), window(), false, &mut stats);
        let local_events = map_visit(&visits[3], "blog", &settings(), window(), false, &mut stats);

        assert_eq!(process_referer(visits[2].referrer_url.as_deref()), Referrer::Spammer);
        assert_eq!(process_referer(visits[3].referrer_url.as_deref()), Referrer::Local);
        assert!(spam_events.is_empty());
        assert!(local_events.is_empty());
        assert_eq!(stats.visits_fetched, 2);
        assert_eq!(stats.actions_seen, 2);
        assert_eq!(stats.referrer_spam, 2);
        assert_eq!(stats.events_imported, 0);
    }

    #[test]
    fn drop_local_urls_filters_loopback_host_when_enabled() {
        let mut kept = ImportStats::default();
        let events = map_visit(&visits()[4], "blog", &settings(), window(), false, &mut kept);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fqdn.as_deref(), Some("127.0.0.1"));
        assert_eq!(kept.skipped_local_url, 0);

        let mut dropped = ImportStats::default();
        let events = map_visit(&visits()[4], "blog", &settings(), window(), true, &mut dropped);
        assert!(events.is_empty());
        assert_eq!(dropped.actions_seen, 1);
        assert_eq!(dropped.skipped_local_url, 1);
        assert_eq!(dropped.events_imported, 0);
    }

    #[test]
    fn malformed_actions_are_counted_not_silently_dropped() {
        let mut stats = ImportStats::default();
        let events = map_visit(&visits()[5], "blog", &settings(), window(), false, &mut stats);
        assert!(events.is_empty());
        assert_eq!(stats.actions_seen, 2);
        assert_eq!(stats.skipped_malformed, 2); // unparseable url + out-of-range timestamp
        assert_eq!(stats.events_imported, 0);
        assert_eq!(stats.out_of_window, 0);
    }

    #[test]
    fn skips_visit_without_visitor_id() {
        let mut stats = ImportStats::default();
        let events = map_visit(&visits()[1], "blog", &settings(), window(), false, &mut stats);
        assert!(events.is_empty());
        assert_eq!(stats.visits_fetched, 1);
        assert_eq!(stats.actions_seen, 1);
        assert_eq!(stats.skipped_no_visitor_id, 1);
        assert_eq!(stats.events_imported, 0);
        assert_eq!(
            stats.actions_seen,
            stats.events_imported
                + stats.dropped_by_rule
                + stats.out_of_window
                + stats.referrer_spam
                + stats.skipped_no_visitor_id
                + stats.skipped_malformed
                + stats.skipped_local_url
        );
    }
}
