mod custom_events;
mod dimension;
mod graph;
mod shared;
mod stats;

pub use custom_events::{CustomEventsReport, custom_events_report};
pub use dimension::dimension_report;
pub use graph::{build_graph_buckets, overall_report};
pub use shared::validate_entity_filters;
pub use stats::{earliest_timestamp, online_users, overall_stats};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};

pub use crate::app::models::FilterType;
use crate::config::LimitsConfig;

/// Validate resource limits shared by dashboard report requests.
pub fn validate_request(range: &DateRange, filters: &[DimensionFilter], limits: &LimitsConfig) -> Result<()> {
    range.validate().map_err(anyhow::Error::msg)?;
    if range.start >= range.end {
        bail!("Report range must end after it starts");
    }
    if range.duration() > Duration::days(limits.report_max_range_days) {
        bail!("Report range cannot exceed {} days", limits.report_max_range_days);
    }
    if filters.len() > limits.report_max_filters {
        bail!("Reports cannot contain more than {} filters", limits.report_max_filters);
    }
    if filters
        .iter()
        .filter_map(|filter| filter.value.as_ref())
        .any(|value| value.len() > limits.report_max_filter_value_bytes)
    {
        bail!("Report filter values cannot exceed {} bytes", limits.report_max_filter_value_bytes);
    }
    for filter in filters {
        match (filter.dimension, filter.key.as_deref()) {
            (Dimension::Property, Some(key)) => validate_property_key(key)?,
            (Dimension::Property, None) => bail!("Property filters require a key"),
            (_, Some(_)) => bail!("Only property filters can have a key"),
            (_, None) => {}
        }
    }

    Ok(())
}

const MAX_PROPERTY_KEY_CHARS: usize = 64;

/// Validate a custom property key.
pub fn validate_property_key(key: &str) -> Result<()> {
    if key.is_empty() || key.chars().count() > MAX_PROPERTY_KEY_CHARS {
        bail!("Property keys must be between 1 and {MAX_PROPERTY_KEY_CHARS} characters");
    }

    Ok(())
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DateRange {
    /// Start of the report range
    pub start: DateTime<Utc>,
    /// End of the report range
    pub end: DateTime<Utc>,
}

/// Widest span a dashboard query may cover. A ceiling on the arithmetic, not a
/// product limit; no instance holds twenty years of history.
const MAX_RANGE: chrono::Duration = chrono::Duration::days(20 * 366);

/// How far past now a range may end, to leave room for client clock skew and
/// timezone-shifted "today".
const MAX_RANGE_END_AHEAD: chrono::Duration = chrono::Duration::days(366);

impl DateRange {
    /// Reject a range no dashboard would ask for. chrono deserializes extended
    /// years (-262143 to +262142), which overflow the date arithmetic below and
    /// let an unauthenticated request take the process down.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.start >= self.end {
            return Err("range start must be before its end");
        }
        if self.start.timestamp() < 0 {
            return Err("range start must be at or after 1970-01-01T00:00:00Z");
        }
        if self.end > Utc::now() + MAX_RANGE_END_AHEAD {
            return Err("range end must be within a year of now");
        }
        if self.duration() > MAX_RANGE {
            return Err("range must span at most 20 years");
        }
        Ok(())
    }

    /// Return the immediately preceding range with the same duration
    pub fn prev(&self) -> Result<Self> {
        let duration = self.end - self.start;
        let start = self.start.checked_sub_signed(duration).context("Previous report range is out of bounds")?;
        Ok(Self { start, end: self.start })
    }

    /// Return the range duration
    pub fn duration(&self) -> chrono::Duration {
        self.end - self.start
    }
}

impl Display for DateRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {}", self.start, self.end)
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    /// Total pageviews
    Views,
    /// Distinct visitor groups
    UniqueVisitors,
    /// Percentage of sessions with one pageview
    BounceRate,
    /// Average time between pageviews in a session
    AvgTimeOnSite,
}

impl Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Views => "views",
            Self::UniqueVisitors => "unique_visitors",
            Self::BounceRate => "bounce_rate",
            Self::AvgTimeOnSite => "avg_time_on_site",
        })
    }
}

impl Metric {
    /// Return all report metrics in dashboard order
    pub const fn all() -> &'static [Self] {
        &[Self::Views, Self::UniqueVisitors, Self::BounceRate, Self::AvgTimeOnSite]
    }
}

/// Time bucket size for graph reports
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphInterval {
    /// Hourly buckets
    Hour,
    /// Daily buckets
    Day,
    /// Weekly buckets, starting Monday
    Week,
    /// Monthly buckets
    Month,
}

/// Dimension selected for table reports and filters
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    /// Full tracked URL
    Url,
    /// First URL in a session
    UrlEntry,
    /// Last URL in a session
    UrlExit,
    /// Tracked hostname
    Fqdn,
    /// Tracked path
    Path,
    /// Referrer domain
    Referrer,
    /// Operating system family
    Platform,
    /// Browser family
    Browser,
    /// Device type
    Mobile,
    /// GeoIP country
    Country,
    /// GeoIP city
    City,
    /// UTM source
    UtmSource,
    /// UTM medium
    UtmMedium,
    /// UTM campaign
    UtmCampaign,
    /// UTM content
    UtmContent,
    /// UTM term
    UtmTerm,
    /// Screen width bucket
    ScreenWidth,
    /// Screen orientation
    Orientation,
    /// Custom property keys, or the values of one key when a property key is given
    Property,
    /// Tracked entity
    EntityId,
}

impl Display for Dimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Url => "url",
            Self::UrlEntry => "url_entry",
            Self::UrlExit => "url_exit",
            Self::Fqdn => "fqdn",
            Self::Path => "path",
            Self::Referrer => "referrer",
            Self::Platform => "platform",
            Self::Browser => "browser",
            Self::Mobile => "mobile",
            Self::Country => "country",
            Self::City => "city",
            Self::UtmSource => "utm_source",
            Self::UtmMedium => "utm_medium",
            Self::UtmCampaign => "utm_campaign",
            Self::UtmContent => "utm_content",
            Self::UtmTerm => "utm_term",
            Self::ScreenWidth => "screen_width",
            Self::Orientation => "orientation",
            Self::Property => "property",
            Self::EntityId => "entity_id",
        })
    }
}

impl Dimension {
    /// Return all report dimensions in dashboard order
    pub const fn all() -> &'static [Self] {
        &[
            Self::Platform,
            Self::Browser,
            Self::Url,
            Self::UrlEntry,
            Self::UrlExit,
            Self::Path,
            Self::Mobile,
            Self::Referrer,
            Self::City,
            Self::Country,
            Self::Fqdn,
            Self::UtmCampaign,
            Self::UtmContent,
            Self::UtmMedium,
            Self::UtmSource,
            Self::UtmTerm,
            Self::ScreenWidth,
            Self::Orientation,
            Self::Property,
        ]
    }
}

/// One point in a graph report
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReportGraphPoint {
    /// Start timestamp of the graph bucket
    pub bin_start: DateTime<Utc>,
    /// Metric value for the graph bucket
    pub value: f64,
}

/// Graph report points ordered by bucket start
pub type ReportGraph = Vec<ReportGraphPoint>;

/// Dimension table values mapped to their metric value
pub type ReportTable = BTreeMap<String, f64>;

/// Overall metric summary for a report range
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReportStats {
    /// Total pageviews
    pub total_views: u64,
    /// Distinct visitor groups
    pub unique_visitors: u64,
    /// Bounce rate, when session metrics are available
    pub bounce_rate: Option<f64>,
    /// Average time on site, when session metrics are available
    pub avg_time_on_site: Option<f64>,
}

/// Filter applied to a dashboard report query
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct DimensionFilter {
    pub(super) dimension: Dimension,
    /// Property key, required for property filters
    pub(super) key: Option<String>,
    pub(super) filter_type: FilterType,
    pub(super) inversed: Option<bool>,
    pub(super) strict: Option<bool>,
    pub(super) value: Option<String>,
}

impl DimensionFilter {
    /// Whether this filter depends on pageview session boundaries.
    pub fn is_session_page_filter(&self) -> bool {
        matches!(self.dimension, Dimension::UrlEntry | Dimension::UrlExit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: &str, end: &str) -> DateRange {
        DateRange { start: start.parse().expect("invalid start"), end: end.parse().expect("invalid end") }
    }

    #[test]
    fn validate_rejects_inverted_range() {
        assert!(range("2024-02-01T00:00:00Z", "2024-01-01T00:00:00Z").validate().is_err());
        assert!(range("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z").validate().is_err());
    }

    #[test]
    fn validate_rejects_extended_year_start() {
        let start: DateTime<Utc> = "-262143-01-01T00:00:00Z".parse().expect("extended years parse");
        assert!(DateRange { start, end: "2024-01-01T00:00:00Z".parse().unwrap() }.validate().is_err());
    }

    #[test]
    fn validate_rejects_far_future_end() {
        let end = Utc::now() + chrono::Duration::days(400);
        assert!(DateRange { start: Utc::now(), end }.validate().is_err());
    }

    #[test]
    fn validate_rejects_span_over_20_years() {
        assert!(range("1990-01-01T00:00:00Z", "2024-01-01T00:00:00Z").validate().is_err());
    }

    #[test]
    fn validate_accepts_a_normal_range() {
        let end = Utc::now();
        let start = end - chrono::Duration::days(30);
        DateRange { start, end }.validate().expect("a 30-day range up to now is valid");
    }

    #[test]
    fn prev_returns_the_preceding_equal_length_range() {
        let prev = range("2024-01-08T00:00:00Z", "2024-01-15T00:00:00Z").prev().expect("prev is representable");
        assert_eq!(prev, range("2024-01-01T00:00:00Z", "2024-01-08T00:00:00Z"));
    }

    fn range_days(days: i64) -> DateRange {
        let start = DateTime::from_timestamp(0, 0).unwrap();
        DateRange { start, end: start + Duration::days(days) }
    }

    fn filter(value: Option<String>) -> DimensionFilter {
        DimensionFilter {
            dimension: Dimension::Path,
            key: None,
            filter_type: FilterType::Equal,
            inversed: None,
            strict: None,
            value,
        }
    }

    #[test]
    fn request_limits_accept_large_normal_reports() {
        let limits = LimitsConfig::default();
        assert!(
            validate_request(
                &range_days(limits.report_max_range_days),
                &vec![filter(Some("x".into())); limits.report_max_filters],
                &limits,
            )
            .is_ok()
        );
    }

    #[test]
    fn request_limits_reject_excessive_inputs() {
        let limits = LimitsConfig::default();
        assert!(validate_request(&range_days(limits.report_max_range_days + 1), &[], &limits).is_err());
        assert!(validate_request(&range_days(1), &vec![filter(None); limits.report_max_filters + 1], &limits).is_err());
        assert!(
            validate_request(
                &range_days(1),
                &[filter(Some("x".repeat(limits.report_max_filter_value_bytes + 1)))],
                &limits,
            )
            .is_err()
        );
    }
}
