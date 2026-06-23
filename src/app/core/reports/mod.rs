mod dimension;
mod graph;
mod shared;
mod stats;

pub use dimension::dimension_report;
pub use graph::{build_graph_buckets, overall_report};
pub use shared::validate_entity_filters;
pub use stats::{earliest_timestamp, online_users, overall_stats};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};

pub use crate::app::models::FilterType;

/// Default event scope for dashboard reports.
pub const DEFAULT_EVENT: &str = "pageview";

/// Split the event scope out of a filter list.
///
/// Returns the scoped event name (defaulting to [`DEFAULT_EVENT`]) and the remaining
/// filters with the event-scope filter removed. An inverted event filter is a genuine
/// exclusion and is left in place.
pub fn split_event_scope(filters: &[DimensionFilter]) -> (String, Vec<DimensionFilter>) {
    let mut event = DEFAULT_EVENT.to_string();
    let mut rest = Vec::with_capacity(filters.len());
    for filter in filters {
        match (&filter.value, filter.dimension, filter.filter_type, filter.inversed) {
            (Some(value), Dimension::Event, FilterType::Equal, inversed) if inversed != Some(true) => {
                event = value.clone();
            }
            _ => rest.push(filter.clone()),
        }
    }
    (event, rest)
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DateRange {
    /// Start of the report range
    pub start: DateTime<Utc>,
    /// End of the report range
    pub end: DateTime<Utc>,
}

impl DateRange {
    /// Return the immediately preceding range with the same duration
    pub fn prev(&self) -> Self {
        let duration = self.end - self.start;
        Self { start: self.start - duration, end: self.start }
    }

    /// Return whether the range ends after the current time
    pub fn ends_in_future(&self) -> bool {
        self.end > Utc::now()
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
    /// Tracked entity
    EntityId,
    /// Custom event name
    Event,
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
            Self::EntityId => "entity_id",
            Self::Event => "event",
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
            Self::Event,
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
    pub(super) filter_type: FilterType,
    pub(super) inversed: Option<bool>,
    pub(super) strict: Option<bool>,
    pub(super) value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_filter(value: &str) -> DimensionFilter {
        DimensionFilter {
            dimension: Dimension::Event,
            filter_type: FilterType::Equal,
            inversed: None,
            strict: None,
            value: Some(value.to_string()),
        }
    }

    #[test]
    fn split_event_scope_defaults_to_pageview() {
        let (event, rest) = split_event_scope(&[]);
        assert_eq!(event, "pageview");
        assert!(rest.is_empty());
    }

    #[test]
    fn split_event_scope_extracts_event_filter() {
        let other = DimensionFilter {
            dimension: Dimension::Country,
            filter_type: FilterType::Equal,
            inversed: None,
            strict: None,
            value: Some("DE".to_string()),
        };
        let (event, rest) = split_event_scope(&[event_filter("signup"), other.clone()]);
        assert_eq!(event, "signup");
        assert_eq!(rest, vec![other]);
    }

    #[test]
    fn split_event_scope_keeps_inverted_event_filter() {
        let mut inverted = event_filter("signup");
        inverted.inversed = Some(true);
        let (event, rest) = split_event_scope(&[inverted.clone()]);
        assert_eq!(event, "pageview");
        assert_eq!(rest, vec![inverted]);
    }
}
