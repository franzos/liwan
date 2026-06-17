use std::{fmt::Display, num::NonZeroU32, str::FromStr};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Event {
    pub entity_id: String,
    pub visitor_group_id: String,
    pub event: String,
    pub created_at: DateTime<Utc>,
    pub fqdn: Option<String>,
    pub path: Option<String>,
    pub referrer: Option<String>,
    pub platform: Option<String>,
    pub browser: Option<String>,
    pub mobile: Option<bool>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub utm_source: Option<String>,
    pub utm_medium: Option<String>,
    pub utm_campaign: Option<String>,
    pub utm_content: Option<String>,
    pub utm_term: Option<String>,
    pub screen_width: Option<String>,
    pub orientation: Option<String>,
    pub track_sessions: bool,
}

#[derive(Debug, Clone)]
pub struct Project {
    pub id: String,
    pub display_name: String,
    pub public: bool,
    pub secret: Option<String>, // currently unused
}

#[derive(Debug, Clone)]
pub struct Entity {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum VisitorGroupMode {
    #[default]
    Accurate,
    RandomPerRequest,
    NetworkStandard,
    NetworkBalanced,
    NetworkAccurate,
}

impl VisitorGroupMode {
    pub fn cidr_prefixes(self) -> Option<(u8, u8)> {
        match self {
            Self::NetworkStandard => Some((24, 56)),
            Self::NetworkBalanced => Some((28, 64)),
            Self::NetworkAccurate => Some((32, 128)),
            Self::Accurate | Self::RandomPerRequest => None,
        }
    }
}

impl Display for VisitorGroupMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Accurate => "accurate",
            Self::RandomPerRequest => "random_per_request",
            Self::NetworkStandard => "network_standard",
            Self::NetworkBalanced => "network_balanced",
            Self::NetworkAccurate => "network_accurate",
        })
    }
}

impl FromStr for VisitorGroupMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "accurate" => Ok(Self::Accurate),
            "random_per_request" => Ok(Self::RandomPerRequest),
            "network_standard" => Ok(Self::NetworkStandard),
            "network_balanced" => Ok(Self::NetworkBalanced),
            "network_accurate" => Ok(Self::NetworkAccurate),
            _ => Err(format!("invalid visitor group mode: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GeoDetail {
    None,
    Country,
    #[default]
    City,
}

impl Display for GeoDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Country => "country",
            Self::City => "city",
        })
    }
}

impl FromStr for GeoDetail {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::None),
            "country" => Ok(Self::Country),
            "city" => Ok(Self::City),
            _ => Err(format!("invalid geo detail: {value}")),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    IsNull,
    Equal,
    Contains,
    StartsWith,
    EndsWith,
    IsTrue,
    IsFalse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "mode", content = "days")]
pub enum DataRetention {
    Inherit,
    All,
    Days(NonZeroU32),
}

impl Display for FilterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IsNull => "is_null",
            Self::Equal => "equal",
            Self::Contains => "contains",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::IsTrue => "is_true",
            Self::IsFalse => "is_false",
        })
    }
}

impl FromStr for FilterType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "is_null" => Ok(Self::IsNull),
            "equal" => Ok(Self::Equal),
            "contains" => Ok(Self::Contains),
            "starts_with" => Ok(Self::StartsWith),
            "ends_with" => Ok(Self::EndsWith),
            "is_true" => Ok(Self::IsTrue),
            "is_false" => Ok(Self::IsFalse),
            _ => Err(format!("invalid filter type: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSettings {
    pub visitor_group_mode: VisitorGroupMode,
    pub track_sessions: bool,
    pub track_utm_params: bool,
    pub track_geo: GeoDetail,
    pub data_retention: DataRetention,
    pub ingest_drop_rules: Vec<IngestDropRule>,
}

impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            visitor_group_mode: VisitorGroupMode::Accurate,
            track_sessions: true,
            track_utm_params: true,
            track_geo: GeoDetail::City,
            data_retention: DataRetention::All,
            ingest_drop_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EntityCollectionSettings {
    pub entity_id: String,
    pub visitor_group_mode: Option<VisitorGroupMode>,
    pub track_sessions: Option<bool>,
    pub track_utm_params: Option<bool>,
    pub track_geo: Option<GeoDetail>,
    pub data_retention: DataRetention,
    pub ingest_drop_rules: Vec<IngestDropRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedCollectionSettings {
    pub visitor_group_mode: VisitorGroupMode,
    pub track_sessions: bool,
    pub track_utm_params: bool,
    pub track_geo: GeoDetail,
    pub data_retention: DataRetention,
    pub ingest_drop_rules: Vec<IngestDropRule>,
}

impl From<CollectionSettings> for ResolvedCollectionSettings {
    fn from(settings: CollectionSettings) -> Self {
        Self {
            visitor_group_mode: settings.visitor_group_mode,
            track_sessions: settings.track_sessions,
            track_utm_params: settings.track_utm_params,
            track_geo: settings.track_geo,
            data_retention: settings.data_retention,
            ingest_drop_rules: settings.ingest_drop_rules,
        }
    }
}

impl ResolvedCollectionSettings {
    pub fn resolve(global: CollectionSettings, entity: Option<EntityCollectionSettings>) -> Self {
        let Some(entity) = entity else {
            return global.into();
        };

        let mut ingest_drop_rules = global.ingest_drop_rules;
        ingest_drop_rules.extend(entity.ingest_drop_rules);

        Self {
            visitor_group_mode: entity.visitor_group_mode.unwrap_or(global.visitor_group_mode),
            track_sessions: entity.track_sessions.unwrap_or(global.track_sessions),
            track_utm_params: entity.track_utm_params.unwrap_or(global.track_utm_params),
            track_geo: entity.track_geo.unwrap_or(global.track_geo),
            data_retention: match entity.data_retention {
                DataRetention::Inherit => global.data_retention,
                retention => retention,
            },
            ingest_drop_rules,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IngestDropRule {
    pub filters: Vec<IngestFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IngestFilter {
    pub dimension: String,
    pub filter_type: FilterType,
    pub value: Option<String>,
}

impl IngestDropRule {
    pub fn matches(&self, event: &Event) -> bool {
        !self.filters.is_empty() && self.filters.iter().all(|filter| filter.matches(event))
    }
}

impl IngestFilter {
    fn matches(&self, event: &Event) -> bool {
        if self.dimension == "mobile" {
            return match self.filter_type {
                FilterType::IsNull => event.mobile.is_none(),
                FilterType::IsTrue => event.mobile == Some(true),
                FilterType::IsFalse => event.mobile == Some(false),
                _ => false,
            };
        }

        let url;
        let value = match self.dimension.as_str() {
            "event" => Some(event.event.as_str()),
            "url" => {
                url = format!(
                    "{}{}",
                    event.fqdn.as_deref().unwrap_or_default(),
                    event.path.as_deref().unwrap_or_default()
                );
                Some(url.as_str())
            }
            "fqdn" => event.fqdn.as_deref(),
            "path" => event.path.as_deref(),
            "referrer" => event.referrer.as_deref(),
            "country" => event.country.as_deref(),
            "city" => event.city.as_deref(),
            "platform" => event.platform.as_deref(),
            "browser" => event.browser.as_deref(),
            "utm_source" => event.utm_source.as_deref(),
            "utm_medium" => event.utm_medium.as_deref(),
            "utm_campaign" => event.utm_campaign.as_deref(),
            "utm_content" => event.utm_content.as_deref(),
            "utm_term" => event.utm_term.as_deref(),
            "screen_width" => event.screen_width.as_deref(),
            "orientation" => event.orientation.as_deref(),
            _ => return false,
        };

        match self.filter_type {
            FilterType::IsNull => value.is_none(),
            FilterType::Equal => {
                value.zip(self.value.as_deref()).is_some_and(|(value, filter)| value.eq_ignore_ascii_case(filter))
            }
            FilterType::Contains => value
                .zip(self.value.as_deref())
                .is_some_and(|(value, filter)| value.to_ascii_lowercase().contains(&filter.to_ascii_lowercase())),
            FilterType::StartsWith => value
                .zip(self.value.as_deref())
                .is_some_and(|(value, filter)| value.to_ascii_lowercase().starts_with(&filter.to_ascii_lowercase())),
            FilterType::EndsWith => value
                .zip(self.value.as_deref())
                .is_some_and(|(value, filter)| value.to_ascii_lowercase().ends_with(&filter.to_ascii_lowercase())),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DisplayOverride {
    #[default]
    Auto,
    Show,
    Hide,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDisplaySettings {
    pub project_id: String,
    pub metric_display_overrides: BTreeMap<String, DisplayOverride>,
    pub dimension_display_overrides: BTreeMap<String, DisplayOverride>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub username: String,
    pub role: UserRole,
    pub projects: Vec<String>,
    pub email: Option<String>,
    pub auth: AuthMethod,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_event() -> Event {
        Event {
            entity_id: "entity".to_string(),
            visitor_group_id: "visitor".to_string(),
            event: "pageview".to_string(),
            created_at: Utc::now(),
            fqdn: None,
            path: None,
            referrer: None,
            platform: None,
            browser: None,
            mobile: None,
            country: None,
            city: None,
            utm_source: None,
            utm_medium: None,
            utm_campaign: None,
            utm_content: None,
            utm_term: None,
            screen_width: None,
            orientation: None,
            track_sessions: true,
        }
    }

    #[test]
    fn unknown_ingest_filter_dimension_does_not_match_null() {
        let filter = IngestFilter { dimension: "unknown".to_string(), filter_type: FilterType::IsNull, value: None };
        assert!(!filter.matches(&empty_event()));
    }

    #[test]
    fn ingest_drop_rule_requires_all_filters_to_match() {
        let event = Event {
            fqdn: Some("example.com".to_string()),
            path: Some("/pricing".to_string()),
            utm_source: Some("newsletter".to_string()),
            ..empty_event()
        };

        let matching_rule = IngestDropRule {
            filters: vec![
                IngestFilter {
                    dimension: "path".to_string(),
                    filter_type: FilterType::Equal,
                    value: Some("/pricing".to_string()),
                },
                IngestFilter {
                    dimension: "utm_source".to_string(),
                    filter_type: FilterType::Equal,
                    value: Some("newsletter".to_string()),
                },
            ],
        };
        let non_matching_rule = IngestDropRule {
            filters: vec![
                IngestFilter {
                    dimension: "path".to_string(),
                    filter_type: FilterType::Equal,
                    value: Some("/pricing".to_string()),
                },
                IngestFilter {
                    dimension: "utm_source".to_string(),
                    filter_type: FilterType::Equal,
                    value: Some("ads".to_string()),
                },
            ],
        };

        assert!(matching_rule.matches(&event));
        assert!(!non_matching_rule.matches(&event));
    }

    #[test]
    fn empty_ingest_drop_rule_does_not_match() {
        assert!(!IngestDropRule { filters: Vec::new() }.matches(&empty_event()));
    }

    #[test]
    fn entity_retention_overrides_global_retention() {
        let resolved = ResolvedCollectionSettings::resolve(
            CollectionSettings { data_retention: DataRetention::All, ..Default::default() },
            Some(EntityCollectionSettings {
                entity_id: "entity".to_string(),
                visitor_group_mode: None,
                track_sessions: None,
                track_utm_params: None,
                track_geo: None,
                data_retention: DataRetention::Days(NonZeroU32::new(30).unwrap()),
                ingest_drop_rules: Vec::new(),
            }),
        );

        assert_eq!(resolved.data_retention, DataRetention::Days(NonZeroU32::new(30).unwrap()));
    }
}

#[derive(Debug, JsonSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    #[default]
    User,
}

impl Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::User => write!(f, "user"),
        }
    }
}

#[derive(Debug, JsonSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[default]
    Password,
    Oidc,
}

impl Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password => write!(f, "password"),
            AuthMethod::Oidc => write!(f, "oidc"),
        }
    }
}

impl TryFrom<String> for AuthMethod {
    type Error = ();
    fn try_from(s: String) -> Result<Self, ()> {
        match s.as_str() {
            "password" => Ok(AuthMethod::Password),
            "oidc" => Ok(AuthMethod::Oidc),
            _ => Err(()),
        }
    }
}

impl TryFrom<String> for UserRole {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(format!("invalid role: {value}")),
        }
    }
}

#[macro_export]
macro_rules! event_params {
    ($event:expr) => {
        duckdb::params![
            $event.entity_id,
            $event.visitor_group_id,
            $event.event,
            $event.created_at,
            $event.fqdn,
            $event.path,
            $event.referrer,
            $event.platform,
            $event.browser,
            $event.mobile,
            $event.country,
            $event.city,
            $event.utm_source,
            $event.utm_medium,
            $event.utm_campaign,
            $event.utm_content,
            $event.utm_term,
            None::<std::time::Duration>,
            None::<std::time::Duration>,
            $event.screen_width,
            $event.orientation,
        ]
    };
}

pub use event_params;
