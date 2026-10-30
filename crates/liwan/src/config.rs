use crate::utils::serde::OneOrMany;
use crate::utils::{
    geoip_headers::GeoIpHeaderSource,
    ip_headers::{ClientIpHeaderSource, TrustedProxy},
};
use anyhow::{Context, Result, bail};
use config::{File, FileFormat, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub base_url: String,
    listen: Option<ListenAddr>,
    port: Option<ListenAddr>,
    // don't load favicons from the duckduckgo api
    pub disable_favicons: bool,
    pub disable_ntp_check: bool,
    /// Links shown in the dashboard footer.
    pub footer_links: Vec<FooterLink>,
    /// HTML inserted directly into the dashboard's `<head>`.
    pub head_html: OneOrMany<String>,
    pub data_dir: String,

    /// Maximum lifetime of a dashboard login, without renewal.
    #[serde(with = "crate::utils::serde::human_duration")]
    pub session_duration: Duration,
    pub geoip: GeoIpConfig,
    pub duckdb: DuckdbConfig,
    pub limits: LimitsConfig,
    pub rate_limit: RateLimitConfig,
    pub oidc: OidcConfig,

    /// Client IP header names or provider presets.
    /// Presets: `cloudflare`, `fastly`, `fly`, `cloudfront`, and `akamai`.
    pub trusted_headers: OneOrMany<ClientIpHeaderSource>,
    pub trusted_proxies: OneOrMany<TrustedProxy>,
    pub visitor_group_rotation_hour: u8,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = if cfg!(target_family = "unix") {
            let home = std::env::var("HOME").ok().unwrap_or_else(|| "/root".to_string());
            std::env::var("XDG_DATA_HOME").map_or_else(
                |_| format!("{home}/.local/share/liwan/data"),
                |data_home| format!("{data_home}/liwan/data"),
            )
        } else {
            "./liwan-data".to_string()
        };

        Self {
            base_url: "http://localhost:9042".to_string(),
            listen: None,
            port: None,
            disable_favicons: false,
            disable_ntp_check: false,
            footer_links: Vec::new(),
            head_html: Default::default(),
            data_dir,
            session_duration: Duration::from_secs(24 * 60 * 60 * 14),
            geoip: Default::default(),
            duckdb: Default::default(),
            limits: Default::default(),
            rate_limit: Default::default(),
            oidc: Default::default(),
            trusted_headers: vec![ClientIpHeaderSource::Header("x-forwarded-for".to_string())].into(),
            trusted_proxies: vec![
                TrustedProxy::Cidr("127.0.0.1/8".parse().expect("valid default trusted proxy")),
                TrustedProxy::Cidr("::1/128".parse().expect("valid default trusted proxy")),
            ]
            .into(),
            visitor_group_rotation_hour: 4,
        }
    }
}

/// A link or HTML shown in the dashboard footer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FooterLink {
    Html(String),
    Link { label: String, url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoIpConfig {
    /// GeoIP header mappings or provider presets.
    /// Presets: `akamai`, `cloudflare`, `cloudfront`, `netlify`, and `vercel`.
    pub headers: OneOrMany<GeoIpHeaderSource>,
    pub maxmind_db_path: Option<String>,
    pub maxmind_account_id: Option<MaxMindAccountId>,
    pub maxmind_license_key: Option<String>,
    pub maxmind_edition: String,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            headers: Default::default(),
            maxmind_db_path: None,
            maxmind_account_id: None,
            maxmind_license_key: None,
            maxmind_edition: "GeoLite2-City".to_string(),
        }
    }
}

/// External identity providers, keyed by the short name that appears in the
/// start URL, the webhook URLs and the env var names.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OidcConfig {
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
}

impl OidcConfig {
    pub fn get(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.get(name)
    }

    /// The single configured provider, if there is exactly one. Lets the CLI and
    /// the login page skip the name when there is nothing to choose between.
    pub fn only(&self) -> Option<(&String, &ProviderConfig)> {
        let mut providers = self.providers.iter();
        providers.next().filter(|_| providers.next().is_none())
    }
}

/// What kind of provider this is. Drives the issuer, the default scopes and
/// which extras are available; `Oidc` is the plain, portable case.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    #[default]
    Oidc,
    Forseti,
    Google,
    Microsoft,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Forseti => "forseti",
            Self::Google => "google",
            Self::Microsoft => "microsoft",
        }
    }

    fn default_display_name(self) -> &'static str {
        match self {
            Self::Oidc => "OpenID Connect",
            Self::Forseti => "Forseti",
            Self::Google => "Google",
            Self::Microsoft => "Microsoft",
        }
    }

    /// Whether `issuer` is configured rather than derived from the kind.
    fn takes_issuer(self) -> bool {
        matches!(self, Self::Oidc | Self::Forseti)
    }
}

/// Who may have a local account created on first sign-in. Returning users,
/// matched on the provider's subject, always log in regardless.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Registration {
    #[default]
    Open,
    Closed,
    /// 1.6.0-fork's third mode. Accepted only so the load error can name its
    /// replacement; rejected in validation.
    DomainAllowlist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)]
    pub kind: ProviderKind,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    /// Forseti's own URL, when Hydra is served somewhere else. Defaults to `issuer`.
    #[serde(default)]
    pub portal_url: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_oidc_scopes", deserialize_with = "deserialize_string_list")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default = "default_true")]
    pub allow_session_reuse: bool,
    #[serde(default)]
    pub registration: Registration,
    #[serde(default, deserialize_with = "deserialize_allowed_domains")]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub groups: Option<GroupsConfig>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            kind: ProviderKind::default(),
            display_name: None,
            issuer: None,
            portal_url: None,
            client_id: String::new(),
            client_secret: String::new(),
            scopes: default_oidc_scopes(),
            tenant_id: None,
            allow_session_reuse: true,
            registration: Registration::default(),
            allowed_domains: Vec::new(),
            groups: None,
        }
    }
}

impl ProviderConfig {
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or_else(|| self.kind.default_display_name())
    }

    /// The OIDC issuer to discover against. Derived for the preset kinds.
    pub fn issuer_url(&self) -> Result<String> {
        match self.kind {
            ProviderKind::Oidc | ProviderKind::Forseti => {
                self.issuer.clone().context("issuer is required for this provider kind")
            }
            ProviderKind::Google => Ok("https://accounts.google.com".to_string()),
            ProviderKind::Microsoft => {
                microsoft_issuer(self.tenant_id.as_deref().context("tenant_id is required for a microsoft provider")?)
            }
        }
    }

    /// Forseti's own base URL, which is where its discovery document and webhook
    /// keys live. Only meaningful for `kind = "forseti"`.
    pub fn portal_url(&self) -> Option<String> {
        if self.kind != ProviderKind::Forseti {
            return None;
        }
        self.portal_url.clone().or_else(|| self.issuer.clone()).map(|url| url.trim_end_matches('/').to_string())
    }

    /// Scopes to request. Configurable for plain OIDC; fixed for the presets,
    /// which know what their own provider accepts.
    pub fn effective_scopes(&self) -> Vec<String> {
        match self.kind {
            ProviderKind::Oidc => self.scopes.clone(),
            ProviderKind::Forseti => {
                let mut scopes = vec!["openid".to_string(), "email".to_string(), "profile".to_string()];
                if self.groups.is_some() {
                    scopes.push("groups".to_string());
                }
                scopes
            }
            ProviderKind::Google | ProviderKind::Microsoft => {
                vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
            }
        }
    }
}

/// Maps IdP group membership onto liwan roles and team membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsConfig {
    #[serde(default = "default_groups_claim")]
    pub claim: String,
    /// When non-empty, a user must be in at least one of these to sign in.
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub allowed: Vec<String>,
    /// Members get role `admin`; everyone else gets `user`.
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub admin: Vec<String>,
    /// Team id every member of this provider joins.
    #[serde(default)]
    pub default_team: Option<String>,
    /// Group name to the team ids its members join. File-only.
    #[serde(default)]
    pub teams: BTreeMap<String, Vec<String>>,
}

impl GroupsConfig {
    /// Whether the outcome of a login depends on the group list at all.
    pub fn reads_groups(&self) -> bool {
        !self.allowed.is_empty() || !self.admin.is_empty() || !self.teams.is_empty()
    }
}

impl Default for GroupsConfig {
    fn default() -> Self {
        Self {
            claim: default_groups_claim(),
            allowed: Vec::new(),
            admin: Vec::new(),
            default_team: None,
            teams: BTreeMap::new(),
        }
    }
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
}

fn default_groups_claim() -> String {
    "groups".to_string()
}

fn default_true() -> bool {
    true
}

/// Derive Microsoft's issuer from the tenant UUID, rejecting anything else:
/// `common` and friends would let any tenant in.
fn microsoft_issuer(tenant_id: &str) -> Result<String> {
    let valid = tenant_id.len() == 36
        && tenant_id.char_indices().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) { character == '-' } else { character.is_ascii_hexdigit() }
        });
    if !valid {
        bail!("Microsoft tenant_id must be a UUID");
    }
    let mut issuer = Url::parse("https://login.microsoftonline.com")?;
    issuer
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid Microsoft authority"))?
        .push(&tenant_id.to_lowercase())
        .push("v2.0");
    Ok(issuer.to_string())
}

/// Accepts a TOML array or a comma-separated env string, since `parse_env_value`
/// only emits scalars for keys it does not know about.
fn deserialize_string_list<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ListInput {
        Single(String),
        Multiple(Vec<String>),
    }

    Ok(match ListInput::deserialize(deserializer)? {
        ListInput::Single(value) => value.split(',').map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()).collect(),
        ListInput::Multiple(values) => values,
    })
}

/// Accepts a TOML array or a comma-separated env string; required because
/// `parse_env_value` only emits scalars for keys it does not know about.
/// Normalizes each entry: trim, strip a trailing `.`, lowercase, drop empties.
pub fn deserialize_allowed_domains<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DomainsInput {
        Single(String),
        Multiple(Vec<String>),
    }

    let values = match DomainsInput::deserialize(deserializer)? {
        DomainsInput::Single(value) => value.split(',').map(str::to_owned).collect::<Vec<_>>(),
        DomainsInput::Multiple(values) => values,
    };

    Ok(values
        .into_iter()
        .map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect())
}

/// Per-client rate limits. Both limits are a token bucket: `burst` tokens up
/// front, one more every `period`. A shared NAT drains one bucket, so the burst
/// carries normal traffic and the period sets the sustained rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_auth_period_seconds")]
    pub auth_period_seconds: u64,
    #[serde(default = "default_auth_burst")]
    pub auth_burst: u32,
    #[serde(default = "default_event_period_ms")]
    pub event_period_ms: u64,
    #[serde(default = "default_event_burst")]
    pub event_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_period_seconds: default_auth_period_seconds(),
            auth_burst: default_auth_burst(),
            event_period_ms: default_event_period_ms(),
            event_burst: default_event_burst(),
        }
    }
}

fn default_auth_period_seconds() -> u64 {
    2
}

fn default_auth_burst() -> u32 {
    5
}

fn default_event_period_ms() -> u64 {
    50
}

fn default_event_burst() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DuckdbConfig {
    pub memory_limit: Option<String>,
    pub threads: Option<NonZeroU16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub report_max_concurrency: usize,
    pub report_timeout_seconds: u64,
    pub report_max_range_days: i64,
    pub report_max_dimension_results: usize,
    /// Minimum entry sessions for bounce rates in summary and dimension reports.
    pub report_min_bounce_rate_sessions: u64,
    /// Minimum measured pageviews for average time in summary and dimension reports.
    pub report_min_avg_time_on_site_samples: u64,
    pub report_max_datapoints: usize,
    pub report_max_filters: usize,
    pub report_max_filter_value_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            report_max_concurrency: 8,
            report_timeout_seconds: 30,
            report_max_range_days: 3660,
            report_max_dimension_results: 1000,
            report_min_bounce_rate_sessions: 10,
            report_min_avg_time_on_site_samples: 5,
            report_max_datapoints: 2000,
            report_max_filters: 20,
            report_max_filter_value_bytes: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MaxMindAccountId {
    String(String),
    Number(u64),
}

impl std::fmt::Display for MaxMindAccountId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(value) => formatter.write_str(value),
            Self::Number(value) => value.fmt(formatter),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ListenAddr {
    Port(u16),
    Addr(String),
}

impl ListenAddr {
    pub fn addr(&self) -> String {
        match self {
            ListenAddr::Port(port) => SocketAddr::from(([0, 0, 0, 0], *port)).to_string(),
            ListenAddr::Addr(addr) => addr.clone(),
        }
    }
}

pub static DEFAULT_CONFIG: &str = include_str!("../../../data/config.example.toml");

impl Config {
    pub fn load<I, K, V>(path: Option<String>, env_vars: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let path = path.or_else(|| std::env::var("LIWAN_CONFIG").ok());
        let mut builder = config::Config::builder();

        #[cfg(all(not(test), target_family = "unix"))]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let config = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
            builder = builder
                .add_source(File::new(&format!("{config}/liwan/config.toml"), FileFormat::Toml).required(false))
                .add_source(File::new(&format!("{config}/liwan/liwan.config.toml"), FileFormat::Toml).required(false))
                .add_source(File::new(&format!("{config}/liwan.config.toml"), FileFormat::Toml).required(false));

            builder = builder.add_source(File::new("liwan.config.toml", FileFormat::Toml).required(false));
        }

        if let Some(path) = path {
            builder = builder.add_source(File::new(&path, FileFormat::Toml).required(false));
        }

        for (key, value) in env_vars {
            if let Some(mapped_key) = map_env_key(key.as_ref()) {
                if is_empty_allow_list(&mapped_key, value.as_ref()) {
                    bail!(
                        "{} is set but lists nothing, which would let everyone in; unset it or name at least one entry",
                        key.as_ref()
                    );
                }
                builder = builder.set_override(&mapped_key, parse_env_value(&mapped_key, value.as_ref()))?;
            };
        }

        let sources = builder.build()?;
        reject_legacy_oidc(&sources)?;
        reject_legacy_groups(&sources)?;
        let config: Self = sources.try_deserialize()?;

        let base_url: Url = Url::from_str(&config.base_url).context("Invalid base URL")?;
        if !["http", "https"].contains(&base_url.scheme()) {
            bail!("Invalid base URL: protocol must be either http or https");
        }
        if base_url.host_str().is_none()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.username() != ""
            || base_url.password().is_some()
        {
            bail!(
                "Invalid base URL: expected an HTTP(S) origin and optional path, without credentials, query or fragment"
            );
        }
        if config.base_url.ends_with('/') && base_url.path() != "/" {
            bail!("Invalid base URL: remove the trailing slash from the path");
        }
        if config.base_path().starts_with("//") || base_url.path().trim_end_matches('/') != config.base_path() {
            bail!("Invalid base URL: path must not contain dot segments or require URL normalization");
        }
        if base_url.scheme() != "https" {
            tracing::warn!("Base URL is not using HTTPS");
        }
        if config.listen.is_some() && config.port.is_some() {
            tracing::warn!(
                "Both `listen` and `port` configuration options are set. The `listen` option will take precedence over `port`."
            );
        }
        if config.visitor_group_rotation_hour > 23 {
            bail!("Invalid visitor_group_rotation_hour: must be between 0 and 23");
        }
        if !(Duration::from_secs(60 * 60)..=Duration::from_secs(365 * 24 * 60 * 60)).contains(&config.session_duration)
        {
            bail!("Invalid session_duration: must be between 1 hour and 365 days");
        }
        // A zero period or burst is rejected by the governor builder, which would
        // panic well after boot. Catch it here instead.
        if config.rate_limit.auth_period_seconds == 0 || config.rate_limit.event_period_ms == 0 {
            bail!("Invalid rate_limit: auth_period_seconds and event_period_ms must be greater than 0");
        }
        if config.rate_limit.auth_burst == 0 || config.rate_limit.event_burst == 0 {
            bail!("Invalid rate_limit: auth_burst and event_burst must be greater than 0");
        }
        if config.limits.report_max_concurrency == 0 || config.limits.report_max_concurrency > 10 {
            bail!("Invalid limits.report_max_concurrency: must be between 1 and 10");
        }
        if config.limits.report_timeout_seconds == 0
            || config.limits.report_max_range_days <= 0
            || config.limits.report_max_dimension_results == 0
            || config.limits.report_max_datapoints == 0
            || config.limits.report_max_filters == 0
            || config.limits.report_max_filter_value_bytes == 0
        {
            bail!("Invalid report limit: values must be greater than zero");
        }
        validate_providers(&config.oidc)?;

        Ok(config)
    }

    /// The URLs an operator has to register with each provider. Logged at
    /// startup so nobody has to reconstruct them from the README.
    pub fn log_provider_urls(&self) {
        if self.oidc.providers.is_empty() {
            return;
        }
        match self.external_auth_redirect_uri() {
            Ok(redirect_uri) => {
                tracing::info!(%redirect_uri, "External auth redirect URI (register this with every provider)");
            }
            Err(error) => tracing::warn!(%error, "Could not build the external auth redirect URI"),
        }
        for (name, provider) in &self.oidc.providers {
            let base = self.base_url.trim_end_matches('/');
            tracing::info!(
                provider = %name,
                kind = %provider.kind.as_str(),
                backchannel_logout_uri = %format!("{base}/api/dashboard/auth/external/{name}/backchannel-logout"),
                "External auth provider configured"
            );
            if provider.kind == ProviderKind::Forseti {
                tracing::info!(
                    provider = %name,
                    account_deletion_url = %format!("{base}/api/dashboard/auth/external/{name}/account-deletion"),
                    "Set this as the Forseti client's account_deletion_url"
                );
            }
        }
    }

    /// One redirect URI serves every provider.
    pub fn external_auth_redirect_uri(&self) -> Result<Url> {
        self.public_url("/api/dashboard/auth/external/callback")
    }

    pub fn listen_addr(&self) -> String {
        self.listen.as_ref().or(self.port.as_ref()).unwrap_or(&ListenAddr::Port(9042)).addr()
    }

    pub fn secure(&self) -> bool {
        self.base_url.split_once("://").is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
    }

    /// Returns the configured URL path prefix, or an empty string at the origin root.
    pub fn base_path(&self) -> &str {
        let url = self.base_url.split_once("://").map(|(_, rest)| rest).unwrap_or(&self.base_url);
        url.find('/').map(|index| url[index..].trim_end_matches('/')).unwrap_or("")
    }

    /// Prefixes an application path (starting with `/`) with the configured base path.
    pub fn path(&self, path: &str) -> String {
        format!("{}{path}", self.base_path())
    }

    /// Builds a public URL for an application path (starting with `/`).
    pub fn public_url(&self, path: &str) -> Result<Url> {
        let mut url = Url::parse(&self.base_url).context("Invalid base URL")?;
        url.set_path(&self.path(path));
        Ok(url)
    }
}

/// The keys 1.6.0-fork accepted directly under `[oidc]`.
const LEGACY_OIDC_KEYS: &[&str] =
    &["issuer", "client_id", "client_secret", "scopes", "button_label", "registration", "allowed_domains"];

/// 1.6.0-fork configured a single provider directly under `[oidc]`. Serde would
/// ignore those keys and start with SSO silently switched off, so name them.
fn reject_legacy_oidc(sources: &config::Config) -> Result<()> {
    const LEGACY: &[(&str, &str)] = &[
        ("oidc.issuer", "oidc.providers.<name>.issuer"),
        ("oidc.client_id", "oidc.providers.<name>.client_id"),
        ("oidc.client_secret", "oidc.providers.<name>.client_secret"),
        ("oidc.scopes", "oidc.providers.<name>.scopes"),
        ("oidc.button_label", "oidc.providers.<name>.display_name"),
        ("oidc.registration", "oidc.providers.<name>.registration"),
        ("oidc.allowed_domains", "oidc.providers.<name>.allowed_domains"),
    ];

    for (legacy, replacement) in LEGACY {
        if sources.get::<config::Value>(legacy).is_ok() {
            bail!(
                "`{legacy}` is no longer supported; configure a named provider instead: `{replacement}`. See the v1.7.0-fork.1 entry in the CHANGELOG."
            );
        }
    }
    Ok(())
}

/// 1.7.0-fork mapped groups straight to projects. Serde would ignore the key and
/// sign people in with no access at all, so name the replacement.
fn reject_legacy_groups(sources: &config::Config) -> Result<()> {
    // Provider names may contain hyphens, which a dotted path lookup cannot address.
    let Ok(providers) = sources.get_table("oidc.providers") else {
        return Ok(());
    };
    let mut names: Vec<_> = providers.keys().collect();
    names.sort();
    for name in names {
        let Some(groups) =
            providers[name].clone().into_table().ok().and_then(|provider| provider.get("groups").cloned())
        else {
            continue;
        };
        if groups.into_table().is_ok_and(|groups| groups.contains_key("projects")) {
            bail!(
                "`oidc.providers.{name}.groups.projects` is no longer supported; map groups to teams with `oidc.providers.{name}.groups.teams` and optionally `groups.default_team`. Teams must exist first: create them in the teams UI and use their ids. See the \"Upgrading from 1.7.0-fork\" section of the README."
            );
        }
    }
    Ok(())
}

/// Everything that has to hold before the first login attempt, so a typo fails
/// at boot rather than at someone's sign-in.
fn validate_providers(oidc: &OidcConfig) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    let mut issuers: BTreeMap<String, &str> = BTreeMap::new();
    for (name, provider) in &oidc.providers {
        if !is_valid_provider_name(name) {
            bail!(
                "Invalid oidc provider name {name:?}: use lowercase letters, digits and hyphens, starting with a letter or digit, at most 32 characters"
            );
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            bail!("Duplicate oidc provider name {name:?}: names are case-insensitive");
        }
        if provider.registration == Registration::DomainAllowlist {
            bail!(
                "oidc.providers.{name}.registration = \"domain_allowlist\" is no longer a mode; use `registration = \"open\"` with `allowed_domains`, which now applies on every login rather than only at sign-up"
            );
        }
        if provider.client_id.trim().is_empty() {
            bail!("oidc.providers.{name}.client_id is required");
        }
        if provider.client_secret.trim().is_empty() {
            bail!(
                "oidc.providers.{name}.client_secret is required (prefer LIWAN_OIDC_PROVIDERS_{}_CLIENT_SECRET)",
                name.to_ascii_uppercase().replace('-', "_")
            );
        }

        if provider.kind.takes_issuer() {
            let issuer = provider.issuer.as_deref().with_context(|| {
                format!("oidc.providers.{name}.issuer is required for kind = \"{}\"", provider.kind.as_str())
            })?;
            validate_provider_url(&format!("oidc.providers.{name}.issuer"), issuer)?;
        } else if provider.issuer.is_some() {
            bail!("oidc.providers.{name}.issuer is not used by kind = \"{}\"", provider.kind.as_str());
        }

        match provider.portal_url.as_deref() {
            Some(_) if provider.kind != ProviderKind::Forseti => {
                bail!("oidc.providers.{name}.portal_url is only used by kind = \"forseti\"")
            }
            Some(portal_url) => validate_provider_url(&format!("oidc.providers.{name}.portal_url"), portal_url)?,
            None => {}
        }

        match provider.kind {
            ProviderKind::Microsoft => {
                let tenant_id = provider
                    .tenant_id
                    .as_deref()
                    .with_context(|| format!("oidc.providers.{name}.tenant_id is required for kind = \"microsoft\""))?;
                if microsoft_issuer(tenant_id).is_err() {
                    bail!("Invalid oidc.providers.{name}.tenant_id: must be a UUID");
                }
            }
            _ if provider.tenant_id.is_some() => {
                bail!("oidc.providers.{name}.tenant_id is only used by kind = \"microsoft\"")
            }
            _ => {}
        }

        // Compared as-is: discovery requires the exact configured string and identities key on it.
        let issuer = provider.issuer_url()?;
        if let Some(first) = issuers.insert(issuer.clone(), name) {
            bail!(
                "oidc.providers.{first} and oidc.providers.{name} both use issuer {issuer}; each issuer can be configured once"
            );
        }

        // The preset kinds request a fixed scope set, so a configured one is a
        // silent no-op rather than a preference.
        if provider.kind != ProviderKind::Oidc && provider.scopes != default_oidc_scopes() {
            bail!("oidc.providers.{name}.scopes is only used by kind = \"oidc\"");
        }
        if provider.kind == ProviderKind::Oidc
            && !provider.allowed_domains.is_empty()
            && !provider.scopes.iter().any(|scope| scope == "email")
        {
            bail!(
                "oidc.providers.{name}.allowed_domains needs the \"email\" scope in oidc.providers.{name}.scopes to read the verified email"
            );
        }
        if let Some(groups) = &provider.groups {
            validate_groups(name, groups)?;
            if (groups.reads_groups() || groups.default_team.is_some())
                && !provider.effective_scopes().iter().any(|scope| scope == "groups")
            {
                tracing::warn!(
                    provider = %name,
                    "oidc.providers.{name}.groups is set but \"groups\" is not in scopes; this only works if the IdP emits the claim unasked"
                );
            }
        }
    }
    Ok(())
}

fn validate_groups(name: &str, groups: &GroupsConfig) -> Result<()> {
    // Entra's overage markers, read separately from the group claim itself.
    if matches!(groups.claim.as_str(), "hasgroups" | "_claim_names") {
        bail!("Invalid oidc.providers.{name}.groups.claim: {:?} is reserved", groups.claim);
    }
    if let Some(team) = &groups.default_team
        && !is_valid_team_id(team)
    {
        bail!(
            "Invalid oidc.providers.{name}.groups.default_team {team:?}: team ids are ASCII letters and digits, at most 64 characters"
        );
    }
    for (group, teams) in &groups.teams {
        if group.is_empty() {
            bail!("Invalid oidc.providers.{name}.groups.teams: group names cannot be empty");
        }
        if let Some(team) = teams.iter().find(|team| !is_valid_team_id(team)) {
            bail!(
                "Invalid oidc.providers.{name}.groups.teams.{group} team id {team:?}: team ids are ASCII letters and digits, at most 64 characters"
            );
        }
    }
    Ok(())
}

fn is_valid_team_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

fn is_valid_provider_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Both the issuer and Forseti's portal carry the client secret, the
/// authorization code and the ID token, so plain http is only tolerated against
/// a loopback host for local development.
fn validate_provider_url(field: &str, value: &str) -> Result<()> {
    let url = Url::parse(value).with_context(|| format!("Invalid {field}"))?;
    if !is_https_or_loopback(&url) {
        bail!("Invalid {field}: must use https; http is allowed only for localhost");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("Invalid {field}: cannot contain a query or fragment");
    }
    Ok(())
}

/// Plain http is tolerated only against a loopback host, so local development
/// against an IdP on the same machine keeps working.
///
/// A name is resolved rather than compared to `localhost`: a container runtime's
/// host alias (`host.containers.internal`) is loopback in every sense that
/// matters here, and refusing it would only push people towards a worse
/// workaround. This decides whether the configuration is accepted, not where the
/// request goes; the discovery checks in `external_auth` still reject provider
/// endpoints that point somewhere else.
fn is_https_or_loopback(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => resolves_to_loopback(host, url.port().unwrap_or(80)),
        None => false,
    }
}

/// Whether every address a name resolves to is loopback. A name that resolves to
/// nothing is not, and neither is one that resolves partly off-machine.
pub fn resolves_to_loopback(host: &str, port: u16) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match std::net::ToSocketAddrs::to_socket_addrs(&(host, port)) {
        Ok(mut addresses) => {
            let mut any = false;
            let all_loopback = addresses.all(|address| {
                any = true;
                address.ip().is_loopback()
            });
            any && all_loopback
        }
        Err(_) => false,
    }
}

fn map_env_key(key: &str) -> Option<String> {
    let key = key.strip_prefix("LIWAN_")?.to_ascii_lowercase();
    if key == "geoip_headers" {
        return Some("geoip.headers".to_string());
    }
    if let Some(rest) = key.strip_prefix("oidc_providers_") {
        return map_provider_env_key(rest);
    }
    // Nest the 1.6.0-fork keys so `reject_legacy_oidc` sees them; left flat they
    // would be an unmapped top-level key and silently do nothing.
    if let Some(rest) = key.strip_prefix("oidc_")
        && LEGACY_OIDC_KEYS.contains(&rest)
    {
        return Some(format!("oidc.{rest}"));
    }
    const NESTED_PREFIXES: &[(&str, &str)] = &[
        ("maxmind_", "geoip.maxmind_"),
        ("duckdb_", "duckdb."),
        ("limits_", "limits."),
        ("rate_limit_", "rate_limit."),
    ];

    for (prefix, mapped_prefix) in NESTED_PREFIXES {
        if let Some(rest) = key.strip_prefix(prefix) {
            return Some(format!("{mapped_prefix}{rest}"));
        }
    }

    Some(key)
}

/// `LIWAN_OIDC_PROVIDERS_<NAME>_<KEY>` splits at the first `_`: provider names
/// cannot contain one, keys can. A `groups_` key prefix addresses the sub-table.
fn map_provider_env_key(rest: &str) -> Option<String> {
    let (name, key) = rest.split_once('_')?;
    if name.is_empty() || key.is_empty() {
        return None;
    }
    let key = match key.strip_prefix("groups_") {
        Some(group_key) => format!("groups.{group_key}"),
        None => key.to_string(),
    };
    Some(format!("oidc.providers.{name}.{key}"))
}

/// The list parsers drop empty items, so an empty value would replace the file's list with no restriction.
fn is_empty_allow_list(key: &str, value: &str) -> bool {
    if !key.starts_with("oidc.providers.") {
        return false;
    }
    let mut items = value.split(',').map(str::trim);
    if key.ends_with(".allowed_domains") {
        items.all(|item| item.trim_end_matches('.').is_empty())
    } else if key.ends_with(".groups.allowed") {
        items.all(str::is_empty)
    } else {
        false
    }
}

fn parse_env_value(key: &str, value: &str) -> Value {
    if ["trusted_headers", "trusted_proxies", "geoip.headers"].contains(&key) && value.contains(',') {
        return Value::from(value.split(',').map(str::trim).collect::<Vec<_>>());
    }
    // The list fields take a comma-separated string; `config` would otherwise
    // hand serde a scalar for what has to deserialize as a sequence. A team id
    // stays a string so an all-digit one keeps its leading zeros.
    if key.starts_with("oidc.providers.")
        && [".allowed_domains", ".scopes", ".groups.allowed", ".groups.admin", ".groups.default_team"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
    {
        return Value::from(value.to_string());
    }

    value
        .parse::<bool>()
        .ok()
        .map(Value::from)
        .or_else(|| value.parse::<i64>().ok().map(Value::from))
        .or_else(|| value.parse::<f64>().ok().map(Value::from))
        .unwrap_or_else(|| Value::from(value.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::ip_headers::{ClientIpHeaderSource, ClientIpProvider, TrustedProxy};
    use tempfile::TempDir;

    fn temp_config(name: &str, content: &str) -> (TempDir, String) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = temp_dir.path().join(name);
        std::fs::write(&path, content).expect("failed to create config file");
        (temp_dir, path.to_string_lossy().into_owned())
    }

    #[test]
    fn test_config() {
        let (_temp_dir, config_path) = temp_config(
            "liwan2.config.toml",
            r#"
                base_url = "http://localhost:8081"
                data_dir = "./liwan-test-data"
                [geoip]
                maxmind_db_path = "test2"
            "#,
        );

        let env = vec![
            ("LIWAN_MAXMIND_EDITION", "test"),
            ("LIWAN_GEOIP_MAXMIND_EDITION", "test2"),
            ("GEOIP_MAXMIND_EDITION", "test3"),
            ("LIWAN_DUCKDB_MEMORY_LIMIT", "2GB"),
            ("LIWAN_DUCKDB_THREADS", "4"),
            ("LIWAN_LIMITS_REPORT_MAX_CONCURRENCY", "6"),
            ("LIWAN_LIMITS_REPORT_TIMEOUT_SECONDS", "45"),
            ("LIWAN_MAXMIND_LICENSE_KEY", "test"),
            ("LIWAN_MAXMIND_ACCOUNT_ID", "test"),
            ("LIWAN_MAXMIND_DB_PATH", "test"),
        ];

        let config = Config::load(Some(config_path), env).expect("failed to load config");

        assert_eq!(config.geoip.maxmind_edition, "test".to_string());
        assert_eq!(config.geoip.maxmind_license_key, Some("test".to_string()));
        assert_eq!(config.geoip.maxmind_account_id, Some(MaxMindAccountId::String("test".to_string())));
        assert_eq!(config.geoip.maxmind_db_path, Some("test".to_string()));
        assert_eq!(config.base_url, "http://localhost:8081");
        assert_eq!(config.data_dir, "./liwan-test-data");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
        assert_eq!(config.duckdb.memory_limit, Some("2GB".to_string()));
        assert_eq!(config.duckdb.threads, Some(NonZeroU16::new(4).unwrap()));
        assert_eq!(config.limits.report_max_concurrency, 6);
        assert_eq!(config.limits.report_timeout_seconds, 45);
    }

    #[test]
    fn test_empty_proxy_config_overrides_defaults() {
        let (_temp_dir, config_path) = temp_config(
            "empty-proxies.config.toml",
            r#"
                trusted_headers = []
                trusted_proxies = []
            "#,
        );

        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");

        assert!(config.trusted_headers.is_empty());
        assert!(config.trusted_proxies.is_empty());
    }

    #[test]
    fn test_custom_html_config() {
        let (_temp_dir, config_path) = temp_config(
            "custom-html.config.toml",
            r#"
                head_html = ['<meta name="custom" content="enabled">', '<meta name="second" content="yes">']
                footer_links = [{ label = "Privacy & terms", url = "https://example.com/privacy?a=1&b=2" }, '<a href="/help">Help</a>']
            "#,
        );

        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).unwrap();
        assert_eq!(
            config.head_html.as_ref(),
            &[
                "<meta name=\"custom\" content=\"enabled\">".to_string(),
                "<meta name=\"second\" content=\"yes\">".to_string()
            ]
        );
        assert_eq!(
            config.footer_links,
            vec![
                FooterLink::Link {
                    label: "Privacy & terms".to_string(),
                    url: "https://example.com/privacy?a=1&b=2".to_string(),
                },
                FooterLink::Html("<a href=\"/help\">Help</a>".to_string())
            ]
        );
        assert_eq!(
            Config::load(None, [("LIWAN_HEAD_HTML", "<meta name='single'>")]).unwrap().head_html.as_ref(),
            &["<meta name='single'>".to_string()]
        );
    }

    #[test]
    fn test_env() {
        let env = vec![
            ("LIWAN_DATA_DIR", "/data"),
            ("LIWAN_BASE_URL", "https://example.com"),
            ("LIWAN_MAXMIND_ACCOUNT_ID", "123"),
            ("LIWAN_TRUSTED_HEADERS", "X_Forwarded_For,Forwarded"),
            ("LIWAN_TRUSTED_PROXIES", "127.0.0.1,10.0.0.0/8"),
        ];

        let config = Config::load(None, env).expect("failed to load config");
        assert_eq!(config.data_dir, "/data");
        assert_eq!(config.base_url, "https://example.com");
        assert_eq!(config.geoip.maxmind_account_id, Some(MaxMindAccountId::Number(123)));
        assert_eq!(
            config.trusted_headers.as_ref(),
            &[
                ClientIpHeaderSource::Header("x-forwarded-for".to_string()),
                ClientIpHeaderSource::Header("forwarded".to_string())
            ]
        );
        assert_eq!(
            config.trusted_proxies.as_ref(),
            &[TrustedProxy::Ip("127.0.0.1".parse().unwrap()), TrustedProxy::Cidr("10.0.0.0/8".parse().unwrap())]
        );
    }

    #[test]
    fn test_rate_limit_defaults_and_env_override() {
        let config = Config::load(None, Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(config.rate_limit.auth_period_seconds, 2);
        assert_eq!(config.rate_limit.auth_burst, 5);
        assert_eq!(config.rate_limit.event_period_ms, 50);
        assert_eq!(config.rate_limit.event_burst, 100);

        let config =
            Config::load(None, vec![("LIWAN_RATE_LIMIT_AUTH_BURST", "3"), ("LIWAN_RATE_LIMIT_EVENT_PERIOD_MS", "10")])
                .expect("failed to load config");
        assert_eq!(config.rate_limit.auth_burst, 3);
        assert_eq!(config.rate_limit.event_period_ms, 10);
        assert_eq!(config.rate_limit.auth_period_seconds, 2);
    }

    #[test]
    fn test_rate_limit_rejects_zero() {
        assert!(Config::load(None, vec![("LIWAN_RATE_LIMIT_AUTH_BURST", "0")]).is_err());
        assert!(Config::load(None, vec![("LIWAN_RATE_LIMIT_EVENT_BURST", "0")]).is_err());
        assert!(Config::load(None, vec![("LIWAN_RATE_LIMIT_AUTH_PERIOD_SECONDS", "0")]).is_err());
        assert!(Config::load(None, vec![("LIWAN_RATE_LIMIT_EVENT_PERIOD_MS", "0")]).is_err());
    }

    #[test]
    fn test_env_custom_trusted_header() {
        let config = Config::load(None, vec![("LIWAN_TRUSTED_HEADERS", "X_CLIENT_IP")]).expect("failed to load config");
        assert_eq!(config.trusted_headers.as_ref(), &[ClientIpHeaderSource::Header("x-client-ip".to_string())]);
    }

    #[test]
    fn test_wildcard_trusted_proxy() {
        let env_config = Config::load(None, [("LIWAN_TRUSTED_PROXIES", "*")]).expect("failed to load config");
        assert_eq!(env_config.trusted_proxies.as_ref(), &[TrustedProxy::All]);

        let (_temp_dir, config_path) = temp_config("wildcard-proxy.config.toml", "trusted_proxies = \"*\"");
        let file_config =
            Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(file_config.trusted_proxies.as_ref(), &[TrustedProxy::All]);
    }

    #[test]
    fn test_header_presets_and_geoip_mappings() {
        let (_temp_dir, config_path) = temp_config(
            "headers.config.toml",
            r#"
                trusted_headers = ["cloudflare", "fastly", "fly", "akamai", "X-Client-IP"]

                [geoip]
                headers = ["cloudflare", { country = "X-Country", city = "X-City" }]
            "#,
        );

        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(
            config.trusted_headers.as_ref(),
            &[
                ClientIpHeaderSource::Provider(ClientIpProvider::Cloudflare),
                ClientIpHeaderSource::Provider(ClientIpProvider::Fastly),
                ClientIpHeaderSource::Provider(ClientIpProvider::Fly),
                ClientIpHeaderSource::Provider(ClientIpProvider::Akamai),
                ClientIpHeaderSource::Header("x-client-ip".to_string())
            ]
        );
        assert_eq!(config.geoip.headers.len(), 2);
        assert_eq!(
            config.geoip.headers[0],
            GeoIpHeaderSource::Provider(crate::utils::geoip_headers::GeoIpProvider::Cloudflare)
        );
        assert_eq!(
            config.geoip.headers[1],
            GeoIpHeaderSource::Mapping(crate::utils::geoip_headers::GeoIpHeaderMapping {
                country: "X-Country".to_string(),
                city: "X-City".to_string(),
            })
        );
    }

    #[test]
    fn test_trusted_headers_serialization() {
        let (_temp_dir, config_path) = temp_config("headers.config.toml", "trusted_headers = \"fly\"");
        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");

        assert_eq!(config.trusted_headers.as_ref(), &[ClientIpHeaderSource::Provider(ClientIpProvider::Fly)]);
        let serialized = serde_json::to_value(config).expect("failed to serialize config");
        assert!(serialized.get("trusted_headers").is_some());
        assert!(serialized.get("client_ip_headers").is_none());
    }

    #[test]
    fn test_defaults() {
        let config = Config::load(None, Vec::<(String, String)>::new()).expect("failed to load config");
        let default = Config::default();
        assert_eq!(config.base_url, "http://localhost:9042");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
        assert_eq!(config.data_dir, default.data_dir);
        assert_eq!(config.session_duration, Duration::from_secs(24 * 60 * 60 * 14));
        assert_eq!(config.visitor_group_rotation_hour, 4);
        assert!(config.geoip.maxmind_db_path.is_none());
        assert!(config.geoip.maxmind_account_id.is_none());
        assert!(config.geoip.maxmind_license_key.is_none());
        assert_eq!(config.geoip.maxmind_edition, "GeoLite2-City");
        assert_eq!(default.geoip.maxmind_edition, "GeoLite2-City");
        assert_eq!(config.trusted_headers.as_ref(), &[ClientIpHeaderSource::Header("x-forwarded-for".to_string())]);
        assert_eq!(config.trusted_headers, default.trusted_headers);
        assert_eq!(
            config.trusted_proxies.as_ref(),
            &[TrustedProxy::Cidr("127.0.0.1/8".parse().unwrap()), TrustedProxy::Cidr("::1/128".parse().unwrap())]
        );
        assert_eq!(config.trusted_proxies, default.trusted_proxies);
        assert_eq!(config.limits.report_max_concurrency, 8);
        assert_eq!(config.limits.report_timeout_seconds, 30);
        assert_eq!(config.limits.report_max_range_days, 3660);
        assert_eq!(config.limits.report_max_dimension_results, 1000);
        assert_eq!(config.limits.report_min_bounce_rate_sessions, 10);
        assert_eq!(config.limits.report_min_avg_time_on_site_samples, 5);
        assert_eq!(config.limits.report_max_datapoints, 2000);
        assert_eq!(config.limits.report_max_filters, 20);
        assert_eq!(config.limits.report_max_filter_value_bytes, 2048);

        // a partial geoip section keeps the remaining defaults
        let (_temp_dir, config_path) = temp_config(
            "liwan3.config.toml",
            r#"
                base_url = "http://localhost:8081"
                data_dir = "./liwan-test-data"
                [geoip]
                maxmind_db_path = "test2"
            "#,
        );
        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(config.geoip.maxmind_edition, "GeoLite2-City");
        assert_eq!(config.geoip.maxmind_db_path, Some("test2".to_string()));
        assert_eq!(config.base_url, "http://localhost:8081");
        assert_eq!(config.data_dir, "./liwan-test-data");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
    }

    #[test]
    fn test_invalid_report_limits() {
        let error = Config::load(None, [("LIWAN_LIMITS_REPORT_TIMEOUT_SECONDS", "0")]).unwrap_err();
        assert!(error.to_string().contains("values must be greater than zero"));

        let error = Config::load(None, [("LIWAN_LIMITS_REPORT_MAX_CONCURRENCY", "11")]).unwrap_err();
        assert!(error.to_string().contains("must be between 1 and 10"));
    }

    #[test]
    fn test_report_sample_limit_overrides() {
        let config = Config::load(
            None,
            [
                ("LIWAN_LIMITS_REPORT_MIN_BOUNCE_RATE_SESSIONS", "0"),
                ("LIWAN_LIMITS_REPORT_MIN_AVG_TIME_ON_SITE_SAMPLES", "3"),
            ],
        )
        .expect("report sample limits should load from environment variables");
        assert_eq!(config.limits.report_min_bounce_rate_sessions, 0);
        assert_eq!(config.limits.report_min_avg_time_on_site_samples, 3);
    }

    #[test]
    fn test_session_duration() {
        let (_temp_dir, path) = temp_config("session.config.toml", "session_duration = \"2 days\"");
        assert_eq!(
            Config::load(Some(path), Vec::<(String, String)>::new()).unwrap().session_duration,
            Duration::from_secs(48 * 60 * 60)
        );
        assert_eq!(
            Config::load(None, [("LIWAN_SESSION_DURATION", "24h")]).unwrap().session_duration,
            Duration::from_secs(24 * 60 * 60)
        );
        let serialized = serde_json::to_value(Config::default()).unwrap();
        assert!(serialized["session_duration"].is_string());
        assert_eq!(
            serde_json::from_value::<Config>(serialized).unwrap().session_duration,
            Config::default().session_duration
        );
        for value in ["0", "0s", "0h", "8761h", "banana", "14", "-1d"] {
            assert!(Config::load(None, [("LIWAN_SESSION_DURATION", value)]).is_err());
        }
    }
    /// `extra` supplies `issuer` unless it sets one of its own.
    fn load_provider(extra: &str) -> Result<Config> {
        let issuer = if extra.contains("issuer") || extra.contains("kind") {
            String::new()
        } else {
            "issuer = \"https://idp.example.com\"".to_string()
        };
        let content = format!(
            r#"
                base_url = "https://example.com"
                [oidc.providers.company]
                client_id = "liwan"
                client_secret = "shhh"
                {issuer}
                {extra}
            "#
        );
        let (_dir, path) = temp_config("liwan-provider.config.toml", &content);
        Config::load(Some(path), Vec::<(String, String)>::new())
    }

    #[test]
    fn oidc_parses_two_providers() {
        let (_dir, path) = temp_config(
            "liwan-two-providers.config.toml",
            r#"
                base_url = "https://example.com"

                [oidc.providers.company]
                kind = "forseti"
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                display_name = "Company SSO"

                [oidc.providers.company.groups]
                admin = ["liwan-admins"]
                default_team = "everyone"
                teams = { marketing = ["blogTeam", "docsTeam"], "app-devs" = ["eng"] }

                [oidc.providers.partner]
                issuer = "https://idp.partner.example"
                client_id = "liwan-partner"
                client_secret = "also-shhh"
                allow_session_reuse = false
                registration = "closed"
                allowed_domains = [" Partner.COM ", "acme.org.", ""]
            "#,
        );
        let config = Config::load(Some(path), Vec::<(String, String)>::new()).expect("failed to load config");

        let company = config.oidc.get("company").expect("company provider");
        assert_eq!(company.kind, ProviderKind::Forseti);
        assert_eq!(company.display_name(), "Company SSO");
        assert_eq!(company.portal_url().as_deref(), Some("https://accounts.example.com"));
        assert!(company.allow_session_reuse);
        let groups = company.groups.as_ref().expect("groups table");
        assert_eq!(groups.claim, "groups");
        assert_eq!(groups.admin, vec!["liwan-admins".to_string()]);
        assert_eq!(groups.default_team.as_deref(), Some("everyone"));
        assert_eq!(groups.teams["marketing"], vec!["blogTeam".to_string(), "docsTeam".to_string()]);
        assert_eq!(groups.teams["app-devs"], vec!["eng".to_string()]);

        let partner = config.oidc.get("partner").expect("partner provider");
        assert_eq!(partner.kind, ProviderKind::Oidc);
        assert_eq!(partner.display_name(), "OpenID Connect");
        assert!(!partner.allow_session_reuse);
        assert_eq!(partner.registration, Registration::Closed);
        assert_eq!(partner.allowed_domains, vec!["partner.com".to_string(), "acme.org".to_string()]);
        assert!(partner.portal_url().is_none(), "portal_url is forseti-only");

        assert!(config.oidc.only().is_none(), "two providers is not one");
        assert_eq!(
            config.external_auth_redirect_uri().unwrap().as_str(),
            "https://example.com/api/dashboard/auth/external/callback"
        );
    }

    #[test]
    fn oidc_env_overrides_nested_keys() {
        let (_dir, path) = temp_config(
            "liwan-provider-env.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.company]
                issuer = "https://idp.example.com"
                client_id = "liwan"
                client_secret = "placeholder"
                [oidc.providers.company.groups]
                admin = ["placeholder"]
            "#,
        );
        let env = vec![
            ("LIWAN_OIDC_PROVIDERS_COMPANY_CLIENT_SECRET", "from-env"),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_ALLOWED_DOMAINS", "Example.com, acme.org"),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_ADMIN", "ops,platform"),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_ALLOW_SESSION_REUSE", "false"),
        ];
        let config = Config::load(Some(path), env).expect("failed to load config");

        let company = config.oidc.get("company").expect("company provider");
        assert_eq!(company.client_secret, "from-env");
        assert_eq!(company.allowed_domains, vec!["example.com".to_string(), "acme.org".to_string()]);
        assert!(!company.allow_session_reuse);
        assert_eq!(company.groups.as_ref().expect("groups").admin, vec!["ops".to_string(), "platform".to_string()]);
    }

    #[test]
    fn oidc_env_key_mapping() {
        assert_eq!(
            map_env_key("LIWAN_OIDC_PROVIDERS_COMPANY_CLIENT_SECRET").as_deref(),
            Some("oidc.providers.company.client_secret")
        );
        assert_eq!(
            map_env_key("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_ALLOWED").as_deref(),
            Some("oidc.providers.company.groups.allowed")
        );
        // The name stops at the first `_`, so keys may contain one and names may not.
        assert_eq!(
            map_env_key("LIWAN_OIDC_PROVIDERS_MY-IDP_TENANT_ID").as_deref(),
            Some("oidc.providers.my-idp.tenant_id")
        );
        assert_eq!(map_env_key("LIWAN_OIDC_PROVIDERS_COMPANY"), None);
    }

    #[test]
    fn oidc_rejects_bad_provider_names() {
        let (_dir, path) = temp_config(
            "liwan-bad-name.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers."Company SSO"]
                issuer = "https://idp.example.com"
                client_id = "liwan"
                client_secret = "shhh"
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("Invalid oidc provider name"), "got: {error}");
    }

    #[test]
    fn oidc_requires_client_credentials() {
        let (_dir, path) = temp_config(
            "liwan-no-secret.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.company]
                issuer = "https://idp.example.com"
                client_id = "liwan"
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("client_secret is required"), "got: {error}");
        assert!(error.to_string().contains("LIWAN_OIDC_PROVIDERS_COMPANY_CLIENT_SECRET"), "got: {error}");
    }

    #[test]
    fn oidc_issuer_rules() {
        assert!(load_provider("").is_ok());
        assert!(load_provider(r#"issuer = "http://localhost:4444""#).is_ok(), "loopback http is for local dev");
        assert!(load_provider(r#"issuer = "http://127.0.0.1:4444""#).is_ok());
        assert!(load_provider(r#"issuer = "http://[::1]:4444""#).is_ok());

        let error = load_provider(r#"issuer = "http://idp.example.com""#).unwrap_err();
        assert!(error.to_string().contains("must use https"), "got: {error}");

        let error = load_provider(r#"issuer = "https://idp.example.com/?a=b""#).unwrap_err();
        assert!(error.to_string().contains("query or fragment"), "got: {error}");

        let error = load_provider("kind = \"google\"\nissuer = \"https://idp.example.com\"").unwrap_err();
        assert!(error.to_string().contains("issuer is not used by kind"), "got: {error}");

        let error = load_provider(r#"kind = "forseti""#).unwrap_err();
        assert!(error.to_string().contains("issuer is required for kind"), "got: {error}");
    }

    #[test]
    fn oidc_kind_specific_fields() {
        let error = load_provider(r#"portal_url = "https://accounts.example.com""#).unwrap_err();
        assert!(error.to_string().contains("portal_url is only used by kind"), "got: {error}");
        assert!(
            load_provider(
                "kind = \"forseti\"\nissuer = \"https://idp.example.com\"\nportal_url = \"https://accounts.example.com\""
            )
            .is_ok()
        );

        let error = load_provider(r#"tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47""#).unwrap_err();
        assert!(error.to_string().contains("tenant_id is only used by kind"), "got: {error}");

        let (_dir, path) = temp_config(
            "liwan-microsoft.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.entra]
                kind = "microsoft"
                client_id = "liwan"
                client_secret = "shhh"
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("tenant_id is required"), "got: {error}");

        let (_dir, path) = temp_config(
            "liwan-microsoft-bad-tenant.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.entra]
                kind = "microsoft"
                client_id = "liwan"
                client_secret = "shhh"
                tenant_id = "common"
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("must be a UUID"), "got: {error}");
    }

    #[test]
    fn oidc_allowed_domains_need_the_email_scope() {
        let error =
            load_provider("allowed_domains = [\"example.com\"]\nscopes = [\"openid\", \"profile\"]").unwrap_err();
        assert!(error.to_string().contains("needs the \"email\" scope"), "got: {error}");
        assert!(load_provider("allowed_domains = [\"example.com\"]").is_ok(), "the default scopes include email");
    }

    #[test]
    fn oidc_scopes_are_only_configurable_for_plain_oidc() {
        let error = load_provider("kind = \"forseti\"\nissuer = \"https://idp.example.com\"\nscopes = [\"openid\"]")
            .unwrap_err();
        assert!(error.to_string().contains("scopes is only used by kind"), "got: {error}");
    }

    #[test]
    fn oidc_rejects_the_flat_table() {
        let (_dir, path) = temp_config(
            "liwan-legacy.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("oidc.providers.<name>.issuer"), "got: {error}");
    }

    #[test]
    fn oidc_rejects_the_flat_env_vars() {
        // The 1.6.0-fork README told people to keep the secret in the
        // environment, so this is the upgrade path most instances hit first.
        for (key, replacement) in [
            ("LIWAN_OIDC_ISSUER", "oidc.providers.<name>.issuer"),
            ("LIWAN_OIDC_CLIENT_ID", "oidc.providers.<name>.client_id"),
            ("LIWAN_OIDC_CLIENT_SECRET", "oidc.providers.<name>.client_secret"),
            ("LIWAN_OIDC_BUTTON_LABEL", "oidc.providers.<name>.display_name"),
            ("LIWAN_OIDC_REGISTRATION", "oidc.providers.<name>.registration"),
            ("LIWAN_OIDC_ALLOWED_DOMAINS", "oidc.providers.<name>.allowed_domains"),
        ] {
            let error = Config::load(None, vec![(key, "value")]).unwrap_err();
            assert!(error.to_string().contains(replacement), "{key} got: {error}");
        }

        // A provider key that merely starts the same way is not a legacy key.
        assert!(Config::load(None, Vec::<(String, String)>::new()).is_ok());
    }

    fn assert_names_the_teams_replacement(error: &anyhow::Error) {
        let message = error.to_string();
        assert!(message.contains("groups.teams"), "got: {message}");
        assert!(message.contains("default_team"), "got: {message}");
        assert!(message.contains("Teams must exist first"), "got: {message}");
        assert!(message.contains("Upgrading from 1.7.0-fork"), "got: {message}");
    }

    #[test]
    fn groups_projects_is_rejected_from_the_file() {
        let (_dir, path) = temp_config(
            "liwan-groups-projects.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.my-idp]
                issuer = "https://idp.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                [oidc.providers.my-idp.groups]
                projects = { marketing = ["blog"] }
            "#,
        );
        let error = Config::load(Some(path), Vec::<(String, String)>::new()).unwrap_err();
        assert!(error.to_string().contains("oidc.providers.my-idp.groups.projects"), "got: {error}");
        assert_names_the_teams_replacement(&error);
    }

    #[test]
    fn groups_projects_is_rejected_from_the_env() {
        let error = Config::load(None, vec![("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_PROJECTS", "blog")]).unwrap_err();
        assert!(error.to_string().contains("oidc.providers.company.groups.projects"), "got: {error}");
        assert_names_the_teams_replacement(&error);
    }

    #[test]
    fn groups_team_ids_are_validated() {
        for bad in ["", "a/b", "a".repeat(65).as_str(), "bad id"] {
            let error = load_provider(&format!("[oidc.providers.company.groups]\ndefault_team = {bad:?}")).unwrap_err();
            assert!(error.to_string().contains("default_team"), "{bad:?} got: {error}");

            let error =
                load_provider(&format!("[oidc.providers.company.groups]\nteams = {{ eng = [{bad:?}] }}")).unwrap_err();
            assert!(error.to_string().contains("groups.teams.eng"), "{bad:?} got: {error}");
        }

        let error = load_provider("[oidc.providers.company.groups]\nteams = { \"\" = [\"eng\"] }").unwrap_err();
        assert!(error.to_string().contains("group names cannot be empty"), "got: {error}");

        let id = "aB3dE5gH7jK9mN1p";
        let config = load_provider(&format!(
            "scopes = [\"openid\", \"email\", \"groups\"]\n[oidc.providers.company.groups]\ndefault_team = {id:?}\nteams = {{ eng = [{id:?}] }}"
        ))
        .unwrap();
        let groups = config.oidc.get("company").unwrap().groups.as_ref().unwrap();
        assert_eq!(groups.default_team.as_deref(), Some(id));
        assert_eq!(groups.teams["eng"], vec![id.to_string()]);
    }

    #[test]
    fn groups_default_team_maps_from_the_env() {
        assert_eq!(
            map_env_key("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_DEFAULT_TEAM").as_deref(),
            Some("oidc.providers.company.groups.default_team")
        );

        let (_dir, path) = temp_config(
            "liwan-default-team-env.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc.providers.company]
                issuer = "https://idp.example.com"
                client_id = "liwan"
                client_secret = "shhh"
            "#,
        );
        let config =
            Config::load(Some(path), vec![("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_DEFAULT_TEAM", "0042")]).unwrap();
        let groups = config.oidc.get("company").unwrap().groups.as_ref().expect("groups table from the env");
        assert_eq!(groups.default_team.as_deref(), Some("0042"), "an all-digit id stays a string");
    }

    #[test]
    fn groups_claim_cannot_be_an_overage_marker() {
        for claim in ["hasgroups", "_claim_names"] {
            let error = load_provider(&format!("[oidc.providers.company.groups]\nclaim = {claim:?}")).unwrap_err();
            assert!(error.to_string().contains("is reserved"), "{claim} got: {error}");
        }
        assert!(load_provider("[oidc.providers.company.groups]\nclaim = \"roles\"").is_ok());
    }

    #[test]
    fn oidc_rejects_domain_allowlist_registration() {
        let error = load_provider(r#"registration = "domain_allowlist""#).unwrap_err();
        assert!(error.to_string().contains("no longer a mode"), "got: {error}");
        assert!(error.to_string().contains("allowed_domains"), "got: {error}");
    }

    fn load_two_providers(first: &str, second: &str) -> Result<Config> {
        let content = format!(
            r#"
                base_url = "https://example.com"
                [oidc.providers.first]
                client_id = "liwan"
                client_secret = "shhh"
                {first}
                [oidc.providers.second]
                client_id = "liwan"
                client_secret = "shhh"
                {second}
            "#
        );
        let (_dir, path) = temp_config("liwan-two-issuers.config.toml", &content);
        Config::load(Some(path), Vec::<(String, String)>::new())
    }

    #[test]
    fn oidc_rejects_a_duplicate_issuer() {
        let issuer = r#"issuer = "https://idp.example.com""#;
        let error = load_two_providers(issuer, issuer).unwrap_err().to_string();
        assert!(error.contains("oidc.providers.first and oidc.providers.second"), "got: {error}");
        assert!(error.contains("https://idp.example.com"), "got: {error}");
        assert!(error.contains("each issuer can be configured once"), "got: {error}");

        let google = r#"kind = "google""#;
        let error = load_two_providers(google, google).unwrap_err().to_string();
        assert!(error.contains("https://accounts.google.com"), "got: {error}");

        assert!(load_two_providers(issuer, r#"issuer = "https://idp.partner.example""#).is_ok());
        assert!(load_two_providers(issuer, google).is_ok());
    }

    #[test]
    fn oidc_rejects_unknown_keys() {
        let error = load_provider(r#"alowed_domains = ["example.com"]"#).unwrap_err();
        assert!(error.to_string().contains("`alowed_domains`"), "got: {error}");

        let error = load_provider("[oidc.providers.company.groups]\nalowed = [\"analytics\"]").unwrap_err();
        assert!(error.to_string().contains("`alowed`"), "got: {error}");

        let error = load_provider("[oidc.providers.company.group]\nallowed = [\"analytics\"]").unwrap_err();
        assert!(error.to_string().contains("`group`"), "got: {error}");
    }

    #[test]
    fn oidc_rejects_an_empty_allow_list_from_the_env() {
        let cases = [
            ("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_ALLOWED", ""),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_GROUPS_ALLOWED", " , ,"),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_ALLOWED_DOMAINS", ""),
            ("LIWAN_OIDC_PROVIDERS_COMPANY_ALLOWED_DOMAINS", ", ."),
        ];
        for (key, value) in cases {
            let error = Config::load(None, vec![(key, value)]).unwrap_err();
            assert!(error.to_string().contains(key), "{key}={value:?} got: {error}");
        }

        let config = load_provider("[oidc.providers.company.groups]\nallowed = []").unwrap();
        assert!(config.oidc.get("company").unwrap().groups.as_ref().unwrap().allowed.is_empty());
    }

    #[test]
    fn effective_scopes_per_kind() {
        let openid_email_profile = vec!["openid".to_string(), "email".to_string(), "profile".to_string()];

        let oidc = ProviderConfig { scopes: vec!["openid".to_string(), "groups".to_string()], ..Default::default() };
        assert_eq!(oidc.effective_scopes(), vec!["openid".to_string(), "groups".to_string()]);

        let forseti = ProviderConfig { kind: ProviderKind::Forseti, ..Default::default() };
        assert_eq!(forseti.effective_scopes(), openid_email_profile);

        let forseti_groups =
            ProviderConfig { kind: ProviderKind::Forseti, groups: Some(GroupsConfig::default()), ..Default::default() };
        assert_eq!(
            forseti_groups.effective_scopes(),
            vec!["openid".to_string(), "email".to_string(), "profile".to_string(), "groups".to_string()]
        );

        let google =
            ProviderConfig { kind: ProviderKind::Google, scopes: vec!["openid".to_string()], ..Default::default() };
        assert_eq!(google.effective_scopes(), openid_email_profile, "presets ignore configured scopes");
    }

    #[test]
    fn issuer_url_per_kind() {
        let forseti = ProviderConfig {
            kind: ProviderKind::Forseti,
            issuer: Some("https://accounts.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(forseti.issuer_url().unwrap(), "https://accounts.example.com");
        assert_eq!(forseti.portal_url().as_deref(), Some("https://accounts.example.com"));

        let google = ProviderConfig { kind: ProviderKind::Google, ..Default::default() };
        assert_eq!(google.issuer_url().unwrap(), "https://accounts.google.com");

        let microsoft = ProviderConfig {
            kind: ProviderKind::Microsoft,
            tenant_id: Some("72F988BF-86F1-41AF-91AB-2D7CD011DB47".to_string()),
            ..Default::default()
        };
        assert_eq!(
            microsoft.issuer_url().unwrap(),
            "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        );
    }

    #[test]
    fn oidc_is_empty_by_default() {
        let config = Config::load(None, Vec::<(String, String)>::new()).expect("failed to load config");
        assert!(config.oidc.providers.is_empty());
        assert!(config.oidc.only().is_none());
    }

    #[test]
    fn redirect_uri_honours_the_base_path() {
        let config = Config { base_url: "https://example.com/analytics".to_string(), ..Default::default() };
        assert_eq!(
            config.external_auth_redirect_uri().unwrap().as_str(),
            "https://example.com/analytics/api/dashboard/auth/external/callback"
        );
    }
}
