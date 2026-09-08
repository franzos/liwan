use crate::utils::ip_headers::{TrustedHeader, TrustedProxy, deserialize_trusted_headers, deserialize_trusted_proxies};
use anyhow::{Context, Result, bail};
use config::{File, FileFormat, Value};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_base")]
    pub base_url: String,

    #[serde(default)]
    listen: Option<ListenAddr>,

    #[serde(default)]
    port: Option<ListenAddr>,

    #[serde(default)]
    // don't load favicons from the duckduckgo api
    pub disable_favicons: bool,

    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    #[serde(default)]
    pub geoip: GeoIpConfig,

    #[serde(default)]
    pub duckdb: DuckdbConfig,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub oidc: OidcConfig,

    #[serde(default = "default_trusted_headers", deserialize_with = "deserialize_trusted_headers")]
    pub trusted_headers: Vec<TrustedHeader>,

    #[serde(default, deserialize_with = "deserialize_trusted_proxies")]
    pub trusted_proxies: Vec<TrustedProxy>,

    #[serde(default = "default_use_forward_headers")]
    pub use_forward_headers: bool,

    #[serde(default = "default_visitor_group_rotation_hour")]
    pub visitor_group_rotation_hour: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: default_base(),
            data_dir: default_data_dir(),
            geoip: Default::default(),
            duckdb: Default::default(),
            rate_limit: Default::default(),
            oidc: Default::default(),
            disable_favicons: false,
            listen: None,
            port: None,
            trusted_headers: default_trusted_headers(),
            trusted_proxies: Vec::new(),
            use_forward_headers: default_use_forward_headers(),
            visitor_group_rotation_hour: default_visitor_group_rotation_hour(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub maxmind_db_path: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_from_number")]
    pub maxmind_account_id: Option<String>,
    #[serde(default)]
    pub maxmind_license_key: Option<String>,
    #[serde(default = "default_maxmind_edition")]
    pub maxmind_edition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub button_label: Option<String>,
    #[serde(default)]
    pub registration: OidcRegistration,
    #[serde(default, deserialize_with = "deserialize_allowed_domains")]
    pub allowed_domains: Vec<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            client_id: None,
            client_secret: None,
            scopes: default_oidc_scopes(),
            button_label: None,
            registration: OidcRegistration::default(),
            allowed_domains: Vec::new(),
        }
    }
}

/// Who may have a local account auto-provisioned on first OIDC login.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OidcRegistration {
    /// Any user the IdP authenticates gets an account (today's behavior).
    #[default]
    Open,
    /// No new accounts; only users who already exist can log in.
    Closed,
    /// New accounts only for verified emails in `allowed_domains`.
    DomainAllowlist,
}

/// Accepts a TOML array or a comma-separated env string (mirrors
/// `deserialize_trusted_headers`); required because `parse_env_value` only emits
/// scalars, so a plain `Vec<String>` can't be set via `LIWAN_OIDC_ALLOWED_DOMAINS`.
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

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
}

impl OidcConfig {
    /// OIDC is active only when issuer, client_id, and client_secret are all set.
    pub fn enabled(&self) -> bool {
        self.issuer.is_some() && self.client_id.is_some() && self.client_secret.is_some()
    }

    /// Derived from base_url; never configured directly.
    pub fn redirect_uri(&self, base_url: &str) -> String {
        format!("{}/api/dashboard/auth/oidc/callback", base_url.trim_end_matches('/'))
    }
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
pub struct DuckdbConfig {
    #[serde(default)]
    pub memory_limit: Option<String>,
    #[serde(default)]
    pub threads: Option<NonZeroU16>,
}

fn default_base() -> String {
    "http://localhost:9042".to_string()
}

fn default_port() -> u16 {
    9042
}

fn default_listen() -> ListenAddr {
    ListenAddr::Port(default_port())
}

fn default_maxmind_edition() -> String {
    "GeoLite2-City".to_string()
}

fn default_data_dir() -> String {
    if cfg!(target_family = "unix") {
        let home = std::env::var("HOME").ok().unwrap_or_else(|| "/root".to_string());
        std::env::var("XDG_DATA_HOME")
            .map_or_else(|_| format!("{home}/.local/share/liwan/data"), |data_home| format!("{data_home}/liwan/data"))
    } else {
        "./liwan-data".to_string()
    }
}

fn default_trusted_headers() -> Vec<TrustedHeader> {
    TrustedHeader::all().to_vec()
}

fn default_use_forward_headers() -> bool {
    true
}

fn default_visitor_group_rotation_hour() -> u8 {
    4
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

pub fn deserialize_string_from_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i64),
        Float(f64),
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => Ok(Some(s)),
        StringOrNumber::Number(i) => Ok(Some(i.to_string())),
        StringOrNumber::Float(f) => Ok(Some(f.to_string())),
    }
}

pub static DEFAULT_CONFIG: &str = include_str!("../data/config.example.toml");

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
                builder = builder.set_override(&mapped_key, parse_env_value(value.as_ref()))?;
            };
        }

        let config: Self = builder.build()?.try_deserialize()?;

        let base_url: Url = Url::from_str(&config.base_url).context("Invalid base URL")?;
        if !["http", "https"].contains(&base_url.scheme()) {
            bail!("Invalid base URL: protocol must be either http or https");
        }
        if base_url.scheme() != "https" {
            if config.oidc.enabled() {
                tracing::warn!(
                    "Base URL is not using HTTPS; the session and OIDC state cookies are sent without the Secure flag"
                );
            } else {
                tracing::warn!("Base URL is not using HTTPS");
            }
        }
        if config.oidc.enabled() {
            let issuer = config.oidc.issuer.as_deref().expect("checked by enabled()");
            let issuer_url = Url::from_str(issuer).context("Invalid oidc.issuer")?;
            if !is_https_or_loopback(&issuer_url) {
                bail!(
                    "Invalid oidc.issuer: must use https (the client secret, authorization code and ID token travel over it); http is allowed only for localhost"
                );
            }
        }
        if config.listen.is_some() && config.port.is_some() {
            tracing::warn!(
                "Both `listen` and `port` configuration options are set. The `listen` option will take precedence over `port`."
            );
        }
        if config.visitor_group_rotation_hour > 23 {
            bail!("Invalid visitor_group_rotation_hour: must be between 0 and 23");
        }
        // A zero period or burst is rejected by the governor builder, which would
        // panic well after boot. Catch it here instead.
        if config.rate_limit.auth_period_seconds == 0 || config.rate_limit.event_period_ms == 0 {
            bail!("Invalid rate_limit: auth_period_seconds and event_period_ms must be greater than 0");
        }
        if config.rate_limit.auth_burst == 0 || config.rate_limit.event_burst == 0 {
            bail!("Invalid rate_limit: auth_burst and event_burst must be greater than 0");
        }
        if config.use_forward_headers && config.trusted_proxies.is_empty() {
            tracing::warn!(
                "use_forward_headers is on but trusted_proxies is empty; the rate limiter keys on the TCP peer, so every client behind a proxy shares one bucket. List your proxies in trusted_proxies."
            );
        }
        if config.oidc.registration == OidcRegistration::DomainAllowlist {
            if config.oidc.allowed_domains.is_empty() {
                bail!("oidc.registration = \"domain_allowlist\" requires a non-empty oidc.allowed_domains");
            }
            if !config.oidc.scopes.iter().any(|s| s == "email") {
                bail!(
                    "oidc.registration = \"domain_allowlist\" requires the \"email\" scope in oidc.scopes to read the verified email"
                );
            }
        } else if !config.oidc.allowed_domains.is_empty() {
            tracing::warn!(
                "oidc.allowed_domains is set but oidc.registration is not \"domain_allowlist\"; the list is ignored"
            );
        }

        Ok(config)
    }

    pub fn listen_addr(&self) -> String {
        self.listen.as_ref().or(self.port.as_ref()).unwrap_or(&default_listen()).addr()
    }

    pub fn secure(&self) -> bool {
        self.base_url.starts_with("https")
    }
}

/// Plain http is tolerated only against a loopback host, so local development
/// against an IdP on `http://localhost` keeps working.
fn is_https_or_loopback(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn map_env_key(key: &str) -> Option<String> {
    let key = key.strip_prefix("LIWAN_")?.to_ascii_lowercase();
    const NESTED_PREFIXES: &[(&str, &str)] =
        &[("maxmind_", "geoip.maxmind_"), ("duckdb_", "duckdb."), ("oidc_", "oidc."), ("rate_limit_", "rate_limit.")];

    for (prefix, mapped_prefix) in NESTED_PREFIXES {
        if let Some(rest) = key.strip_prefix(prefix) {
            return Some(format!("{mapped_prefix}{rest}"));
        }
    }

    Some(key)
}

fn parse_env_value(value: &str) -> Value {
    if let Ok(parsed) = value.parse::<bool>() {
        Value::from(parsed)
    } else if let Ok(parsed) = value.parse::<i64>() {
        Value::from(parsed)
    } else if let Ok(parsed) = value.parse::<f64>() {
        Value::from(parsed)
    } else {
        Value::from(value.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::ip_headers::{TrustedHeader, TrustedProxy};
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
            ("LIWAN_MAXMIND_LICENSE_KEY", "test"),
            ("LIWAN_MAXMIND_ACCOUNT_ID", "test"),
            ("LIWAN_MAXMIND_DB_PATH", "test"),
        ];

        let config = Config::load(Some(config_path), env).expect("failed to load config");

        assert_eq!(config.geoip.maxmind_edition, "test".to_string());
        assert_eq!(config.geoip.maxmind_license_key, Some("test".to_string()));
        assert_eq!(config.geoip.maxmind_account_id, Some("test".to_string()));
        assert_eq!(config.geoip.maxmind_db_path, Some("test".to_string()));
        assert_eq!(config.base_url, "http://localhost:8081");
        assert_eq!(config.data_dir, "./liwan-test-data");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
        assert_eq!(config.duckdb.memory_limit, Some("2GB".to_string()));
        assert_eq!(config.duckdb.threads, Some(NonZeroU16::new(4).unwrap()));
    }

    #[test]
    fn test_no_geoip() {
        let (_temp_dir, config_path) = temp_config(
            "liwan3.config.toml",
            r#"
                base_url = "http://localhost:8081"
                data_dir = "./liwan-test-data"
            "#,
        );

        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");

        assert!(config.geoip.maxmind_db_path.is_none());
        assert!(config.geoip.maxmind_account_id.is_none());
        assert!(config.geoip.maxmind_license_key.is_none());
        assert_eq!(config.base_url, "http://localhost:8081");
        assert_eq!(config.data_dir, "./liwan-test-data");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
    }

    #[test]
    fn test_default_geoip() {
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
        assert_eq!(config.geoip.maxmind_edition, default_maxmind_edition());
        assert_eq!(config.geoip.maxmind_db_path, Some("test2".to_string()));
        assert_eq!(config.base_url, "http://localhost:8081");
        assert_eq!(config.data_dir, "./liwan-test-data");
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
        assert_eq!(config.geoip.maxmind_account_id, Some("123".to_string()));
        assert_eq!(config.trusted_headers, vec![TrustedHeader::XForwardedFor, TrustedHeader::Forwarded]);
        assert_eq!(
            config.trusted_proxies,
            vec![TrustedProxy::Ip("127.0.0.1".parse().unwrap()), TrustedProxy::Cidr("10.0.0.0/8".parse().unwrap())]
        );
        assert!(config.use_forward_headers);
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
        assert_eq!(config.trusted_headers, vec![TrustedHeader::Other("x-client-ip".to_string())]);
    }

    #[test]
    fn test_oidc_config() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-oidc.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
            "#,
        );
        let env = vec![("LIWAN_OIDC_CLIENT_SECRET", "shhh")];
        let config = Config::load(Some(config_path), env).expect("failed to load config");
        assert!(config.oidc.enabled());
        assert_eq!(config.oidc.issuer.as_deref(), Some("https://accounts.example.com"));
        assert_eq!(config.oidc.client_secret.as_deref(), Some("shhh"));
        assert_eq!(config.oidc.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(
            config.oidc.redirect_uri("https://example.com"),
            "https://example.com/api/dashboard/auth/oidc/callback"
        );
    }

    fn oidc_config_with_issuer(issuer: &str) -> Result<Config> {
        Config::load(
            None,
            vec![
                ("LIWAN_OIDC_ISSUER", issuer),
                ("LIWAN_OIDC_CLIENT_ID", "liwan"),
                ("LIWAN_OIDC_CLIENT_SECRET", "shhh"),
            ],
        )
    }

    #[test]
    fn test_oidc_issuer_rejects_plain_http() {
        let err = oidc_config_with_issuer("http://idp.example").unwrap_err();
        assert!(err.to_string().contains("oidc.issuer"), "got: {err}");
    }

    #[test]
    fn test_oidc_issuer_allows_localhost_http() {
        assert!(oidc_config_with_issuer("http://localhost:4444").is_ok());
    }

    #[test]
    fn test_oidc_issuer_allows_loopback_ip_http() {
        assert!(oidc_config_with_issuer("http://127.0.0.1:4444").is_ok());
        assert!(oidc_config_with_issuer("http://[::1]:4444").is_ok());
    }

    #[test]
    fn test_oidc_issuer_allows_https() {
        assert!(oidc_config_with_issuer("https://accounts.example.com").is_ok());
    }

    #[test]
    fn test_oidc_disabled_by_default() {
        let config = Config::load(None, Vec::<(String, String)>::new()).expect("failed to load config");
        assert!(!config.oidc.enabled());
        assert_eq!(config.oidc.registration, OidcRegistration::Open);
        assert!(config.oidc.allowed_domains.is_empty());
    }

    #[test]
    fn test_oidc_allowed_domains_toml_normalized() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-allowlist.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                registration = "domain_allowlist"
                allowed_domains = [" Example.COM", "acme.org.", ""]
            "#,
        );
        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(config.oidc.registration, OidcRegistration::DomainAllowlist);
        assert_eq!(config.oidc.allowed_domains, vec!["example.com".to_string(), "acme.org".to_string()]);
    }

    #[test]
    fn test_oidc_allowed_domains_env_comma_separated() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-allowlist-env.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                registration = "domain_allowlist"
            "#,
        );
        let env = vec![("LIWAN_OIDC_ALLOWED_DOMAINS", "example.com,acme.org")];
        let config = Config::load(Some(config_path), env).expect("failed to load config");
        assert_eq!(config.oidc.allowed_domains, vec!["example.com".to_string(), "acme.org".to_string()]);
    }

    #[test]
    fn test_oidc_allowlist_empty_domains_errors() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-allowlist-empty.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                registration = "domain_allowlist"
            "#,
        );
        assert!(Config::load(Some(config_path), Vec::<(String, String)>::new()).is_err());
    }

    #[test]
    fn test_oidc_allowlist_without_email_scope_errors() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-allowlist-noscope.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                registration = "domain_allowlist"
                allowed_domains = ["example.com"]
                scopes = ["openid", "profile"]
            "#,
        );
        assert!(Config::load(Some(config_path), Vec::<(String, String)>::new()).is_err());
    }

    #[test]
    fn test_oidc_allowed_domains_ignored_when_open() {
        let (_temp_dir, config_path) = temp_config(
            "liwan-allowlist-open.config.toml",
            r#"
                base_url = "https://example.com"
                [oidc]
                issuer = "https://accounts.example.com"
                client_id = "liwan"
                client_secret = "shhh"
                allowed_domains = ["example.com"]
            "#,
        );
        let config = Config::load(Some(config_path), Vec::<(String, String)>::new()).expect("failed to load config");
        assert_eq!(config.oidc.registration, OidcRegistration::Open);
        assert_eq!(config.oidc.allowed_domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_no_config() {
        let config = Config::load(None, Vec::<(String, String)>::new()).expect("failed to load config");
        assert!(config.geoip.maxmind_db_path.is_none());
        assert!(config.geoip.maxmind_account_id.is_none());
        assert!(config.geoip.maxmind_license_key.is_none());
        assert_eq!(config.base_url, "http://localhost:9042");
        assert_eq!(config.listen_addr(), "0.0.0.0:9042");
    }
}
