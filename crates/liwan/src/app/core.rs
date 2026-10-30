mod api_keys;
mod entities;
mod events;
mod external_auth;
mod onboarding;
mod projects;
pub mod reports;
mod sessions;
mod settings;
mod teams;
mod users;

pub use api_keys::{ApiKeyAccess, LiwanApiKeys};
pub use entities::LiwanEntities;
#[cfg(feature = "import")]
pub use events::IMPORTED_VISITOR_PREFIX;
pub use events::{LiwanEvents, PruneStats};
pub use external_auth::{
    ExternalAccount, ExternalAuthError, ExternalAuthLogin, ExternalAuthStart, LinkOutcome, LiwanExternalAuth,
    MAX_LOGOUT_BODY, MAX_WEBHOOK_BODY, Rejection, SET_CONTENT_TYPE, WebhookError, email_domain,
};
pub use onboarding::LiwanOnboarding;
pub use projects::LiwanProjects;
pub use sessions::LiwanSessions;
pub use settings::{LiwanProjectSettings, LiwanSettings};
pub use teams::LiwanTeams;
pub use users::{LiwanUsers, PasswordUpdateOutcome};

#[cfg(feature = "geoip")]
mod geoip;

#[cfg(feature = "geoip")]
pub use geoip::{LiwanGeoIP, keep_updated};
