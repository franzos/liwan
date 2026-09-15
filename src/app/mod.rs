mod core;
mod db;

#[cfg(feature = "import")]
pub mod import;
pub mod models;
pub use core::reports;
pub use core::{
    ExternalAccount, ExternalAuthError, ExternalAuthLogin, ExternalAuthStart, LinkOutcome, LiwanExternalAuth,
    MAX_LOGOUT_BODY, MAX_WEBHOOK_BODY, Rejection, SET_CONTENT_TYPE, WebhookError, email_domain,
};
use std::sync::Arc;

use crate::{config::Config, utils::writable::check_directory_writable};

use crate::utils::r2d2_sqlite::SqliteConnectionManager;
use anyhow::{Context, Result};
pub use core::PasswordUpdateOutcome;
use core::{
    LiwanEntities, LiwanEvents, LiwanOnboarding, LiwanProjectSettings, LiwanProjects, LiwanSessions, LiwanSettings,
    LiwanUsers,
};
use duckdb::DuckdbConnectionManager;
use models::{DisplayOverride, GeoDetail};
use reports::{Dimension, Metric};

pub type DuckDBConn = r2d2::PooledConnection<DuckdbConnectionManager>;
pub type DuckDBPool = r2d2::Pool<DuckdbConnectionManager>;
pub type SqlitePool = r2d2::Pool<SqliteConnectionManager>;
#[cfg(feature = "import")]
pub use core::IMPORTED_VISITOR_PREFIX;
pub use core::PruneStats;

pub struct Liwan {
    events_pool: r2d2::Pool<DuckdbConnectionManager>,

    pub events: LiwanEvents,
    pub users: LiwanUsers,
    pub sessions: LiwanSessions,
    pub external_auth: LiwanExternalAuth,
    pub onboarding: LiwanOnboarding,
    pub entities: LiwanEntities,
    pub projects: LiwanProjects,
    pub settings: LiwanSettings,
    pub project_settings: LiwanProjectSettings,

    #[cfg(feature = "geoip")]
    pub geoip: Arc<core::LiwanGeoIP>,

    pub config: Config,
}

#[rustfmt::skip]
mod embedded {
    pub(super) mod app { refinery::embed_migrations!("src/migrations/app"); }
    pub(super) mod events { refinery::embed_migrations!("src/migrations/events"); }
}

impl Liwan {
    pub fn try_new(config: Config) -> Result<Arc<Self>> {
        tracing::debug!("Initializing app");
        let dir = std::path::Path::new(&config.data_dir);

        if !dir.exists() {
            tracing::debug!(path = config.data_dir, "Creating data directory since it doesn't exist");
            std::fs::create_dir_all(dir).context("Failed to create data directory")?;
        }
        check_directory_writable(dir);

        tracing::debug!("Initializing databases");
        let conn_app = db::init_sqlite(&dir.join("liwan-app.sqlite"), embedded::app::migrations::runner())?;
        let conn_events = db::init_duckdb(
            &dir.join("liwan-events.duckdb"),
            config.duckdb.clone(),
            embedded::events::migrations::runner(),
        )?;

        Ok(Self {
            #[cfg(feature = "geoip")]
            geoip: core::LiwanGeoIP::try_new(config.clone())?.into(),

            events: LiwanEvents::try_new(conn_events.clone(), conn_app.clone(), config.visitor_group_rotation_hour)?,
            onboarding: LiwanOnboarding::try_new(&conn_app)?,
            sessions: LiwanSessions::new(conn_app.clone()),
            external_auth: LiwanExternalAuth::try_new(conn_app.clone(), &config)?,
            entities: LiwanEntities::new(conn_app.clone()),
            projects: LiwanProjects::new(conn_app.clone()),
            settings: LiwanSettings::try_new(conn_app.clone())?,
            project_settings: LiwanProjectSettings::new(conn_app.clone()),
            users: LiwanUsers::new(conn_app),

            events_pool: conn_events,
            config,
        }
        .into())
    }

    pub fn new_memory(config: Config) -> Result<Arc<Self>> {
        tracing::debug!("Initializing app in memory");
        let conn_app = db::init_sqlite_mem(embedded::app::migrations::runner())?;
        let conn_events = db::init_duckdb_mem(embedded::events::migrations::runner())?;

        Ok(Self {
            #[cfg(feature = "geoip")]
            geoip: core::LiwanGeoIP::try_new(config.clone())?.into(),

            events: LiwanEvents::try_new(conn_events.clone(), conn_app.clone(), config.visitor_group_rotation_hour)?,
            onboarding: LiwanOnboarding::try_new(&conn_app)?,
            sessions: LiwanSessions::new(conn_app.clone()),
            external_auth: LiwanExternalAuth::try_new(conn_app.clone(), &config)?,
            entities: LiwanEntities::new(conn_app.clone()),
            projects: LiwanProjects::new(conn_app.clone()),
            settings: LiwanSettings::try_new(conn_app.clone())?,
            project_settings: LiwanProjectSettings::new(conn_app.clone()),
            users: LiwanUsers::new(conn_app),

            events_pool: conn_events,
            config,
        }
        .into())
    }

    pub fn events_conn(&self) -> Result<DuckDBConn> {
        Ok(self.events_pool.get()?)
    }

    pub fn run_background_tasks(&self) {
        if !self.config.disable_ntp_check {
            tokio::task::spawn(async {
                if let Ok(result) = rsntp::AsyncSntpClient::new().synchronize("pool.ntp.org").await {
                    let offset_seconds = result.clock_offset().as_secs_f64();
                    if offset_seconds.abs() >= 5.0 * 60.0 {
                        tracing::warn!(
                            offset_seconds,
                            "System clock is not synchronized; analytics timestamps may be inaccurate"
                        );
                    }
                }
            });
        }
        #[cfg(feature = "geoip")]
        tokio::task::spawn(core::keep_updated(self.geoip.clone()));
    }

    pub fn shutdown(&self) -> Result<()> {
        self.events_pool.get()?.execute("FORCE CHECKPOINT", [])?; // normal checkpoints don't seem to work consistently on shutdown
        tracing::info!("Shutting down");
        Ok(())
    }

    pub fn is_metric_hidden(&self, project_id: &str, entities: &[String], metric: Metric) -> bool {
        match self
            .project_settings
            .get(project_id)
            .ok()
            .and_then(|settings| settings.metric_display_overrides.get(&metric.to_string()).copied())
            .unwrap_or(DisplayOverride::Auto)
        {
            DisplayOverride::Show => false,
            DisplayOverride::Hide => true,
            DisplayOverride::Auto => match metric {
                Metric::Views | Metric::UniqueVisitors => false,
                Metric::BounceRate | Metric::AvgTimeOnSite => {
                    entities.iter().any(|entity_id| !self.settings.resolved_for_entity(entity_id).track_sessions)
                }
            },
        }
    }

    pub fn is_dimension_hidden(&self, project_id: &str, entities: &[String], dimension: Dimension) -> bool {
        match self
            .project_settings
            .get(project_id)
            .ok()
            .and_then(|settings| settings.dimension_display_overrides.get(&dimension.to_string()).copied())
            .unwrap_or(DisplayOverride::Auto)
        {
            DisplayOverride::Show => false,
            DisplayOverride::Hide => true,
            DisplayOverride::Auto => match dimension {
                Dimension::UrlEntry | Dimension::UrlExit => {
                    entities.iter().any(|entity_id| !self.settings.resolved_for_entity(entity_id).track_sessions)
                }
                Dimension::Country => entities
                    .iter()
                    .any(|entity_id| self.settings.resolved_for_entity(entity_id).track_geo == GeoDetail::None),
                Dimension::City => entities
                    .iter()
                    .any(|entity_id| self.settings.resolved_for_entity(entity_id).track_geo != GeoDetail::City),
                Dimension::UtmSource
                | Dimension::UtmMedium
                | Dimension::UtmCampaign
                | Dimension::UtmContent
                | Dimension::UtmTerm => {
                    entities.iter().any(|entity_id| !self.settings.resolved_for_entity(entity_id).track_utm_params)
                }
                _ => false,
            },
        }
    }
}

#[cfg(any(debug_assertions, test))]
impl Liwan {
    pub fn seed_database(&self, count_per_entity: usize) -> Result<()> {
        use chrono::{Days, Utc};
        use models::UserRole;

        let entities = vec![
            (
                "entity-1",
                "Entity 1",
                "example.com",
                vec!["public-project".to_string(), "private-project".to_string(), "clients".to_string()],
            ),
            ("entity-2", "Entity 2", "test.example.com", vec!["clients".to_string()]),
            ("entity-3", "Entity 3", "example.org", vec!["clients".to_string()]),
        ];
        let projects = [
            ("public-project", "Public Project", true),
            ("private-project", "Private Project", false),
            ("clients", "Clients", true),
        ];
        let users = [("admin", "admin", UserRole::Admin), ("user", "user", UserRole::User)];

        for (username, password, role) in users {
            self.users.create(username, password, role, &[])?;
        }

        for (project_id, display_name, public) in projects {
            self.projects.create(
                &models::Project {
                    id: project_id.to_string(),
                    display_name: display_name.to_string(),
                    public,
                    unlisted: false,
                    secret: None,
                },
                &[],
            )?;
        }

        let start = Utc::now().checked_sub_days(Days::new(365)).unwrap();
        let end = Utc::now();
        for (entity_id, display_name, fqdn, project_ids) in entities {
            self.entities.create(
                &models::Entity { id: entity_id.to_string(), display_name: display_name.to_string() },
                &project_ids,
            )?;
            let events = crate::utils::seed::random_events((start, end), entity_id, fqdn, count_per_entity);
            let now = std::time::Instant::now();
            self.events.append(events)?;

            // Seed a couple of custom events so the Events card has data in dev/tests.
            if entity_id == "entity-1" {
                for name in ["signup", "scroll-50%"] {
                    let custom = crate::utils::seed::random_custom_events(
                        (start, end),
                        entity_id,
                        fqdn,
                        name,
                        count_per_entity / 10,
                    );
                    self.events.append(custom)?;
                }
            }
            tracing::info!("Seeded entity {} in {:?}", entity_id, now.elapsed());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{r2d2_sqlite::SqliteConnectionManager, refinery_sqlite::RqlConnection};

    /// `V6` carries the fork's `users.oidc_issuer`/`oidc_subject` links over to
    /// `external_identities` before the old table is dropped, so an upgrade does
    /// not force a re-enrolment.
    #[test]
    fn migration_v6_converts_fork_identities() {
        let pool = r2d2::Pool::new(SqliteConnectionManager::memory()).unwrap();
        let mut runner = embedded::app::migrations::runner();
        runner.set_migration_table_name("migrations");
        runner.set_target(refinery::Target::Version(5)).run(&mut RqlConnection(pool.get().unwrap())).unwrap();

        {
            let conn = pool.get().unwrap();
            conn.execute(
                "insert into users (username, password_hash, role, projects, auth) values ('bob', 'hash', 'admin', 'p1', 'password')",
                [],
            )
            .unwrap();
            conn.execute(
                "insert into users (username, password_hash, role, projects, email, oidc_issuer, oidc_subject, auth)
                 values ('alice', null, 'user', '', 'a@b.com', 'https://idp.example.com', 'sub-1', 'oidc')",
                [],
            )
            .unwrap();
            for (id, username) in [("s-bob", "bob"), ("s-alice", "alice")] {
                conn.execute(
                    "insert into sessions (id, username, expires_at) values (?, ?, ?)",
                    rusqlite::params![id, username, chrono::Utc::now() + chrono::Duration::hours(1)],
                )
                .unwrap();
            }
        }

        let mut runner = embedded::app::migrations::runner();
        runner.set_migration_table_name("migrations");
        runner.run(&mut RqlConnection(pool.get().unwrap())).unwrap();

        let conn = pool.get().unwrap();
        let identity: (String, String, String) = conn
            .query_row("select provider_key, subject, username from external_identities", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(identity, ("https://idp.example.com".to_string(), "sub-1".to_string(), "alice".to_string()));

        let columns: Vec<String> = conn
            .prepare("select name from pragma_table_info('users')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(columns, vec!["username", "password_hash", "role", "projects"]);

        assert!(
            !conn.prepare("select 1 from sqlite_master where name = 'oidc_auth_state'").unwrap().exists([]).unwrap()
        );
        let sessions: u32 = conn.query_row("select count(*) from sessions", [], |row| row.get(0)).unwrap();
        assert_eq!(sessions, 2);
    }
}
