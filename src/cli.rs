use crate::{
    app::{Liwan, models::UserRole},
    config::{Config, DEFAULT_CONFIG, GeoIpConfig},
};
use anyhow::Result;
use argh::FromArgs;

#[derive(FromArgs)]
/// liwan - lightweight web analytics
pub struct Args {
    #[argh(option)]
    /// path to the configuration file
    pub config: Option<String>,

    #[argh(option, default = "tracing::Level::INFO")]
    /// set the log level (default: INFO)
    pub log_level: tracing::Level,

    #[argh(subcommand)]
    pub cmd: Option<Command>,
}

pub fn args() -> Args {
    argh::from_env()
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum Command {
    GenerateConfig(GenConfig),
    UpdatePassword(UpdatePassword),
    AddUser(AddUser),
    Users(ListUsers),
    Prune(Prune),
    #[cfg(feature = "import")]
    Import(Import),
    #[cfg(debug_assertions)]
    Dev(Dev),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "prune")]
/// Prune collection data according to current UI-managed settings
pub struct Prune {
    #[argh(switch)]
    /// show what would be pruned without changing data
    dry_run: bool,
}

#[derive(FromArgs)]
#[cfg(feature = "import")]
#[argh(subcommand, name = "import")]
/// Import analytics data from another platform
pub struct Import {
    #[argh(subcommand)]
    cmd: ImportCommand,
}

#[derive(FromArgs)]
#[cfg(feature = "import")]
#[argh(subcommand)]
pub enum ImportCommand {
    #[cfg(feature = "import-matomo")]
    Matomo(ImportMatomo),
}

#[derive(FromArgs)]
#[cfg(feature = "import-matomo")]
#[argh(subcommand, name = "matomo")]
/// Import data from a Matomo instance
pub struct ImportMatomo {
    #[argh(option)]
    /// base URL of the Matomo instance (e.g. https://matomo.example.com)
    url: String,

    #[argh(option)]
    /// matomo API token; prefer the MATOMO_TOKEN environment variable
    token: Option<String>,

    #[argh(option)]
    /// site mapping <idSite>=<entity_id>; repeatable, at least one required
    site: Vec<String>,

    #[argh(option)]
    /// start date (YYYY-MM-DD, UTC); required on the first run per site
    since: Option<String>,

    #[argh(option, default = "1000")]
    /// number of visits to fetch per API request (default: 1000)
    page_size: u32,

    #[argh(switch)]
    /// fetch and map without writing anything (still pages the full window)
    dry_run: bool,

    #[argh(switch)]
    /// import even when entity settings would destroy imported data
    force: bool,

    #[argh(switch)]
    /// skip pageviews whose URL host is localhost or a private/reserved IP (live ingest keeps these)
    drop_local_urls: bool,
}

#[derive(FromArgs)]
#[cfg(debug_assertions)]
#[argh(subcommand, name = "dev")]
/// Debug-only development commands
pub struct Dev {
    #[argh(subcommand)]
    cmd: DevCommand,
}

#[derive(FromArgs)]
#[cfg(debug_assertions)]
#[argh(subcommand)]
pub enum DevCommand {
    Seed(SeedDatabase),
    GenerateOpenApi(GenerateOpenApi),
    ResetDb(ResetDb),
}

#[derive(FromArgs)]
#[cfg(debug_assertions)]
#[argh(subcommand, name = "seed")]
/// Seed the database with some test data
pub struct SeedDatabase {}

#[derive(FromArgs)]
#[cfg(debug_assertions)]
#[argh(subcommand, name = "generate-openapi")]
/// Regenerate the TypeScript OpenAPI definition
pub struct GenerateOpenApi {}

#[derive(FromArgs)]
#[cfg(debug_assertions)]
#[argh(subcommand, name = "reset-db")]
/// Delete local app and events database files
pub struct ResetDb {}

#[derive(FromArgs)]
#[argh(subcommand, name = "generate-config")]
/// Save a default configuration file to `liwan.config.toml`
pub struct GenConfig {
    #[argh(option, short = 'o')]
    /// the path to write the configuration file to
    output: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "update-password")]
/// Update a user's password
pub struct UpdatePassword {
    #[argh(positional)]
    /// the username of the user to update
    username: String,

    #[argh(positional)]
    /// the new password
    password: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "users")]
/// List all registered users
pub struct ListUsers {}

#[derive(FromArgs)]
#[argh(subcommand, name = "add-user")]
/// Create a new user
pub struct AddUser {
    #[argh(positional)]
    /// the username of the new user
    username: String,

    #[argh(positional)]
    /// the password of the new user
    password: String,

    #[argh(option, default = "false")]
    /// assign the user the admin role
    admin: bool,
}

pub async fn handle_command(mut config: Config, cmd: Command) -> Result<()> {
    config.geoip = GeoIpConfig::default(); // disable GeoIP in CLI commands

    match cmd {
        Command::UpdatePassword(update) => {
            let app = Liwan::try_new(config)?;
            app.users.update_password(&update.username, &update.password)?;
            println!("Password updated for user {}", update.username);
        }
        Command::Users(_) => {
            let app = Liwan::try_new(config)?;
            let users = app.users.all()?;
            if users.is_empty() {
                println!("No users found");
                println!("Use `liwan add-user` to create a new user");
                return Ok(());
            }

            println!("Users:");
            for user in users {
                println!(" - {} ({})", user.username, user.role);
            }
        }
        Command::AddUser(add) => {
            let app = Liwan::try_new(config)?;
            app.users.create(
                &add.username,
                &add.password,
                if add.admin { UserRole::Admin } else { UserRole::User },
                &[],
            )?;

            println!("User {} created", add.username);
        }
        Command::GenerateConfig(GenConfig { output }) => {
            let output = output.unwrap_or_else(|| "liwan.config.toml".to_string());
            if std::path::Path::new(&output).exists() {
                println!("Configuration file already exists");
                return Ok(());
            }

            std::fs::write(&output, DEFAULT_CONFIG)?;
            println!("Configuration file written to liwan.config.toml");
        }
        Command::Prune(prune) => {
            let app = Liwan::try_new(config)?;
            let mut totals = crate::app::PruneStats::default();
            for entity in app.entities.all()? {
                let settings = app.settings.resolved_for_entity(&entity.id);
                let stats = app.events.prune_entity(&entity.id, &settings, prune.dry_run)?;
                println!(
                    "{}: total={}, delete={}, clear_utm={}, clear_geo={}, clear_sessions={}",
                    entity.id,
                    stats.total_events,
                    stats.deleted_events,
                    stats.cleared_utm_events,
                    stats.cleared_geo_events,
                    stats.cleared_session_events
                );
                totals.total_events += stats.total_events;
                totals.deleted_events += stats.deleted_events;
                totals.cleared_utm_events += stats.cleared_utm_events;
                totals.cleared_geo_events += stats.cleared_geo_events;
                totals.cleared_session_events += stats.cleared_session_events;
            }
            println!(
                "total: total={}, delete={}, clear_utm={}, clear_geo={}, clear_sessions={}",
                totals.total_events,
                totals.deleted_events,
                totals.cleared_utm_events,
                totals.cleared_geo_events,
                totals.cleared_session_events
            );
            if prune.dry_run {
                println!("Dry run only. Re-run without --dry-run to apply changes.");
            }
        }
        #[cfg(feature = "import")]
        Command::Import(import) => match import.cmd {
            #[cfg(feature = "import-matomo")]
            ImportCommand::Matomo(matomo) => {
                let options = crate::app::import::run::MatomoImportOptions {
                    url: matomo.url,
                    token: matomo.token,
                    sites: matomo.site,
                    since: matomo.since,
                    page_size: matomo.page_size,
                    dry_run: matomo.dry_run,
                    force: matomo.force,
                    drop_local_urls: matomo.drop_local_urls,
                };
                crate::app::import::run::run_matomo(config, options).await?;
            }
        },
        #[cfg(debug_assertions)]
        Command::Dev(dev) => match dev.cmd {
            DevCommand::Seed(_) => {
                let app = Liwan::try_new(config)?;
                app.seed_database(5_000)?;
                println!("Database seeded with test data");
            }
            DevCommand::GenerateOpenApi(_) => {
                let app = Liwan::try_new(config)?;
                let (events, _) = tokio::sync::mpsc::channel(1);
                let (_, spec) = crate::web::router(app, events)?;
                crate::web::save_spec(spec)?;
                println!("OpenAPI definition generated");
            }
            DevCommand::ResetDb(_) => {
                let dir = std::path::Path::new(&config.data_dir);
                for file in [
                    "liwan-app.sqlite",
                    "liwan-app.sqlite-shm",
                    "liwan-app.sqlite-wal",
                    "liwan-events.duckdb",
                    "liwan-events.duckdb.wal",
                ] {
                    let path = dir.join(file);
                    if path.exists() {
                        std::fs::remove_file(&path)?;
                        println!("Deleted {}", path.display());
                    }
                }
            }
        },
    }

    Ok(())
}
