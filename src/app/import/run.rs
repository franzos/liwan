use std::collections::HashSet;
use std::num::NonZeroU32;

use ::matomo::MatomoClient;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};

use crate::app::Liwan;
use crate::app::import::{
    Checkpoint, ImportStats, SiteMapping, chunk_windows, guard_destructive_settings, load_checkpoint, matomo,
    resolve_start, save_checkpoint, validate_entities, validate_mappings,
};
use crate::app::models::ResolvedCollectionSettings;
use crate::config::Config;

const SOURCE: &str = "matomo";
const PROGRESS_EVERY_PAGES: u32 = 50;

pub struct MatomoImportOptions {
    pub url: String,
    pub token: Option<String>,
    pub sites: Vec<String>,
    pub since: Option<String>,
    pub page_size: u32,
    pub dry_run: bool,
    pub force: bool,
    pub drop_local_urls: bool,
}

pub async fn run_matomo(config: Config, opts: MatomoImportOptions) -> Result<()> {
    if opts.sites.is_empty() {
        bail!("at least one --site <idSite>=<entity_id> mapping is required");
    }
    let mappings = opts.sites.iter().map(|raw| parse_site_mapping(raw)).collect::<Result<Vec<_>>>()?;
    validate_mappings(&mappings)?;

    let since = opts.since.as_deref().map(parse_since).transpose()?;
    let page_size = NonZeroU32::new(opts.page_size).context("--page-size must be at least 1")?;

    if opts.token.is_some() {
        tracing::warn!("--token can leak via shell history and process lists; prefer the MATOMO_TOKEN env var");
    }
    let token = resolve_token(opts.token.as_deref(), std::env::var("MATOMO_TOKEN").ok().as_deref())?;

    let data_dir = config.data_dir.clone();
    let app = Liwan::try_new(config)?;
    validate_entities(&app, &mappings)?;

    let mut plans = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let settings = app.settings.resolved_for_entity(&mapping.entity_id);
        guard_destructive_settings(&mapping.entity_id, &settings, opts.force)?;
        let checkpoint = load_checkpoint(&data_dir, SOURCE, mapping.id_site)?;
        let watermark = resolve_start(&mapping, checkpoint.as_ref(), since)?;
        plans.push((mapping, settings, watermark));
    }

    let ctx = SiteImport {
        app: &app,
        client: &matomo::client(&opts.url, &token)?,
        data_dir: &data_dir,
        page_size,
        dry_run: opts.dry_run,
        drop_local_urls: opts.drop_local_urls,
        run_start: Utc::now(),
    };

    let mut failed = Vec::new();
    for (mapping, settings, watermark) in &plans {
        let mut stats = ImportStats::default();
        let result = import_site(&ctx, mapping, settings, *watermark, &mut stats).await;
        println!("{}: {stats}", mapping.entity_id);
        if let Err(err) = result {
            println!("site {} ({}) failed: {err:#}", mapping.id_site, mapping.entity_id);
            failed.push(mapping.id_site.to_string());
        }
    }

    if ctx.dry_run {
        println!("Dry run only. Re-run without --dry-run to apply changes.");
    }
    if !failed.is_empty() {
        bail!("import failed for site(s): {}", failed.join(", "));
    }
    Ok(())
}

struct SiteImport<'a> {
    app: &'a Liwan,
    client: &'a MatomoClient,
    data_dir: &'a str,
    page_size: NonZeroU32,
    dry_run: bool,
    drop_local_urls: bool,
    run_start: DateTime<Utc>,
}

async fn import_site(
    ctx: &SiteImport<'_>,
    mapping: &SiteMapping,
    settings: &ResolvedCollectionSettings,
    watermark: DateTime<Utc>,
    stats: &mut ImportStats,
) -> Result<()> {
    if !ctx.dry_run {
        let deleted = ctx.app.events.delete_imported_after(&mapping.entity_id, watermark)?;
        stats.tail_deleted = deleted as u64;
    }

    let chunks = chunk_windows(watermark, ctx.run_start);
    let chunk_result = if chunks.is_empty() {
        println!("{}: nothing new to import since {watermark}", mapping.entity_id);
        Ok(())
    } else {
        import_chunks(ctx, mapping, settings, &chunks, stats).await
    };

    // also on zero-insert runs: heals intervals left stale by an interrupted run or the tail delete
    if !ctx.dry_run
        && settings.track_sessions
        && let Err(err) = ctx.app.events.recompute_sessions(&mapping.entity_id)
    {
        if chunk_result.is_ok() {
            return Err(err);
        }
        println!("{}: session recompute also failed: {err:#}", mapping.entity_id);
    }
    chunk_result
}

async fn import_chunks(
    ctx: &SiteImport<'_>,
    mapping: &SiteMapping,
    settings: &ResolvedCollectionSettings,
    chunks: &[(DateTime<Utc>, DateTime<Utc>)],
    stats: &mut ImportStats,
) -> Result<()> {
    for &(lo, hi) in chunks {
        let mut seen = HashSet::new();
        let mut offset = 0u32;
        let mut pages = 0u32;
        let mut chunk_events = 0u64;

        loop {
            let visits = matomo::fetch_page(ctx.client, mapping.id_site, (lo, hi), ctx.page_size, offset).await?;
            if visits.is_empty() {
                break;
            }
            pages += 1;

            let mut events = Vec::new();
            for visit in &visits {
                if !seen.insert(visit.id_visit) {
                    continue;
                }
                events.extend(matomo::map_visit(
                    visit,
                    &mapping.entity_id,
                    settings,
                    (lo, hi),
                    ctx.drop_local_urls,
                    stats,
                ));
            }
            chunk_events += events.len() as u64;

            if !ctx.dry_run && !events.is_empty() {
                ctx.app.events.bulk_insert(events.into_iter())?;
            }

            offset += ctx.page_size.get();
            if pages.is_multiple_of(PROGRESS_EVERY_PAGES) {
                println!("{}: chunk ({lo}, {hi}]: {pages} pages so far, {chunk_events} events", mapping.entity_id);
            }
        }

        println!("{}: chunk ({lo}, {hi}]: {pages} pages, {chunk_events} events", mapping.entity_id);

        if !ctx.dry_run {
            save_checkpoint(
                ctx.data_dir,
                &Checkpoint {
                    source: SOURCE.to_string(),
                    id_site: mapping.id_site,
                    entity_id: mapping.entity_id.clone(),
                    last_timestamp: hi.timestamp(),
                },
            )?;
        }
    }
    Ok(())
}

fn parse_site_mapping(raw: &str) -> Result<SiteMapping> {
    let (id_site, entity_id) =
        raw.split_once('=').with_context(|| format!("invalid --site '{raw}': expected <idSite>=<entity_id>"))?;
    let id_site: u32 =
        id_site.parse().with_context(|| format!("invalid --site '{raw}': '{id_site}' is not a valid site id"))?;
    if entity_id.is_empty() {
        bail!("invalid --site '{raw}': entity id is empty");
    }
    Ok(SiteMapping { id_site: id_site.into(), entity_id: entity_id.to_string() })
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>> {
    let date = NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .with_context(|| format!("invalid --since '{raw}': expected YYYY-MM-DD"))?;
    Ok(date.and_time(NaiveTime::MIN).and_utc())
}

fn resolve_token(flag: Option<&str>, env: Option<&str>) -> Result<String> {
    flag.filter(|token| !token.is_empty())
        .or(env.filter(|token| !token.is_empty()))
        .map(ToString::to_string)
        .context("no Matomo API token provided; pass --token or set the MATOMO_TOKEN environment variable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn site_mapping_parses_valid_input() {
        assert_eq!(parse_site_mapping("3=blog").unwrap(), SiteMapping { id_site: 3, entity_id: "blog".to_string() });
        assert_eq!(parse_site_mapping("1=my-entity=x").unwrap().entity_id, "my-entity=x");
    }

    #[test]
    fn site_mapping_rejects_bad_site_id() {
        assert!(parse_site_mapping("abc=blog").unwrap_err().to_string().contains("not a valid site id"));
        assert!(parse_site_mapping("-1=blog").unwrap_err().to_string().contains("not a valid site id"));
        assert!(parse_site_mapping("=blog").unwrap_err().to_string().contains("not a valid site id"));
    }

    #[test]
    fn site_mapping_rejects_missing_separator_and_empty_entity() {
        assert!(parse_site_mapping("3blog").unwrap_err().to_string().contains("expected <idSite>=<entity_id>"));
        assert!(parse_site_mapping("3=").unwrap_err().to_string().contains("entity id is empty"));
    }

    #[test]
    fn duplicate_mappings_are_rejected_by_validate_mappings() {
        let mappings: Vec<_> = ["1=a", "1=b"].iter().map(|raw| parse_site_mapping(raw).unwrap()).collect();
        assert!(validate_mappings(&mappings).unwrap_err().to_string().contains("duplicate site id 1"));

        let mappings: Vec<_> = ["1=a", "2=a"].iter().map(|raw| parse_site_mapping(raw).unwrap()).collect();
        assert!(validate_mappings(&mappings).unwrap_err().to_string().contains("mapped from multiple sites"));
    }

    #[test]
    fn since_parses_as_start_of_day_utc() {
        assert_eq!(parse_since("2024-05-01").unwrap(), Utc.with_ymd_and_hms(2024, 5, 1, 0, 0, 0).unwrap());
        assert!(parse_since("01.05.2024").unwrap_err().to_string().contains("expected YYYY-MM-DD"));
        assert!(parse_since("2024-13-01").is_err());
    }

    #[test]
    fn token_precedence_is_flag_then_env_then_error() {
        assert_eq!(resolve_token(Some("flag"), Some("env")).unwrap(), "flag");
        assert_eq!(resolve_token(None, Some("env")).unwrap(), "env");
        assert_eq!(resolve_token(Some(""), Some("env")).unwrap(), "env");
        assert_eq!(
            resolve_token(None, Some("")).unwrap_err().to_string(),
            resolve_token(None, None).unwrap_err().to_string()
        );
        assert_eq!(
            resolve_token(Some(""), None).unwrap_err().to_string(),
            resolve_token(None, None).unwrap_err().to_string()
        );
        assert!(resolve_token(None, None).unwrap_err().to_string().contains("MATOMO_TOKEN"));
    }
}
