#[cfg(feature = "import-matomo")]
pub mod matomo;
#[cfg(feature = "import-matomo")]
pub mod run;

use std::fmt::Display;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Months, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::app::Liwan;
use crate::app::models::{DataRetention, FilterType, IngestDropRule, ResolvedCollectionSettings};

/// Events newer than `run_start - LATENESS_ALLOWANCE` are left for the next run
pub const LATENESS_ALLOWANCE: TimeDelta = TimeDelta::hours(1);

/// Maps a source-side site id to a liwan entity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteMapping {
    pub id_site: u64,
    pub entity_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub source: String,
    pub id_site: u64,
    pub entity_id: String,
    /// UTC unix seconds watermark of the newest imported event
    pub last_timestamp: i64,
}

impl Checkpoint {
    pub fn watermark(&self) -> Result<DateTime<Utc>> {
        DateTime::from_timestamp(self.last_timestamp, 0)
            .with_context(|| format!("invalid checkpoint timestamp: {}", self.last_timestamp))
    }
}

fn checkpoint_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("import")
}

fn checkpoint_file(source: &str, id_site: u64) -> String {
    format!("{source}-{id_site}.json")
}

pub fn load_checkpoint(data_dir: &str, source: &str, id_site: u64) -> Result<Option<Checkpoint>> {
    let path = checkpoint_dir(data_dir).join(checkpoint_file(source, id_site));
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse checkpoint file {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read checkpoint file {}", path.display())),
    }
}

pub fn save_checkpoint(data_dir: &str, checkpoint: &Checkpoint) -> Result<()> {
    let dir = checkpoint_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create checkpoint directory {}", dir.display()))?;

    let file = checkpoint_file(&checkpoint.source, checkpoint.id_site);
    let path = dir.join(&file);
    let tmp = dir.join(format!("{file}.tmp"));
    let json = serde_json::to_vec_pretty(checkpoint)?;

    std::fs::write(&tmp, json).with_context(|| format!("failed to write checkpoint file {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("failed to move checkpoint file into place at {}", path.display()))?;
    Ok(())
}

pub fn validate_mappings(mappings: &[SiteMapping]) -> Result<()> {
    let mut seen_sites = std::collections::HashSet::new();
    let mut seen_entities = std::collections::HashSet::new();
    for mapping in mappings {
        if !seen_sites.insert(mapping.id_site) {
            bail!("duplicate site id {} in site mappings", mapping.id_site);
        }
        if !seen_entities.insert(mapping.entity_id.as_str()) {
            bail!(
                "entity '{}' is mapped from multiple sites; imported rows cannot be attributed back to a source site, so resuming one site's import would delete another site's rows",
                mapping.entity_id
            );
        }
    }
    Ok(())
}

/// Resolve the import start for a site: the checkpoint watermark on resume, `--since` on first run
pub fn resolve_start(
    mapping: &SiteMapping,
    checkpoint: Option<&Checkpoint>,
    since: Option<DateTime<Utc>>,
) -> Result<DateTime<Utc>> {
    match (checkpoint, since) {
        (Some(checkpoint), _) if checkpoint.entity_id != mapping.entity_id => bail!(
            "checkpoint for site {} maps to entity '{}', but the current mapping says '{}'; \
             delete the checkpoint file to re-import deliberately",
            mapping.id_site,
            checkpoint.entity_id,
            mapping.entity_id,
        ),
        (Some(_), Some(_)) => bail!(
            "--since cannot be combined with an existing checkpoint for site {}; \
             to backfill older data, delete the checkpoint file first \
             (re-importing is safe: resuming deletes imported rows newer than the watermark)",
            mapping.id_site,
        ),
        (Some(checkpoint), None) => checkpoint.watermark(),
        (None, Some(since)) => Ok(since),
        (None, None) => bail!("no checkpoint found for site {}; the first run requires --since", mapping.id_site),
    }
}

/// Split `(watermark, run_start - LATENESS_ALLOWANCE]` into closed intervals `(lo, hi]`
/// of at most one calendar month each
pub fn chunk_windows(watermark: DateTime<Utc>, run_start: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let upper = run_start - LATENESS_ALLOWANCE;
    let mut chunks = Vec::new();
    let mut lo = watermark;
    while lo < upper {
        let hi = lo.checked_add_months(Months::new(1)).map_or(upper, |hi| hi.min(upper));
        chunks.push((lo, hi));
        lo = hi;
    }
    chunks
}

#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    pub visits_fetched: u64,
    pub actions_seen: u64,
    pub events_imported: u64,
    pub dropped_by_rule: u64,
    pub referrer_spam: u64,
    pub out_of_window: u64,
    pub skipped_no_visitor_id: u64,
    pub skipped_malformed: u64,
    pub skipped_local_url: u64,
    pub tail_deleted: u64,
}

impl Display for ImportStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "visits={}, actions={}, imported={}, dropped={}, referrer_spam={}, out_of_window={}, no_visitor_id={}, malformed={}, local_url={}, tail_deleted={}",
            self.visits_fetched,
            self.actions_seen,
            self.events_imported,
            self.dropped_by_rule,
            self.referrer_spam,
            self.out_of_window,
            self.skipped_no_visitor_id,
            self.skipped_malformed,
            self.skipped_local_url,
            self.tail_deleted
        )
    }
}

pub fn validate_entities(app: &Liwan, mappings: &[SiteMapping]) -> Result<()> {
    for mapping in mappings {
        if !app.entities.exists(&mapping.entity_id)? {
            bail!("entity '{}' does not exist (mapped from site {})", mapping.entity_id, mapping.id_site);
        }
    }
    Ok(())
}

/// Abort when the entity's settings would destroy imported data, unless `force` is set
pub fn guard_destructive_settings(entity_id: &str, settings: &ResolvedCollectionSettings, force: bool) -> Result<()> {
    let mut problems = Vec::new();

    if let DataRetention::Days(days) = settings.data_retention {
        problems.push(format!("data retention is set to {days} days, the next prune would delete imported history"));
    }

    if settings.ingest_drop_rules.iter().any(drops_all_imported_events) {
        problems.push(
            "a drop rule matches 100% of imported events (is_null on screen_width or orientation, \
             which are always empty for imported data)"
                .to_string(),
        );
    }

    if problems.is_empty() {
        return Ok(());
    }

    if force {
        for problem in &problems {
            tracing::warn!(entity_id, "ignoring destructive setting (--force): {problem}");
        }
        return Ok(());
    }

    bail!("entity '{entity_id}': {}; re-run with --force to import anyway", problems.join("; "))
}

fn drops_all_imported_events(rule: &IngestDropRule) -> bool {
    !rule.filters.is_empty()
        && rule.filters.iter().all(|filter| {
            filter.filter_type == FilterType::IsNull
                && matches!(filter.dimension.as_str(), "screen_width" | "orientation")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::models::{IngestDropRule, IngestFilter, VisitorGroupMode};
    use chrono::TimeZone;
    use std::num::NonZeroU32;

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            source: "matomo".to_string(),
            id_site: 3,
            entity_id: "blog".to_string(),
            last_timestamp: 1_717_800_000,
        }
    }

    fn mapping(id_site: u64, entity_id: &str) -> SiteMapping {
        SiteMapping { id_site, entity_id: entity_id.to_string() }
    }

    fn settings(data_retention: DataRetention, ingest_drop_rules: Vec<IngestDropRule>) -> ResolvedCollectionSettings {
        ResolvedCollectionSettings {
            visitor_group_mode: VisitorGroupMode::Accurate,
            track_sessions: true,
            track_utm_params: true,
            track_geo: crate::app::models::GeoDetail::City,
            data_retention,
            ingest_drop_rules,
            allowed_hostnames: Vec::new(),
        }
    }

    fn is_null(dimension: &str) -> IngestFilter {
        IngestFilter { dimension: dimension.to_string(), filter_type: FilterType::IsNull, value: None }
    }

    #[test]
    fn checkpoint_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        save_checkpoint(data_dir, &checkpoint()).unwrap();
        assert_eq!(load_checkpoint(data_dir, "matomo", 3).unwrap(), Some(checkpoint()));
    }

    #[test]
    fn checkpoint_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_checkpoint(dir.path().to_str().unwrap(), "matomo", 3).unwrap(), None);
    }

    #[test]
    fn checkpoint_save_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        save_checkpoint(data_dir, &checkpoint()).unwrap();
        save_checkpoint(data_dir, &Checkpoint { last_timestamp: 1_717_900_000, ..checkpoint() }).unwrap();

        let files: Vec<_> = std::fs::read_dir(dir.path().join("import"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(files, vec!["matomo-3.json"]);
        assert_eq!(load_checkpoint(data_dir, "matomo", 3).unwrap().unwrap().last_timestamp, 1_717_900_000);
    }

    #[test]
    fn validate_mappings_rejects_duplicate_site_ids() {
        assert!(validate_mappings(&[mapping(1, "a"), mapping(2, "b")]).is_ok());

        let err = validate_mappings(&[mapping(1, "a"), mapping(1, "b")]).unwrap_err();
        assert!(err.to_string().contains("duplicate site id 1"));
    }

    #[test]
    fn validate_mappings_rejects_duplicate_entities() {
        assert!(validate_mappings(&[mapping(1, "a"), mapping(2, "b")]).is_ok());

        let err = validate_mappings(&[mapping(1, "a"), mapping(2, "a")]).unwrap_err();
        assert!(err.to_string().contains("'a' is mapped from multiple sites"));
    }

    #[test]
    fn resolve_start_rejects_entity_mismatch() {
        let err = resolve_start(&mapping(3, "docs"), Some(&checkpoint()), None).unwrap_err();
        assert!(err.to_string().contains("delete the checkpoint"));
    }

    #[test]
    fn resolve_start_rejects_since_with_checkpoint() {
        let since = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let err = resolve_start(&mapping(3, "blog"), Some(&checkpoint()), Some(since)).unwrap_err();
        assert!(err.to_string().contains("--since cannot be combined"));
    }

    #[test]
    fn resolve_start_requires_since_on_first_run() {
        let err = resolve_start(&mapping(3, "blog"), None, None).unwrap_err();
        assert!(err.to_string().contains("requires --since"));
    }

    #[test]
    fn resolve_start_happy_paths() {
        let watermark = resolve_start(&mapping(3, "blog"), Some(&checkpoint()), None).unwrap();
        assert_eq!(watermark.timestamp(), 1_717_800_000);

        let since = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(resolve_start(&mapping(3, "blog"), None, Some(since)).unwrap(), since);
    }

    #[test]
    fn chunking_short_window_is_a_single_chunk() {
        let watermark = Utc.with_ymd_and_hms(2024, 5, 1, 0, 0, 0).unwrap();
        let run_start = Utc.with_ymd_and_hms(2024, 5, 10, 12, 0, 0).unwrap();

        let chunks = chunk_windows(watermark, run_start);
        assert_eq!(chunks, vec![(watermark, run_start - LATENESS_ALLOWANCE)]);
    }

    #[test]
    fn chunking_multi_month_window_is_contiguous_and_bounded() {
        let watermark = Utc.with_ymd_and_hms(2024, 1, 15, 6, 30, 0).unwrap();
        let run_start = Utc.with_ymd_and_hms(2024, 6, 3, 12, 0, 0).unwrap();
        let upper = run_start - LATENESS_ALLOWANCE;

        let chunks = chunk_windows(watermark, run_start);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.first().unwrap().0, watermark);
        assert_eq!(chunks.last().unwrap().1, upper);
        for (lo, hi) in &chunks {
            assert!(lo < hi);
            assert!(*hi <= lo.checked_add_months(Months::new(1)).unwrap());
        }
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].1, pair[1].0);
        }
    }

    #[test]
    fn chunking_empty_window_yields_no_chunks() {
        let run_start = Utc.with_ymd_and_hms(2024, 5, 10, 12, 0, 0).unwrap();
        assert!(chunk_windows(run_start - LATENESS_ALLOWANCE, run_start).is_empty());
        assert!(chunk_windows(run_start, run_start).is_empty());
    }

    #[test]
    fn chunking_boundary_belongs_to_exactly_one_chunk() {
        let watermark = Utc.with_ymd_and_hms(2024, 1, 15, 0, 0, 0).unwrap();
        let run_start = Utc.with_ymd_and_hms(2024, 4, 1, 12, 0, 0).unwrap();

        let chunks = chunk_windows(watermark, run_start);
        let boundary = chunks[0].1;
        let containing = chunks.iter().filter(|(lo, hi)| *lo < boundary && boundary <= *hi).count();
        assert_eq!(containing, 1);
    }

    #[test]
    fn guard_aborts_on_days_retention() {
        let settings = settings(DataRetention::Days(NonZeroU32::new(30).unwrap()), Vec::new());
        let err = guard_destructive_settings("blog", &settings, false).unwrap_err();
        assert!(err.to_string().contains("prune"));
    }

    #[test]
    fn guard_aborts_on_is_null_screen_width_or_orientation_rule() {
        for dimension in ["screen_width", "orientation"] {
            let settings = settings(DataRetention::All, vec![IngestDropRule { filters: vec![is_null(dimension)] }]);
            assert!(guard_destructive_settings("blog", &settings, false).is_err());
        }
    }

    #[test]
    fn guard_passes_on_forever_retention_and_harmless_rules() {
        let harmless_rules = vec![
            IngestDropRule {
                filters: vec![IngestFilter {
                    dimension: "path".to_string(),
                    filter_type: FilterType::StartsWith,
                    value: Some("/internal".to_string()),
                }],
            },
            // only drops a subset of imports: the path filter narrows it
            IngestDropRule {
                filters: vec![
                    is_null("screen_width"),
                    IngestFilter {
                        dimension: "path".to_string(),
                        filter_type: FilterType::Equal,
                        value: Some("/health".to_string()),
                    },
                ],
            },
        ];
        assert!(guard_destructive_settings("blog", &settings(DataRetention::All, harmless_rules), false).is_ok());
    }

    #[test]
    fn guard_force_bypasses_with_warning() {
        let settings = settings(
            DataRetention::Days(NonZeroU32::new(30).unwrap()),
            vec![IngestDropRule { filters: vec![is_null("screen_width")] }],
        );
        assert!(guard_destructive_settings("blog", &settings, true).is_ok());
    }

    #[test]
    fn validate_entities_checks_existence() {
        let app = crate::app::Liwan::new_memory(crate::config::Config::default()).unwrap();
        app.entities
            .create(&crate::app::models::Entity { id: "blog".to_string(), display_name: "Blog".to_string() }, &[])
            .unwrap();

        assert!(validate_entities(&app, &[mapping(3, "blog")]).is_ok());
        let err = validate_entities(&app, &[mapping(3, "blog"), mapping(4, "missing")]).unwrap_err();
        assert!(err.to_string().contains("'missing' does not exist"));
    }
}
