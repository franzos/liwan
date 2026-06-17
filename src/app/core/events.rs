use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::{DateTime, Local, NaiveTime, TimeZone, Utc};
use duckdb::{Connection, Result as DuckResult, params};
use rand::distr::{SampleString, StandardUniform};
use tokio::sync::mpsc::Receiver;

use crate::app::models::{Event, GeoDetail, ResolvedCollectionSettings, event_params};
use crate::app::{DuckDBPool, SqlitePool};
use crate::utils::duckdb::{ParamVec, repeat_vars};

#[derive(Clone)]
pub struct LiwanEvents {
    duckdb: DuckDBPool,
    sqlite: SqlitePool,
    daily_salt: Arc<ArcSwap<(String, DateTime<Utc>)>>,
    visitor_group_rotation_hour: u8,
}

#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    pub total_events: u64,
    pub deleted_events: u64,
    pub cleared_utm_events: u64,
    pub cleared_geo_events: u64,
    pub cleared_session_events: u64,
}

impl LiwanEvents {
    pub fn try_new(duckdb: DuckDBPool, sqlite: SqlitePool, visitor_group_rotation_hour: u8) -> Result<Self> {
        let daily_salt: (String, DateTime<Utc>) = {
            tracing::debug!("Loading visitor group salt");
            sqlite.get()?.query_row("select salt, updated_at from salts where id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
        };
        Ok(Self { duckdb, sqlite, daily_salt: ArcSwap::new(daily_salt.into()).into(), visitor_group_rotation_hour })
    }

    /// Get the visitor group salt, generating a new one after the daily local rotation time
    pub fn get_salt(&self) -> Result<String> {
        let (salt, updated_at) = &**self.daily_salt.load();

        if should_rotate_salt(*updated_at, self.visitor_group_rotation_hour) {
            tracing::debug!("Visitor group salt expired, generating a new one");
            let new_salt = StandardUniform.sample_string(&mut rand::rng(), 16);
            let now = Utc::now();
            let conn = self.sqlite.get()?;
            conn.execute(
                "update salts set salt = :salt, updated_at = :updated_at where id = 1",
                rusqlite::named_params! { ":salt": &new_salt, ":updated_at": now },
            )?;
            self.daily_salt.store((new_salt.clone(), now).into());
            Ok(new_salt)
        } else {
            Ok(salt.clone())
        }
    }

    /// Append events in a batch and update session timing fields when needed
    pub fn append(&self, events: impl Iterator<Item = Event>) -> Result<()> {
        let conn = self.duckdb.get()?;
        let mut first_event_time = None;
        let mut session_entities = Vec::new();
        let mut appender = conn.appender("events").context("Failed to get DuckDB appender")?;
        for event in events {
            if event.track_sessions {
                if first_event_time.is_none_or(|first_event_time| event.created_at < first_event_time) {
                    first_event_time = Some(event.created_at);
                }
                if !session_entities.contains(&event.entity_id) {
                    session_entities.push(event.entity_id.clone());
                }
            }
            appender.append_row(event_params![event]).context("Failed to append event to DuckDB")?;
        }

        appender.flush().context("Failed to flush events to DuckDB")?;
        if let Some(first_event_time) = first_event_time {
            update_event_times(&conn, first_event_time, &session_entities)
                .context("Failed to update event times in DuckDB")?;
        }
        Ok(())
    }

    /// Append events in a batch without touching session timing fields (bulk import path)
    #[cfg(feature = "import")]
    pub fn bulk_insert(&self, events: impl Iterator<Item = Event>) -> Result<()> {
        let conn = self.duckdb.get()?;
        let mut appender = conn.appender("events").context("Failed to get DuckDB appender")?;
        for event in events {
            appender.append_row(event_params![event]).context("Failed to append event to DuckDB")?;
        }
        appender.flush().context("Failed to flush events to DuckDB")?;
        Ok(())
    }

    /// Recompute session timing fields for all of an entity's imported events in one pass
    #[cfg(feature = "import")]
    pub fn recompute_sessions(&self, entity_id: &str) -> Result<()> {
        let conn = self.duckdb.get()?;
        // rowid keeps same-second rows ordered deterministically and joins back without fan-out
        let sql = "--sql
            with cte as (
                select
                    rowid as row_id,
                    created_at - lag(created_at) over (partition by visitor_group_id order by created_at, rowid) as time_from_last_event,
                    lead(created_at) over (partition by visitor_group_id order by created_at, rowid) - created_at as time_to_next_event
                from events
                where entity_id = ? and starts_with(visitor_group_id, ?)
            )
            update events
                set
                    time_from_last_event = cte.time_from_last_event,
                    time_to_next_event = cte.time_to_next_event
                from cte
                where events.rowid = cte.row_id;
        ";
        conn.execute(sql, params![entity_id, IMPORTED_VISITOR_PREFIX])
            .context("Failed to recompute session times in DuckDB")?;
        Ok(())
    }

    /// Delete an entity's imported events newer than the watermark, returning the deleted count
    #[cfg(feature = "import")]
    pub fn delete_imported_after(&self, entity_id: &str, watermark: DateTime<Utc>) -> Result<usize> {
        let conn = self.duckdb.get()?;
        let deleted = conn
            .execute(
                "delete from events where entity_id = ? and starts_with(visitor_group_id, ?) and created_at > ?::timestamp",
                params![entity_id, IMPORTED_VISITOR_PREFIX, watermark],
            )
            .context("Failed to delete imported events from DuckDB")?;
        Ok(deleted)
    }

    /// Start processing events from the given channel. Blocks until the channel is closed
    pub async fn process_events(&self, events_rx: Receiver<Event>) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let events = self.clone();
        std::thread::spawn(move || {
            let res = events.process_events_sync(events_rx).context("Event processing task failed");
            let _ = tx.send(res);
        });
        rx.await??;
        Ok(())
    }

    fn process_events_sync(&self, mut events: Receiver<Event>) -> Result<()> {
        let mut buffer = Vec::with_capacity(1024);
        let conn = self.duckdb.clone();

        loop {
            let count = events.blocking_recv_many(&mut buffer, 512);
            if count == 0 {
                tracing::info!("Event channel closed, stopping event processing");
                break Ok(());
            }

            let mut first_event_time = None;
            let mut session_entities = Vec::new();
            let mut insert_events = || -> Result<()> {
                let conn = conn.get().context("Failed to get DuckDB connection")?;
                let mut appender = conn.appender("events").context("Failed to get DuckDB appender")?;
                for event in buffer.drain(..count) {
                    if event.track_sessions {
                        if first_event_time.is_none_or(|first_event_time| event.created_at < first_event_time) {
                            first_event_time = Some(event.created_at);
                        }
                        if !session_entities.contains(&event.entity_id) {
                            session_entities.push(event.entity_id.clone());
                        }
                    }
                    appender.append_row(event_params![event]).context("Failed to append event to DuckDB")?;
                }

                appender.flush().context("Failed to flush events to DuckDB")?;
                if let Some(first_event_time) = first_event_time {
                    update_event_times(&conn, first_event_time, &session_entities)?;
                }
                Ok(())
            };

            match insert_events() {
                Err(err) => tracing::error!("Event processing task panicked: {:?}", err),
                _ => tracing::debug!("Processed {} events", count),
            }
        }
    }

    /// Preview or apply collection-setting pruning for a single entity
    pub fn prune_entity(
        &self,
        entity_id: &str,
        settings: &ResolvedCollectionSettings,
        dry_run: bool,
    ) -> Result<PruneStats> {
        let conn = self.duckdb.get()?;
        let mut stats = PruneStats {
            total_events: count_rows(&conn, "select count(*) from events where entity_id = ?", params![entity_id])?,
            ..Default::default()
        };

        if let crate::app::models::DataRetention::Days(data_retention_days) = settings.data_retention {
            let cutoff = Utc::now() - chrono::Duration::days(i64::from(data_retention_days.get()));
            stats.deleted_events = count_rows(
                &conn,
                "select count(*) from events where entity_id = $entity_id and created_at < $cutoff::timestamp",
                duckdb::named_params! { "entity_id": entity_id, "cutoff": cutoff },
            )?;
            if !dry_run {
                conn.execute(
                    "delete from events where entity_id = $entity_id and created_at < $cutoff::timestamp",
                    duckdb::named_params! { "entity_id": entity_id, "cutoff": cutoff },
                )?;
            }
        }

        if !settings.track_utm_params {
            let sql = "entity_id = ? and (utm_source is not null or utm_medium is not null or utm_campaign is not null or utm_content is not null or utm_term is not null)";
            stats.cleared_utm_events =
                count_rows(&conn, &format!("select count(*) from events where {sql}"), params![entity_id])?;
            if !dry_run {
                conn.execute(
                    &format!(
                        "update events set utm_source = null, utm_medium = null, utm_campaign = null, utm_content = null, utm_term = null where {sql}"
                    ),
                    params![entity_id],
                )?;
            }
        }

        match settings.track_geo {
            GeoDetail::None => {
                let sql = "entity_id = ? and (country is not null or city is not null)";
                stats.cleared_geo_events =
                    count_rows(&conn, &format!("select count(*) from events where {sql}"), params![entity_id])?;
                if !dry_run {
                    conn.execute(
                        &format!("update events set country = null, city = null where {sql}"),
                        params![entity_id],
                    )?;
                }
            }
            GeoDetail::Country => {
                let sql = "entity_id = ? and city is not null";
                stats.cleared_geo_events =
                    count_rows(&conn, &format!("select count(*) from events where {sql}"), params![entity_id])?;
                if !dry_run {
                    conn.execute(&format!("update events set city = null where {sql}"), params![entity_id])?;
                }
            }
            GeoDetail::City => {}
        }

        if !settings.track_sessions {
            let sql = "entity_id = ? and (time_from_last_event is not null or time_to_next_event is not null)";
            stats.cleared_session_events =
                count_rows(&conn, &format!("select count(*) from events where {sql}"), params![entity_id])?;
            if !dry_run {
                conn.execute(
                    &format!("update events set time_from_last_event = null, time_to_next_event = null where {sql}"),
                    params![entity_id],
                )?;
            }
        }

        Ok(stats)
    }
}

fn should_rotate_salt(updated_at: DateTime<Utc>, rotation_hour: u8) -> bool {
    let now = Local::now();
    let rotation_time = NaiveTime::from_hms_opt(u32::from(rotation_hour.min(23)), 0, 0).expect("valid rotation hour");
    let local_rotation = now.date_naive().and_time(rotation_time);
    let latest_rotation = match Local.from_local_datetime(&local_rotation) {
        chrono::LocalResult::Single(rotation) => rotation,
        chrono::LocalResult::Ambiguous(earlier, later) => earlier.min(later),
        chrono::LocalResult::None => now,
    };
    let latest_rotation =
        if now < latest_rotation { latest_rotation - chrono::Duration::days(1) } else { latest_rotation };

    updated_at < latest_rotation.with_timezone(&Utc)
}

fn count_rows(conn: &Connection, sql: &str, params: impl duckdb::Params) -> DuckResult<u64> {
    conn.query_row(sql, params, |row| row.get(0))
}

#[cfg(feature = "import")]
pub const IMPORTED_VISITOR_PREFIX: &str = "i_";

fn update_event_times(conn: &Connection, from_time: DateTime<Utc>, entities: &[String]) -> DuckResult<()> {
    if entities.is_empty() {
        return Ok(());
    }

    let entity_vars = repeat_vars(entities.len());
    // this can probably be simplified, sadly the where clause can't contain window functions
    let sql = format!("--sql
        with
            filtered_events as (
                select *
                from events
                where entity_id in ({entity_vars}) and (created_at >= ?::timestamp or visitor_group_id in (
                    select visitor_group_id
                    from events
                    where entity_id in ({entity_vars}) and created_at >= now()::timestamp - interval '24 hours' and created_at < ?::timestamp and time_to_next_event is null
                ))
            ),
            cte as (
                select
                    visitor_group_id,
                    created_at,
                    created_at - lag(created_at) over (partition by visitor_group_id order by created_at) as time_from_last_event,
                    lead(created_at) over (partition by visitor_group_id order by created_at) - created_at as time_to_next_event
                from filtered_events
            )
        update events
            set
                time_from_last_event = cte.time_from_last_event,
                time_to_next_event = cte.time_to_next_event
            from cte
            where events.visitor_group_id = cte.visitor_group_id and events.created_at = cte.created_at;
    ");

    let mut params = ParamVec::new();
    params.extend(entities);
    params.push(from_time);
    params.extend(entities);
    params.push(from_time);
    conn.execute(&sql, duckdb::params_from_iter(params))?;
    Ok(())
}

#[cfg(all(test, feature = "import"))]
mod tests {
    use super::*;
    use crate::app::Liwan;
    use crate::config::Config;
    use chrono::TimeZone;

    fn event(entity_id: &str, visitor_group_id: &str, created_at: DateTime<Utc>) -> Event {
        Event {
            entity_id: entity_id.to_string(),
            visitor_group_id: visitor_group_id.to_string(),
            event: "pageview".to_string(),
            created_at,
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

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2023, 6, 1, 10, 0, 0).unwrap()
    }

    /// (visitor_group_id, time_from_last_event, time_to_next_event) in seconds, ordered by created_at, rowid
    fn intervals(conn: &Connection, entity_id: &str) -> Vec<(String, Option<f64>, Option<f64>)> {
        let mut stmt = conn
            .prepare(
                "select visitor_group_id, epoch(time_from_last_event), epoch(time_to_next_event) from events where entity_id = ? order by created_at, rowid",
            )
            .unwrap();
        let rows = stmt.query_map(params![entity_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        rows.collect::<DuckResult<_>>().unwrap()
    }

    #[test]
    fn recompute_spans_batches_without_phantom_boundaries() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let start = t0();

        let batch1 =
            vec![event("ent", "i_visitor", start), event("ent", "i_visitor", start + chrono::Duration::seconds(30))];
        let batch2 = vec![
            event("ent", "i_visitor", start + chrono::Duration::seconds(60)),
            event("ent", "i_visitor", start + chrono::Duration::hours(2)),
        ];
        app.events.bulk_insert(batch1.into_iter()).unwrap();
        app.events.bulk_insert(batch2.into_iter()).unwrap();

        let conn = app.events_conn().unwrap();
        assert!(intervals(&conn, "ent").iter().all(|(_, from, to)| from.is_none() && to.is_none()));

        app.events.recompute_sessions("ent").unwrap();
        let rows = intervals(&conn, "ent");
        assert_eq!(
            rows,
            vec![
                ("i_visitor".to_string(), None, Some(30.0)),
                ("i_visitor".to_string(), Some(30.0), Some(30.0)),
                ("i_visitor".to_string(), Some(30.0), Some(7140.0)),
                ("i_visitor".to_string(), Some(7140.0), None),
            ]
        );
    }

    #[test]
    fn recompute_same_second_events_is_deterministic() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let start = t0();

        let events = vec![
            event("ent", "i_visitor", start),
            event("ent", "i_visitor", start),
            event("ent", "i_visitor", start),
            event("ent", "i_visitor", start + chrono::Duration::seconds(10)),
        ];
        app.events.bulk_insert(events.into_iter()).unwrap();

        let conn = app.events_conn().unwrap();
        let expected = vec![
            ("i_visitor".to_string(), None, Some(0.0)),
            ("i_visitor".to_string(), Some(0.0), Some(0.0)),
            ("i_visitor".to_string(), Some(0.0), Some(10.0)),
            ("i_visitor".to_string(), Some(10.0), None),
        ];

        app.events.recompute_sessions("ent").unwrap();
        assert_eq!(intervals(&conn, "ent"), expected);

        app.events.recompute_sessions("ent").unwrap();
        assert_eq!(intervals(&conn, "ent"), expected);
    }

    #[test]
    fn recompute_leaves_non_imported_rows_untouched() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let start = t0();

        let events = vec![
            event("ent", "iDecoyVisitor00", start),
            event("ent", "iDecoyVisitor00", start + chrono::Duration::seconds(30)),
            event("ent", "LiveVisitor00000", start),
            event("ent", "LiveVisitor00000", start + chrono::Duration::seconds(30)),
            event("other", "i_visitor", start),
            event("other", "i_visitor", start + chrono::Duration::seconds(30)),
        ];
        app.events.bulk_insert(events.into_iter()).unwrap();
        app.events.recompute_sessions("ent").unwrap();

        let conn = app.events_conn().unwrap();
        assert!(intervals(&conn, "ent").iter().all(|(_, from, to)| from.is_none() && to.is_none()));
        assert!(intervals(&conn, "other").iter().all(|(_, from, to)| from.is_none() && to.is_none()));
    }

    #[test]
    fn delete_imported_after_only_deletes_newer_imported_rows() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let start = t0();
        let watermark = start + chrono::Duration::hours(1);

        let events = vec![
            event("ent", "i_visitor", start),
            event("ent", "i_visitor", watermark),
            event("ent", "i_visitor", start + chrono::Duration::hours(2)),
            event("ent", "i_visitor", start + chrono::Duration::hours(3)),
            event("ent", "iDecoyVisitor00", start + chrono::Duration::hours(2)),
            event("ent", "LiveVisitor00000", start + chrono::Duration::hours(2)),
            event("other", "i_visitor", start + chrono::Duration::hours(2)),
        ];
        app.events.bulk_insert(events.into_iter()).unwrap();

        let deleted = app.events.delete_imported_after("ent", watermark).unwrap();
        assert_eq!(deleted, 2);

        let conn = app.events_conn().unwrap();
        let remaining = intervals(&conn, "ent");
        assert_eq!(
            remaining.iter().map(|(visitor, ..)| visitor.as_str()).collect::<Vec<_>>(),
            vec!["i_visitor", "i_visitor", "iDecoyVisitor00", "LiveVisitor00000"]
        );
        assert_eq!(intervals(&conn, "other").len(), 1);
    }
}
