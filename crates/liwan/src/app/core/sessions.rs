use crate::app::{SqlitePool, models};
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use std::collections::HashSet;

#[derive(Clone)]
pub struct LiwanSessions {
    pool: SqlitePool,
}

impl LiwanSessions {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new session
    pub fn create(&self, session_id: &str, username: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare_cached("insert into sessions (id, username, expires_at) values (:id, :username, :expires_at)")?;
        stmt.execute(rusqlite::named_params! {
            ":id": session_id,
            ":username": username,
            ":expires_at": expires_at,
        })?;
        Ok(())
    }

    /// Create a session for an SSO login, tagged with the IdP's session id when
    /// it sent one. That tag is what back-channel logout ends.
    pub fn create_external(
        &self,
        session_id: &str,
        username: &str,
        expires_at: DateTime<Utc>,
        external_sid: Option<&str>,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached(
            "insert into sessions (id, username, expires_at, external_sid) values (:id, :username, :expires_at, :external_sid)",
        )?;
        stmt.execute(rusqlite::named_params! {
            ":id": session_id,
            ":username": username,
            ":expires_at": expires_at,
            ":external_sid": external_sid,
        })?;
        Ok(())
    }

    /// Get the user associated with a session ID, if the session is still valid
    /// Returns `None` if the session is expired
    pub fn get(&self, session_id: &str) -> Result<Option<models::User>> {
        let conn = self.pool.get()?;

        let user = conn
            .query_row(
                "select u.username, u.role from sessions s join users u on lower(u.username) = lower(s.username) where s.id = ? and s.expires_at > ?",
                rusqlite::params![session_id, Utc::now()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((username, role)) = user else { return Ok(None) };

        let mut teams = conn.prepare_cached(
            "select t.all_projects, t.all_entities, t.permissions_json,
                (select json_group_array(project_id) from team_projects where team_id = t.id),
                (select json_group_array(entity_id) from team_entities where team_id = t.id)
             from teams t join team_users tu on tu.team_id = t.id where tu.username = ?",
        )?;
        let rows = teams.query_map([&username], |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut projects = HashSet::new();
        let mut entities = HashSet::new();
        let mut all_projects = false;
        let mut all_entities = false;
        let mut permissions = HashSet::new();
        for row in rows {
            let (team_all_projects, team_all_entities, granted, project_ids, entity_ids) = row?;
            if serde_json::from_str::<HashSet<models::AccessPermission>>(&granted)?
                .contains(&models::AccessPermission::ProjectRead)
            {
                permissions.insert(models::AccessPermission::ProjectRead);
                all_projects |= team_all_projects;
                if !team_all_projects {
                    projects.extend(serde_json::from_str::<Vec<String>>(&project_ids)?);
                }
            }
            all_entities |= team_all_entities;
            if !team_all_entities {
                entities.extend(serde_json::from_str::<Vec<String>>(&entity_ids)?);
            }
        }

        Ok(Some(models::User {
            username,
            role: role.try_into().unwrap_or_default(),
            access: models::Access {
                projects: if all_projects {
                    models::AccessScope::All
                } else {
                    models::AccessScope::Selected(projects.into_iter().collect())
                },
                entities: if all_entities {
                    models::AccessScope::All
                } else {
                    models::AccessScope::Selected(entities.into_iter().collect())
                },
                permissions,
            },
        }))
    }

    /// Revoke all sessions belonging to a user. Matches the case-insensitive
    /// join `get` uses, since `login` stores whatever casing the client sent.
    pub fn revoke_user(&self, username: &str) -> Result<usize> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached("delete from sessions where lower(username) = lower(?)")?;
        Ok(stmt.execute([username])?)
    }

    /// Expire a session
    pub fn delete(&self, session_id: &str) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached("update sessions set expires_at = :expires_at where id = :id")?;
        stmt.execute(rusqlite::named_params! { ":expires_at": Utc::now(), ":id": session_id })?;
        Ok(())
    }

    /// End the sessions carrying an IdP session id. Deleted rather than expired:
    /// the IdP has signed the person out, so there is nothing left to audit.
    pub fn delete_by_external_sid(&self, external_sid: &str) -> Result<usize> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached("delete from sessions where external_sid = ?")?;
        Ok(stmt.execute([external_sid])?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{app::Liwan, app::models::UserRole, config::Config};

    fn app() -> std::sync::Arc<Liwan> {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("alice", "correct-horse-battery", UserRole::User).unwrap();
        app
    }

    fn expires() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    #[test]
    fn delete_by_external_sid_leaves_other_sessions() {
        let app = app();
        app.sessions.create_external("laptop", "alice", expires(), Some("idp-session-1")).unwrap();
        app.sessions.create_external("phone", "alice", expires(), Some("idp-session-2")).unwrap();
        app.sessions.create("password-login", "alice", expires()).unwrap();

        assert_eq!(app.sessions.delete_by_external_sid("idp-session-1").unwrap(), 1);
        assert!(app.sessions.get("laptop").unwrap().is_none());
        assert!(app.sessions.get("phone").unwrap().is_some());
        assert!(app.sessions.get("password-login").unwrap().is_some());

        // A sid nobody signed in with is a no-op, not a mass logout.
        assert_eq!(app.sessions.delete_by_external_sid("idp-session-unknown").unwrap(), 0);
        assert_eq!(app.sessions.delete_by_external_sid("").unwrap(), 0);
    }

    #[test]
    fn revoke_user_is_case_insensitive() {
        let app = app();
        app.sessions.create("password-login", "AlIcE", expires()).unwrap();
        app.sessions.create_external("laptop", "alice", expires(), Some("idp-session-1")).unwrap();
        app.users.create("bob", "another-long-password", UserRole::User).unwrap();
        app.sessions.create("bobs-session", "bob", expires()).unwrap();

        assert_eq!(app.sessions.revoke_user("alice").unwrap(), 2);
        assert!(app.sessions.get("password-login").unwrap().is_none());
        assert!(app.sessions.get("laptop").unwrap().is_none());
        assert!(app.sessions.get("bobs-session").unwrap().is_some());
    }
}
