use crate::app::{SqlitePool, models};
use anyhow::Result;
use chrono::{DateTime, Utc};

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

    /// Get the user associated with a session ID, if the session is still valid
    /// Returns `None` if the session is expired
    pub fn get(&self, session_id: &str) -> Result<Option<models::User>> {
        let conn = self.pool.get()?;

        let mut stmt = conn.prepare_cached(
            r#"--sql
            select u.username, u.role, u.projects
            from sessions s
            join users u
            on lower(u.username) = lower(s.username)
            where
                s.id = :session_id
                and s.expires_at > :now
        "#,
        )?;

        let user = stmt.query_row(rusqlite::named_params! { ":session_id": session_id, ":now": Utc::now() }, |row| {
            Ok(models::User {
                username: row.get("username")?,
                role: row.get::<_, String>("role")?.try_into().unwrap_or_default(),
                projects: row
                    .get::<_, String>("projects")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        });

        user.map(Some).or_else(
            |err| {
                if err == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(err.into()) }
            },
        )
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

    /// End every session an account has, password logins included. Matches the
    /// case-insensitive join `get` uses, since `login` stores whatever casing
    /// the client sent.
    pub fn delete_for_user(&self, username: &str) -> Result<usize> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached("delete from sessions where lower(username) = lower(?)")?;
        Ok(stmt.execute([username])?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{app::Liwan, app::models::UserRole, config::Config};

    fn app() -> std::sync::Arc<Liwan> {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("alice", "correct-horse-battery", UserRole::User, &[]).unwrap();
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
    fn delete_for_user_is_case_insensitive() {
        let app = app();
        app.sessions.create("password-login", "AlIcE", expires()).unwrap();
        app.sessions.create_external("laptop", "alice", expires(), Some("idp-session-1")).unwrap();
        app.users.create("bob", "another-long-password", UserRole::User, &[]).unwrap();
        app.sessions.create("bobs-session", "bob", expires()).unwrap();

        assert_eq!(app.sessions.delete_for_user("alice").unwrap(), 2);
        assert!(app.sessions.get("password-login").unwrap().is_none());
        assert!(app.sessions.get("laptop").unwrap().is_none());
        assert!(app.sessions.get("bobs-session").unwrap().is_some());
    }
}
