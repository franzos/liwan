use crate::app::{SqlitePool, models};
use crate::utils::hash::{hash_password, verify_password};
use crate::utils::validate;
use anyhow::{Result, bail};
use rusqlite::OptionalExtension;

/// What [`LiwanUsers::update_password`] did, so callers can distinguish a refusal
/// from a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordUpdateOutcome {
    Updated,
    UserNotFound,
    /// The account signs in through the IdP and has no local password.
    NotPasswordAuth,
}

#[derive(Clone)]
pub struct LiwanUsers {
    pub(crate) pool: SqlitePool,
}

impl LiwanUsers {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Check whether a user's password is correct
    pub fn check_login(&self, username: &str, password: &str) -> Result<bool> {
        let username = username.to_lowercase();
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("select password_hash from users where username = ?")?;
        let hash: Option<String> = stmt.query_row([username], |row| row.get(0))?;
        // SSO-only accounts have a NULL hash; password auth must never succeed for them.
        Ok(hash.is_some_and(|hash| verify_password(password, &hash).is_ok()))
    }

    /// Get a user by username
    pub fn get(&self, username: &str) -> Result<models::User> {
        let username = username.to_lowercase();
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("select username, password_hash, role, projects from users where username = ?")?;
        let user = stmt.query_row([username], row_to_user);
        user.map_err(|_| anyhow::anyhow!("user not found"))
    }

    /// Get all users
    pub fn all(&self) -> Result<Vec<models::User>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("select username, password_hash, role, projects from users")?;
        let users = stmt.query_map([], row_to_user)?;
        Ok(users.collect::<Result<Vec<models::User>, rusqlite::Error>>()?)
    }

    /// Create a new user
    pub fn create(&self, username: &str, password: &str, role: models::UserRole, projects: &[&str]) -> Result<()> {
        if !validate::is_valid_username(username) {
            bail!("invalid username");
        }
        let username = username.to_lowercase();
        let password_hash = hash_password(password)?;
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached(
            "insert into users (username, password_hash, role, projects) values (:username, :password_hash, :role, :projects)",
        )?;
        stmt.execute(rusqlite::named_params! {
            ":username": username,
            ":password_hash": password_hash,
            ":role": role.to_string(),
            ":projects": projects.join(","),
        })?;
        Ok(())
    }

    /// Update a user's role and project memberships
    pub fn update(&self, username: &str, role: models::UserRole, projects: &[String]) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare_cached("update users set role = :role, projects = :projects where username = :username")?;
        stmt.execute(rusqlite::named_params! {
            ":role": role.to_string(),
            ":projects": projects.join(","),
            ":username": username,
        })?;
        Ok(())
    }

    /// Update a user's password.
    ///
    /// Refuses SSO-only accounts: a local password on one is a login path that
    /// outlives IdP deactivation and MFA, while the UI still reports SSO-only.
    /// The break-glass for a locked-out SSO admin is `liwan add-user`.
    pub fn update_password(&self, username: &str, password: &str) -> Result<PasswordUpdateOutcome> {
        let conn = self.pool.get()?;
        // Same connection for the check and the update, so a concurrent change
        // cannot slip between them.
        let existing: Option<Option<String>> = conn
            .prepare_cached("select password_hash from users where username = ?")?
            .query_row([username], |row| row.get(0))
            .optional()?;

        let Some(existing) = existing else {
            return Ok(PasswordUpdateOutcome::UserNotFound);
        };
        if existing.is_none() {
            return Ok(PasswordUpdateOutcome::NotPasswordAuth);
        }

        let password_hash = hash_password(password)?;
        let mut stmt = conn.prepare_cached(
            "update users set password_hash = :password_hash where username = :username and password_hash is not null",
        )?;
        stmt.execute(rusqlite::named_params! { ":password_hash": password_hash, ":username": username })?;
        Ok(PasswordUpdateOutcome::Updated)
    }

    /// Delete a user and every session issued to them. Sessions join to users on
    /// `lower(username)`, so leaving them behind hands the account to whoever
    /// takes the name next.
    ///
    /// The users row matches case-sensitively, the sessions rows do not: `login`
    /// stores whatever casing the client sent. Clearing sessions only once the
    /// row is really gone keeps a name that matches nothing a no-op, rather than
    /// logging someone out of an account that still exists.
    pub fn delete(&self, username: &str) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        let deleted = tx.execute("delete from users where username = ?", [username])?;
        if deleted > 0 {
            tx.execute("delete from sessions where lower(username) = lower(?)", [username])?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Map a row selecting `username, password_hash, role, projects`.
fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<models::User> {
    Ok(models::User {
        username: row.get("username")?,
        role: row.get::<_, String>("role")?.try_into().unwrap_or_default(),
        projects: row.get::<_, String>("projects")?.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Liwan;
    use crate::app::models::UserRole;
    use crate::config::Config;
    use chrono::Utc;

    #[test]
    fn update_password_refuses_sso_only_account() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users
            .pool
            .get()
            .unwrap()
            .execute(
                "insert into users (username, password_hash, role, projects) values ('alice', null, 'user', '')",
                [],
            )
            .unwrap();

        assert_eq!(
            app.users.update_password("alice", "newpasswordnew").unwrap(),
            PasswordUpdateOutcome::NotPasswordAuth
        );
        // Still no local login path.
        assert!(!app.users.check_login("alice", "newpasswordnew").unwrap());
    }

    #[test]
    fn update_password_reports_unknown_user() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        assert_eq!(app.users.update_password("nobody", "newpasswordnew").unwrap(), PasswordUpdateOutcome::UserNotFound);
    }

    #[test]
    fn update_password_updates_password_account() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "oldpasswordold", UserRole::User, &[]).unwrap();

        assert_eq!(app.users.update_password("bob", "newpasswordnew").unwrap(), PasswordUpdateOutcome::Updated);
        assert!(app.users.check_login("bob", "newpasswordnew").unwrap());
        assert!(!app.users.check_login("bob", "oldpasswordold").unwrap());
    }

    #[test]
    fn delete_invalidates_sessions_so_a_recreated_user_does_not_inherit_them() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User, &[]).unwrap();
        app.sessions.create("session-1", "bob", Utc::now() + chrono::Duration::days(14)).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_some());

        app.users.delete("bob").unwrap();
        app.users.create("bob", "another-password", UserRole::Admin, &[]).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_none());
    }

    #[test]
    fn delete_removes_sessions_regardless_of_case() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User, &[]).unwrap();
        app.sessions.create("session-1", "BoB", Utc::now() + chrono::Duration::days(14)).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_some());

        app.users.delete("bob").unwrap();
        app.users.create("bob", "another-password", UserRole::User, &[]).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_none());
    }

    #[test]
    fn delete_with_a_non_matching_name_leaves_the_account_alone() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User, &[]).unwrap();
        app.sessions.create("session-1", "bob", Utc::now() + chrono::Duration::days(14)).unwrap();

        // The users row is matched case-sensitively, so this deletes nothing at
        // all — it must not strand the account without its sessions.
        app.users.delete("BoB").unwrap();
        assert!(app.users.get("bob").is_ok());
        assert!(app.sessions.get("session-1").unwrap().is_some());
    }
}
