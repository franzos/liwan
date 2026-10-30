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
    /// The current password did not match, or the hash changed concurrently.
    CurrentPasswordRejected,
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
        let mut stmt = conn.prepare("select username, role from users where username = ?")?;
        let user = stmt.query_row([username], |row| {
            Ok(models::User {
                username: row.get("username")?,
                role: row.get::<_, String>("role")?.try_into().unwrap_or_default(),
                access: models::Access::default(),
            })
        });
        user.map_err(|_| anyhow::anyhow!("user not found"))
    }

    /// Get all users
    pub fn all(&self) -> Result<Vec<models::User>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("select username, role from users")?;
        let users = stmt.query_map([], |row| {
            Ok(models::User {
                username: row.get("username")?,
                role: row.get::<_, String>("role")?.try_into().unwrap_or_default(),
                access: models::Access::default(),
            })
        })?;
        Ok(users.collect::<Result<Vec<models::User>, rusqlite::Error>>()?)
    }

    /// Create a new user
    pub fn create(&self, username: &str, password: &str, role: models::UserRole) -> Result<()> {
        if !validate::is_valid_username(username) {
            bail!("invalid username");
        }
        let username = username.to_lowercase();
        let password_hash = hash_password(password)?;
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached(
            "insert into users (username, password_hash, role) values (:username, :password_hash, :role)",
        )?;
        stmt.execute(rusqlite::named_params! {
            ":username": username,
            ":password_hash": password_hash,
            ":role": role.to_string(),
        })?;
        Ok(())
    }

    /// Update a user's role and team memberships atomically.
    pub fn update(&self, username: &str, role: models::UserRole, team_ids: &[String]) -> Result<bool> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        if tx.execute("update users set role = ? where username = ?", rusqlite::params![role.to_string(), username])?
            == 0
        {
            return Ok(false);
        }
        let team_ids_json = serde_json::to_string(team_ids)?;
        let missing: Option<String> = tx
            .query_row(
                "select value from json_each(?) where value not in (select id from teams) limit 1",
                [&team_ids_json],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(team_id) = missing {
            bail!("team not found: {team_id}");
        }
        tx.execute("delete from team_users where username = ?", [username])?;
        tx.execute(
            "insert into team_users (team_id, username) select distinct value, ? from json_each(?)",
            rusqlite::params![username, team_ids_json],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Update a password and revoke other sessions. CLI resets may omit the current password and session.
    ///
    /// Refuses SSO-only accounts: a local password on one is a login path that
    /// outlives IdP deactivation and MFA, while the UI still reports SSO-only.
    /// The break-glass for a locked-out SSO admin is `liwan add-user`.
    pub fn update_password(
        &self,
        username: &str,
        password: &str,
        current_password: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<PasswordUpdateOutcome> {
        let username = username.to_lowercase();
        let Some(previous_hash) = self
            .pool
            .get()?
            .query_row("select password_hash from users where username = ?", [&username], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()?
        else {
            return Ok(PasswordUpdateOutcome::UserNotFound);
        };
        let Some(previous_hash) = previous_hash else {
            return Ok(PasswordUpdateOutcome::NotPasswordAuth);
        };
        if let Some(current_password) = current_password
            && verify_password(current_password, &previous_hash).is_err()
        {
            return Ok(PasswordUpdateOutcome::CurrentPasswordRejected);
        }
        let password_hash = hash_password(password)?;
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        if tx.execute(
            "update users set password_hash = ? where username = ? and password_hash is ?",
            rusqlite::params![password_hash, username, previous_hash],
        )? == 0
        {
            return Ok(PasswordUpdateOutcome::CurrentPasswordRejected);
        }
        tx.execute(
            "delete from sessions where lower(username) = ? and id != ?",
            [&username, session_id.unwrap_or_default()],
        )?;
        tx.commit()?;
        Ok(PasswordUpdateOutcome::Updated)
    }

    /// Delete a user, their team memberships and every session issued to them.
    /// Sessions join to users on `lower(username)`, so leaving them behind hands
    /// the account to whoever takes the name next. They are cleared only once the
    /// row is really gone, so a name that matches nothing is a no-op.
    pub fn delete(&self, username: &str) -> Result<()> {
        let username = username.to_lowercase();
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        if tx.execute("delete from users where username = ?", [&username])? > 0 {
            tx.execute("delete from sessions where lower(username) = lower(?)", [&username])?;
            tx.execute("delete from team_users where username = ?", [&username])?;
        }
        tx.commit()?;
        Ok(())
    }
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
            .execute("insert into users (username, password_hash, role) values ('alice', null, 'user')", [])
            .unwrap();

        assert_eq!(
            app.users.update_password("alice", "newpasswordnew", None, None).unwrap(),
            PasswordUpdateOutcome::NotPasswordAuth
        );
        assert_eq!(
            app.users.update_password("alice", "newpasswordnew", Some("anything"), None).unwrap(),
            PasswordUpdateOutcome::NotPasswordAuth
        );
        // Still no local login path.
        assert!(!app.users.check_login("alice", "newpasswordnew").unwrap());
    }

    #[test]
    fn update_password_reports_unknown_user() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        assert_eq!(
            app.users.update_password("nobody", "newpasswordnew", None, None).unwrap(),
            PasswordUpdateOutcome::UserNotFound
        );
    }

    #[test]
    fn update_password_updates_password_account() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "oldpasswordold", UserRole::User).unwrap();

        assert_eq!(
            app.users.update_password("bob", "newpasswordnew", None, None).unwrap(),
            PasswordUpdateOutcome::Updated
        );
        assert!(app.users.check_login("bob", "newpasswordnew").unwrap());
        assert!(!app.users.check_login("bob", "oldpasswordold").unwrap());
    }

    #[test]
    fn update_password_rejects_a_wrong_current_password() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "oldpasswordold", UserRole::User).unwrap();

        assert_eq!(
            app.users.update_password("bob", "newpasswordnew", Some("wrongpassword"), None).unwrap(),
            PasswordUpdateOutcome::CurrentPasswordRejected
        );
        assert!(app.users.check_login("bob", "oldpasswordold").unwrap());
    }

    #[test]
    fn delete_invalidates_sessions_so_a_recreated_user_does_not_inherit_them() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User).unwrap();
        app.sessions.create("session-1", "bob", Utc::now() + chrono::Duration::days(14)).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_some());

        app.users.delete("bob").unwrap();
        app.users.create("bob", "another-password", UserRole::Admin).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_none());
    }

    #[test]
    fn delete_removes_sessions_regardless_of_case() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User).unwrap();
        app.sessions.create("session-1", "BoB", Utc::now() + chrono::Duration::days(14)).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_some());

        app.users.delete("bob").unwrap();
        app.users.create("bob", "another-password", UserRole::User).unwrap();
        assert!(app.sessions.get("session-1").unwrap().is_none());
    }

    #[test]
    fn delete_removes_team_memberships() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User).unwrap();
        let team = app.teams.create("Editors").unwrap();
        app.users.update("bob", UserRole::User, std::slice::from_ref(&team)).unwrap();

        app.users.delete("bob").unwrap();
        app.users.create("bob", "another-password", UserRole::User).unwrap();
        assert!(app.teams.all().unwrap().iter().all(|team| team.users.is_empty()));
    }

    #[test]
    fn delete_with_a_non_matching_name_leaves_sessions_alone() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("bob", "password", UserRole::User).unwrap();
        app.sessions.create("session-1", "bob", Utc::now() + chrono::Duration::days(14)).unwrap();
        app.sessions.create("session-2", "carol", Utc::now() + chrono::Duration::days(14)).unwrap();

        app.users.delete("carol").unwrap();
        assert!(app.users.get("bob").is_ok());
        assert!(app.sessions.get("session-1").unwrap().is_some());
        let orphans: u32 = app
            .users
            .pool
            .get()
            .unwrap()
            .query_row("select count(*) from sessions where username = 'carol'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(orphans, 1);
    }
}
