use crate::app::{SqlitePool, models};
use crate::utils::hash::{hash_password, verify_password};
use crate::utils::validate;
use anyhow::{Context, Result, bail};

#[derive(Clone)]
pub struct LiwanUsers {
    pool: SqlitePool,
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
        // OIDC accounts have a NULL hash; password auth must never succeed for them.
        match hash {
            Some(hash) => Ok(verify_password(password, &hash).is_ok()),
            None => Ok(false),
        }
    }

    /// Get a user by username
    pub fn get(&self, username: &str) -> Result<models::User> {
        let username = username.to_lowercase();
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("select username, password_hash, role, projects, email, auth from users where username = ?")?;
        let user = stmt.query_row([username], row_to_user);
        user.map_err(|_| anyhow::anyhow!("user not found"))
    }

    /// Get all users
    pub fn all(&self) -> Result<Vec<models::User>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("select username, password_hash, role, projects, email, auth from users")?;
        let users = stmt.query_map([], row_to_user)?;
        Ok(users.collect::<Result<Vec<models::User>, rusqlite::Error>>()?)
    }

    /// Look up a user by their OIDC identity.
    pub fn get_by_oidc(&self, issuer: &str, subject: &str) -> Result<Option<models::User>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "select username, password_hash, role, projects, email, auth
             from users where oidc_issuer = ? and oidc_subject = ?",
        )?;
        let user = stmt.query_row(rusqlite::params![issuer, subject], row_to_user);
        user.map(Some).or_else(
            |err| {
                if err == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(err.into()) }
            },
        )
    }

    /// Find-or-create the local user for an OIDC identity. New users get role
    /// `user` and no project access until an admin grants it. Existing users
    /// (matched on issuer+subject) have their email refreshed.
    pub fn provision_oidc(
        &self,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        preferred_username: Option<&str>,
        name: Option<&str>,
    ) -> Result<models::User> {
        if self.get_by_oidc(issuer, subject)?.is_some() {
            let conn = self.pool.get()?;
            // coalesce: a re-login without a verified email must not clear a
            // previously-stored address.
            conn.execute(
                "update users set email = coalesce(?, email) where oidc_issuer = ? and oidc_subject = ?",
                rusqlite::params![email, issuer, subject],
            )?;
            return self.get_by_oidc(issuer, subject)?.context("user vanished after update");
        }

        let base = derive_username_base(preferred_username, email, name, subject);
        let username = self.unique_username(&base)?;
        let conn = self.pool.get()?;
        conn.execute(
            "insert into users (username, password_hash, role, projects, email, oidc_issuer, oidc_subject, auth)
             values (?, NULL, ?, '', ?, ?, ?, 'oidc')",
            rusqlite::params![username, models::UserRole::User.to_string(), email, issuer, subject],
        )?;
        self.get_by_oidc(issuer, subject)?.context("user vanished after insert")
    }

    /// Append a numeric suffix until the username is free.
    fn unique_username(&self, base: &str) -> Result<String> {
        let conn = self.pool.get()?;
        let exists = |name: &str| -> Result<bool> {
            let mut stmt = conn.prepare_cached("select 1 from users where username = ? limit 1")?;
            Ok(stmt.exists([name])?)
        };
        if !exists(base)? {
            return Ok(base.to_string());
        }
        for n in 2..10_000 {
            let mut candidate = format!("{base}-{n}");
            if candidate.len() > 64 {
                candidate = candidate[candidate.len() - 64..].to_string();
            }
            if !exists(&candidate)? {
                return Ok(candidate);
            }
        }
        bail!("could not allocate a unique username for {base}");
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

    /// Update a user's password
    pub fn update_password(&self, username: &str, password: &str) -> Result<()> {
        let conn = self.pool.get()?;
        let password_hash = hash_password(password)?;
        let mut stmt =
            conn.prepare_cached("update users set password_hash = :password_hash where username = :username")?;
        stmt.execute(rusqlite::named_params! { ":password_hash": password_hash, ":username": username })?;
        Ok(())
    }

    /// Delete a user
    pub fn delete(&self, username: &str) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached("delete from users where username = ?")?;
        stmt.execute([username])?;
        Ok(())
    }
}

/// Map a row selecting `username, password_hash, role, projects, email, auth`.
fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<models::User> {
    Ok(models::User {
        username: row.get("username")?,
        role: row.get::<_, String>("role")?.try_into().unwrap_or_default(),
        projects: row.get::<_, String>("projects")?.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
        email: row.get("email")?,
        auth: row.get::<_, String>("auth")?.try_into().unwrap_or_default(),
    })
}

/// Transliterate to ASCII, lowercase, drop quotes, and reduce every run of
/// disallowed chars to a single `-`. Underscores are preserved; `-` separates.
/// May return an empty or short string — the caller decides what to do.
fn slugify(raw: &str) -> String {
    let ascii = deunicode::deunicode(raw).to_lowercase();
    let mut out = String::with_capacity(ascii.len());
    let mut pending_dash = false;
    for c in ascii.chars() {
        match c {
            '\'' | '"' | '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}' => {}
            'a'..='z' | '0'..='9' | '_' => {
                if pending_dash && !out.is_empty() {
                    out.push('-');
                }
                pending_dash = false;
                out.push(c);
            }
            _ => pending_dash = true,
        }
    }
    out
}

/// Build a candidate Liwan username from OIDC claims, preferring
/// preferred_username, then the verified email local-part, then the name, then
/// the subject. The result is an ASCII slug clamped to 3..=64 chars. Always
/// returns a string that passes `is_valid_username`.
pub(crate) fn derive_username_base(
    preferred_username: Option<&str>,
    email: Option<&str>,
    name: Option<&str>,
    subject: &str,
) -> String {
    let candidates = [preferred_username, email.and_then(|e| e.split('@').next()), name];

    let mut base = candidates.into_iter().flatten().map(slugify).find(|s| s.len() >= 3).unwrap_or_default();

    if base.len() < 3 {
        let sub_slug = slugify(subject);
        base = if sub_slug.len() >= 3 { sub_slug } else { format!("user-{sub_slug}") };
    }

    if base.len() > 64 {
        base.truncate(64);
        while base.ends_with('-') {
            base.pop();
        }
    }
    while base.len() < 3 {
        base.push('0');
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Liwan;
    use crate::app::models::{AuthMethod, UserRole};
    use crate::config::Config;

    #[test]
    fn slugify_transforms() {
        assert_eq!(slugify("José Müller"), "jose-muller");
        assert_eq!(slugify("李雷"), "li-lei");
        assert_eq!(slugify("Москва"), "moskva");
        assert_eq!(slugify("O'Brien"), "obrien");
        assert_eq!(slugify("Mike  Simon"), "mike-simon");
        assert_eq!(slugify("  Mike  "), "mike");
        assert_eq!(slugify("Mike Anderson Simon"), "mike-anderson-simon");
        assert_eq!(slugify("bob_smith"), "bob_smith");
        assert_eq!(slugify("Bob+tag"), "bob-tag");
        assert_eq!(slugify("Alice.B"), "alice-b");
    }

    #[test]
    fn derive_username_order_precedence() {
        // preferred beats email beats name beats subject
        assert_eq!(derive_username_base(Some("Alice.B"), Some("x@y.com"), Some("Name"), "sub1"), "alice-b");
        assert_eq!(derive_username_base(None, Some("bob@y.com"), Some("Name"), "sub1"), "bob");
        assert_eq!(derive_username_base(None, Some("a@y.com"), Some("Name"), "sub1"), "name");
        assert_eq!(derive_username_base(None, None, None, "abc-123"), "abc-123");
    }

    #[test]
    fn derive_username_uses_name() {
        assert_eq!(derive_username_base(None, None, Some("Liwan Tester"), "550e8400-uuid"), "liwan-tester");
        assert_eq!(derive_username_base(None, None, Some("Mike Anderson Simon"), "s"), "mike-anderson-simon");
        assert_eq!(derive_username_base(None, None, Some("José Müller"), "s"), "jose-muller");
        assert_eq!(derive_username_base(None, None, Some("李雷"), "s"), "li-lei");
        assert_eq!(derive_username_base(None, None, Some("Москва"), "s"), "moskva");
        assert_eq!(derive_username_base(None, None, Some("O'Brien"), "s"), "obrien");
    }

    #[test]
    fn derive_username_email_local_part() {
        assert_eq!(derive_username_base(None, Some("Bob+tag@y.com"), None, "s"), "bob-tag");
    }

    #[test]
    fn derive_username_preserves_underscore() {
        assert_eq!(derive_username_base(Some("bob_smith"), None, None, "s"), "bob_smith");
    }

    #[test]
    fn derive_username_short_candidate_falls_through() {
        assert_eq!(derive_username_base(Some("ab"), None, None, "abc-123"), "abc-123");
    }

    #[test]
    fn derive_username_pads_short_and_falls_back() {
        assert!(derive_username_base(Some("a"), None, None, "sub").len() >= 3);
        let u = derive_username_base(Some("@@@"), None, None, "f8c9-d0e1");
        assert!(validate::is_valid_username(&u), "got: {u}");
        let u = derive_username_base(None, None, None, "x");
        assert!(validate::is_valid_username(&u), "got: {u}");
    }

    #[test]
    fn provision_creates_then_links_by_sub() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let iss = "https://idp.example.com";
        let u1 = app.users.provision_oidc(iss, "sub-123", Some("a@b.com"), Some("alice"), Some("Alice")).unwrap();
        assert_eq!(u1.auth, AuthMethod::Oidc);
        assert_eq!(u1.email.as_deref(), Some("a@b.com"));
        assert!(u1.projects.is_empty());
        assert_eq!(u1.role, UserRole::User);
        let u2 = app.users.provision_oidc(iss, "sub-123", Some("a@b.com"), Some("alice"), Some("Alice")).unwrap();
        assert_eq!(u1.username, u2.username);
        assert_eq!(app.users.all().unwrap().len(), 1);
    }

    #[test]
    fn provision_relogin_without_email_keeps_stored_email() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let iss = "https://idp.example.com";
        app.users.provision_oidc(iss, "sub-1", Some("a@b.com"), Some("alice"), None).unwrap();
        // A later login without a verified email must not wipe the stored one.
        let u = app.users.provision_oidc(iss, "sub-1", None, Some("alice"), None).unwrap();
        assert_eq!(u.email.as_deref(), Some("a@b.com"));
    }

    #[test]
    fn provision_avoids_username_collision() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("alice", "password", UserRole::User, &[]).unwrap();
        let u = app.users.provision_oidc("https://idp", "sub-x", None, Some("alice"), None).unwrap();
        assert_ne!(u.username, "alice");
        assert!(u.username.starts_with("alice"));
    }

    #[test]
    fn provision_suffixes_name_collisions() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let iss = "https://idp.example.com";
        let u1 = app.users.provision_oidc(iss, "sub-a", None, None, Some("Liwan Tester")).unwrap();
        let u2 = app.users.provision_oidc(iss, "sub-b", None, None, Some("Liwan Tester")).unwrap();
        assert_eq!(u1.username, "liwan-tester");
        assert_eq!(u2.username, "liwan-tester-2");
    }

    #[test]
    fn check_login_rejects_oidc_user() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.provision_oidc("https://idp", "sub-y", Some("c@d.com"), Some("carol"), None).unwrap();
        assert!(!app.users.check_login("carol", "").unwrap_or(false));
        assert!(!app.users.check_login("carol", "anything").unwrap_or(false));
    }
}
