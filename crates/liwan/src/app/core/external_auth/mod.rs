use crate::{
    app::{SqlitePool, models::UserRole},
    config::{Config, GroupsConfig, ProviderConfig, ProviderKind},
    utils::validate,
};
mod forseti;
mod http;
mod keys;
mod logout;
mod policy;
mod provider;

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, TransactionBehavior};

use provider::{FlowSecret, Provider};

pub use forseti::{MAX_WEBHOOK_BODY, SET_CONTENT_TYPE, WebhookError};
pub use logout::MAX_LOGOUT_BODY;
pub use policy::{Rejection, email_domain};

/// Everything a verified ID token told us about the person signing in.
/// `email` is only ever set when the provider marked it verified.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ExternalIdentity {
    provider_key: String,
    subject: String,
    email: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
    /// Google's Workspace domain.
    hd: Option<String>,
    /// Microsoft's tenant.
    tid: Option<String>,
    /// The IdP's session id, for back-channel logout.
    sid: Option<String>,
    /// Absent claim is `None`; a present one is the list, however short.
    groups: Option<Vec<String>>,
    /// The IdP marked the configured group claim as incomplete.
    groups_overage: bool,
}

const FLOW_LIFETIME: Duration = Duration::from_secs(10 * 60);
const PROVIDER_CACHE_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// A browser that starts more login flows than this is not a browser.
const MAX_PENDING_FLOWS: usize = 256;

/// A newly created provider authorization request.
#[derive(Debug)]
pub struct ExternalAuthStart {
    pub authorization_url: url::Url,
    pub state: String,
}

/// The local account and redirect resolved by a successful provider callback.
#[derive(Debug)]
pub struct ExternalAuthLogin {
    pub username: String,
    pub return_to: String,
    /// The IdP's session id, stored on the session so back-channel logout can
    /// end this device and no other.
    pub sid: Option<String>,
}

/// What a caller needs to tell apart: a name nobody configured, a person the
/// policy turned away, and everything else.
#[derive(Debug)]
pub enum ExternalAuthError {
    UnknownProvider,
    Rejected(Rejection),
    /// A webhook delivery that did not verify. Every one of these is one 400
    /// without a body; the reason stays in the log.
    Webhook(WebhookError),
    Failed(anyhow::Error),
}

fn webhook_error(reason: impl Into<String>) -> ExternalAuthError {
    ExternalAuthError::Webhook(WebhookError::Invalid(reason.into()))
}

impl std::fmt::Display for ExternalAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProvider => formatter.write_str("no such external authentication provider"),
            Self::Rejected(rejection) => write!(formatter, "external authentication rejected: {rejection}"),
            Self::Webhook(error) => write!(formatter, "{error}"),
            Self::Failed(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for ExternalAuthError {}

impl From<anyhow::Error> for ExternalAuthError {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

impl From<Rejection> for ExternalAuthError {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}

impl ExternalAuthError {
    /// The `externalAuthError` code the login page maps to a message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Rejected(rejection) => rejection.code(),
            _ => "unavailable",
        }
    }
}

/// What [`LiwanExternalAuth::link`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    Linked,
    UserNotFound,
    /// Another account already answers to this issuer and subject.
    SubjectHeldBy(String),
    /// The holder has a local password, so it is a real account rather than an
    /// auto-provisioned duplicate, and is not replaced.
    HolderHasPassword(String),
}

/// How an account signs in, for the settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAccount {
    pub provider_name: String,
    pub display_name: String,
    /// Where the person manages the account at the IdP, when it offers one.
    pub manage_url: Option<String>,
}

/// A provider and, for `kind = "forseti"`, the portal's own document.
struct BuiltProvider {
    provider: Arc<Provider>,
    forseti: Option<Arc<forseti::ForsetiConfiguration>>,
}

struct PendingFlow {
    provider_name: String,
    provider: Arc<Provider>,
    secret: FlowSecret,
    return_to: String,
    expires_at: Instant,
}

struct CachedProvider {
    provider: Arc<Provider>,
    /// `None` when the portal's document was unreachable or unusable; the
    /// extras stay off until the next rebuild, but login keeps working.
    forseti: Option<Arc<forseti::ForsetiConfiguration>>,
    created_at: Instant,
}

struct RuntimeState {
    http: reqwest::Client,
    base_url: String,
    redirect_url: String,
    providers: BTreeMap<String, ProviderConfig>,
    cache: Mutex<HashMap<String, CachedProvider>>,
    cache_lifetime: Duration,
    flows: Mutex<HashMap<String, PendingFlow>>,
    /// Outlives the provider cache: Forseti's JWKS is good for a day and is
    /// refetched on a `kid` miss, not on a timer.
    webhook_jwks: HashMap<String, forseti::WebhookJwks>,
    /// Shared by the deletion webhook and back-channel logout; the event ids
    /// cannot collide across the two.
    seen_events: forseti::JtiCache,
}

/// Runs the configured external login flows and owns the local identities they
/// map onto.
#[derive(Clone)]
pub struct LiwanExternalAuth {
    pool: SqlitePool,
    sessions: super::LiwanSessions,
    runtime: Arc<RuntimeState>,
}

impl LiwanExternalAuth {
    /// Creates the external authentication service and its restricted HTTP client.
    pub fn try_new(pool: SqlitePool, config: &Config) -> Result<Self> {
        let redirect_url =
            config.external_auth_redirect_uri().context("invalid base URL for the external auth redirect")?.to_string();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            sessions: super::LiwanSessions::new(pool.clone()),
            pool,
            runtime: Arc::new(RuntimeState {
                http,
                base_url: config.base_url.clone(),
                redirect_url,
                webhook_jwks: config
                    .oidc
                    .providers
                    .keys()
                    .map(|name| (name.clone(), forseti::WebhookJwks::default()))
                    .collect(),
                providers: config.oidc.providers.clone(),
                cache: Mutex::new(HashMap::new()),
                cache_lifetime: PROVIDER_CACHE_LIFETIME,
                flows: Mutex::new(HashMap::new()),
                seen_events: forseti::JtiCache::default(),
            }),
        })
    }

    /// The configured providers, in config order, for the login page.
    pub fn providers(&self) -> impl Iterator<Item = (&String, &ProviderConfig)> {
        self.runtime.providers.iter()
    }

    pub fn is_configured(&self) -> bool {
        !self.runtime.providers.is_empty()
    }

    /// The callback URL that must be registered with every provider.
    pub fn callback_url(&self) -> &str {
        &self.runtime.redirect_url
    }

    /// Starts a short-lived external login flow against a named provider.
    pub async fn begin(&self, provider_name: &str, return_to: &str) -> Result<ExternalAuthStart, ExternalAuthError> {
        if !self.runtime.providers.contains_key(provider_name) {
            return Err(ExternalAuthError::UnknownProvider);
        }
        let return_to =
            local_return_path(return_to).context("invalid return path").map_err(ExternalAuthError::Failed)?;
        let provider = self.provider(provider_name).await?.provider;
        let authorization = provider.authorize();

        let mut flows = self.runtime.flows.lock().expect("external auth flow lock poisoned");
        let now = Instant::now();
        flows.retain(|_, flow| flow.expires_at > now);
        if flows.len() >= MAX_PENDING_FLOWS
            && let Some(oldest) = flows.iter().min_by_key(|(_, flow)| flow.expires_at).map(|(state, _)| state.clone())
        {
            flows.remove(&oldest);
        }
        flows.insert(
            authorization.state.clone(),
            PendingFlow {
                provider_name: provider_name.to_string(),
                provider,
                secret: authorization.secret,
                return_to,
                expires_at: now + FLOW_LIFETIME,
            },
        );
        Ok(ExternalAuthStart { authorization_url: authorization.url, state: authorization.state })
    }

    /// Consumes a login flow and resolves it to a local Liwan account.
    pub async fn finish(&self, state: &str, code: String) -> Result<ExternalAuthLogin, ExternalAuthError> {
        // Removing before the token exchange makes every callback attempt
        // one-use, including the ones that fail.
        let flow = self
            .runtime
            .flows
            .lock()
            .expect("external auth flow lock poisoned")
            .remove(state)
            .context("external authentication flow not found or already used")?;
        if flow.expires_at <= Instant::now() {
            return Err(anyhow::anyhow!("external authentication flow expired").into());
        }

        // The provider list is fixed at startup, so a flow can only outlive its
        // own provider through a restart, which also clears the flows.
        let provider_config =
            self.runtime.providers.get(&flow.provider_name).ok_or(ExternalAuthError::UnknownProvider)?;
        let identity = flow.provider.complete(code, flow.secret, &self.runtime.http).await?;

        if let Err(rejection) = policy::evaluate_access(provider_config, &identity) {
            tracing::warn!(
                provider = %flow.provider_name,
                subject = %identity.subject,
                %rejection,
                "external authentication denied",
            );
            if rejection.revokes_access()
                && let Err(error) = self.revoke_access(&identity.provider_key, &identity.subject)
            {
                tracing::error!(provider = %flow.provider_name, error = %format!("{error:#}"), "could not revoke access");
            }
            return Err(rejection.into());
        }

        let existing = self.find_user(&identity.provider_key, &identity.subject)?;
        policy::evaluate_registration(provider_config.registration, existing.is_some()).inspect_err(|rejection| {
            tracing::warn!(
                provider = %flow.provider_name,
                subject = %identity.subject,
                %rejection,
                "external authentication denied",
            );
        })?;

        let username = match existing {
            Some(username) => username,
            None => self.create_user(&identity)?,
        };

        if let Some(groups) = provider_config.groups.as_ref() {
            self.sync_access(&username, groups, identity.groups.as_deref().unwrap_or_default())?;
        }

        // Scoped to the issuer, so two providers cannot hand out the same
        // session id and end each other's sessions.
        let sid = identity.sid.as_deref().map(|sid| scoped_sid(&identity.provider_key, sid));
        Ok(ExternalAuthLogin { username, return_to: flow.return_to, sid })
    }

    /// Cancels an in-progress login flow.
    pub fn cancel(&self, state: &str) {
        self.runtime.flows.lock().expect("external auth flow lock poisoned").remove(state);
    }

    /// The built provider for a configured name. Discovery runs once per cache
    /// lifetime, which is also how often the JWKS is refreshed.
    async fn provider(&self, name: &str) -> Result<BuiltProvider, ExternalAuthError> {
        let config = self.runtime.providers.get(name).ok_or(ExternalAuthError::UnknownProvider)?;

        if let Some(built) = self
            .runtime
            .cache
            .lock()
            .expect("external auth provider lock poisoned")
            .get(name)
            .filter(|cached| cached.created_at.elapsed() < self.runtime.cache_lifetime)
            .map(|cached| BuiltProvider { provider: cached.provider.clone(), forseti: cached.forseti.clone() })
        {
            return Ok(built);
        }

        let provider = Arc::new(Provider::from_config(config, &self.runtime.redirect_url, &self.runtime.http).await?);
        let forseti = match config.portal_url() {
            Some(portal_url) => match forseti::fetch(&portal_url, &self.runtime.http).await {
                Ok(document) => Some(Arc::new(document)),
                Err(error) => {
                    // The account link and the deletion webhook go quiet, but
                    // people can still sign in.
                    tracing::warn!(provider = %name, %error, "Forseti discovery failed; its extras stay off");
                    None
                }
            },
            None => None,
        };

        self.runtime.cache.lock().expect("external auth provider lock poisoned").insert(
            name.to_string(),
            CachedProvider { provider: provider.clone(), forseti: forseti.clone(), created_at: Instant::now() },
        );
        Ok(BuiltProvider { provider, forseti })
    }

    /// Handles Forseti's `account-purged` security event token.
    ///
    /// The account is deleted outright when it only ever signed in through the
    /// IdP. One with a local password keeps working as a local account; only the
    /// link goes.
    pub async fn handle_account_purged(&self, name: &str, body: &[u8]) -> Result<(), ExternalAuthError> {
        let config = self.runtime.providers.get(name).ok_or(ExternalAuthError::UnknownProvider)?;
        if config.kind != ProviderKind::Forseti {
            return Err(ExternalAuthError::UnknownProvider);
        }
        let portal_url = config.portal_url().ok_or(ExternalAuthError::UnknownProvider)?;
        let token = std::str::from_utf8(body).map_err(|_| webhook_error("body is not valid UTF-8"))?.trim();

        let built = self.provider(name).await?;
        let jwks_uri = built
            .forseti
            .as_ref()
            .and_then(|document| document.webhook_jwks_uri.clone())
            .ok_or(ExternalAuthError::UnknownProvider)?;
        forseti::validate_jwks_uri(&jwks_uri, &portal_url).map_err(|error| webhook_error(format!("{error:#}")))?;

        let kid = forseti::token_kid(token).map_err(ExternalAuthError::Webhook)?;
        let key = self
            .runtime
            .webhook_jwks
            .get(name)
            .ok_or(ExternalAuthError::UnknownProvider)?
            .key_for(&kid, &jwks_uri, &self.runtime.http)
            .await
            .map_err(|error| webhook_error(format!("no usable signing key: {error:#}")))?;

        let purged =
            forseti::verify_account_purged(token, &key, &portal_url, &config.client_id, chrono::Utc::now().timestamp())
                .map_err(ExternalAuthError::Webhook)?;

        // A retry of a delivery we already applied is a 200, not a second delete.
        if !self.runtime.seen_events.insert(&format!("purge:{name}:{}", purged.jti)) {
            tracing::debug!(provider = %name, jti = %purged.jti, "account deletion event already handled");
            return Ok(());
        }

        self.purge_identity(built.provider.provider_key(), &purged.subject)?;
        Ok(())
    }

    /// Handles an OpenID Connect back-channel logout token.
    ///
    /// With a `sid` this ends the one session the IdP signed out. Without one,
    /// every session the subject has goes, password logins included: the IdP has
    /// told us it no longer vouches for that person at all.
    pub async fn handle_backchannel_logout(&self, name: &str, token: &str) -> Result<(), ExternalAuthError> {
        let config = self.runtime.providers.get(name).ok_or(ExternalAuthError::UnknownProvider)?;
        let token = token.trim();

        let mut built = self.provider(name).await?;
        let (algorithm, kid) =
            logout::token_header(token, built.provider.signing_algorithms()).map_err(ExternalAuthError::Webhook)?;

        let key = match keys::select(built.provider.jwks(), kid.as_deref(), algorithm) {
            Some(key) => key,
            None => {
                // A key we have never seen means the IdP rotated. Rebuild rather
                // than refuse a legitimate logout, but keep the cached provider
                // in place until the replacement is in hand: this is an
                // unauthenticated caller and logins use the same entry.
                built = self.rebuild_provider(name).await?;
                keys::select(built.provider.jwks(), kid.as_deref(), algorithm)
                    .ok_or_else(|| webhook_error("no provider key matches the logout token"))?
            }
        };

        let request = logout::verify_logout_token(
            token,
            &key,
            algorithm,
            built.provider.provider_key(),
            &config.client_id,
            chrono::Utc::now().timestamp(),
        )
        .map_err(ExternalAuthError::Webhook)?;

        // A retried delivery must not end a session the person has since started.
        // A token without a `jti` dedupes on its own digest rather than on the
        // whole token, which would otherwise sit in memory at 16 KiB a time.
        let event = if request.jti.is_empty() {
            blake3::hash(token.as_bytes()).to_hex().to_string()
        } else {
            request.jti.clone()
        };
        if !self.runtime.seen_events.insert(&format!("logout:{name}:{event}")) {
            tracing::debug!(provider = %name, "back-channel logout already handled");
            return Ok(());
        }

        let ended = match request.sid.as_deref() {
            Some(sid) => self.sessions.delete_by_external_sid(&scoped_sid(built.provider.provider_key(), sid))?,
            None => {
                let subject = request.sub.as_deref().expect("verify requires sub or sid");
                match self.find_user(built.provider.provider_key(), subject)? {
                    Some(username) => self.sessions.revoke_user(&username)?,
                    // Nothing to do: we never had this person, or they are gone.
                    None => 0,
                }
            }
        };
        if ended == 0 {
            // Either the person was already signed out here, or their session
            // predates the `sid` column, or the IdP sent a `sid` we never stored.
            tracing::warn!(provider = %name, "back-channel logout matched no session");
        } else {
            tracing::info!(provider = %name, ended, "ended sessions on back-channel logout");
        }
        Ok(())
    }

    /// Discards the cached provider only once its replacement is in hand, so an
    /// unauthenticated caller cannot leave logins without a provider to use.
    async fn rebuild_provider(&self, name: &str) -> Result<BuiltProvider, ExternalAuthError> {
        let config = self.runtime.providers.get(name).ok_or(ExternalAuthError::UnknownProvider)?;
        let provider = Arc::new(Provider::from_config(config, &self.runtime.redirect_url, &self.runtime.http).await?);
        let forseti = self
            .runtime
            .cache
            .lock()
            .expect("external auth provider lock poisoned")
            .get(name)
            .and_then(|cached| cached.forseti.clone());
        self.runtime.cache.lock().expect("external auth provider lock poisoned").insert(
            name.to_string(),
            CachedProvider { provider: provider.clone(), forseti: forseti.clone(), created_at: Instant::now() },
        );
        Ok(BuiltProvider { provider, forseti })
    }

    /// Attach an IdP identity to an account that already exists, so the next
    /// sign-in lands on it instead of provisioning a second one. The account
    /// keeps its role, its teams and, if it has one, its password.
    ///
    /// With `replace`, an SSO-provisioned account already holding the subject
    /// (the usual case: someone signed in before being linked) is deleted along
    /// with its sessions. One with a local password never is.
    pub fn link(&self, username: &str, issuer: &str, subject: &str, replace: bool) -> Result<LinkOutcome> {
        let mut conn = self.pool.get()?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if !transaction.prepare_cached("select 1 from users where username = ?")?.exists([username])? {
            return Ok(LinkOutcome::UserNotFound);
        }

        let holder: Option<(String, Option<String>)> = transaction
            .prepare_cached(
                "select i.username, u.password_hash from external_identities i
                 join users u on u.username = i.username
                 where i.provider_key = ? and i.subject = ?",
            )?
            .query_row([issuer, subject], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;

        if let Some((holder, password_hash)) = holder {
            if holder == username {
                return Ok(LinkOutcome::Linked);
            }
            if !replace {
                return Ok(LinkOutcome::SubjectHeldBy(holder));
            }
            if password_hash.is_some() {
                return Ok(LinkOutcome::HolderHasPassword(holder));
            }
            // The identity row cascades with the user.
            transaction.execute("delete from users where username = ?", [&holder])?;
            transaction.execute("delete from sessions where lower(username) = lower(?)", [&holder])?;
            transaction.execute("delete from team_users where username = ?", [&holder])?;
        }

        // `(provider_key, username)` is unique too, so re-linking the same
        // account to a new subject replaces the old row rather than failing.
        transaction
            .execute("delete from external_identities where provider_key = ? and username = ?", [issuer, username])?;
        transaction.execute(
            "insert into external_identities (provider_key, subject, username) values (?, ?, ?)",
            [issuer, subject, username],
        )?;
        transaction.commit()?;
        Ok(LinkOutcome::Linked)
    }

    /// Removes an identity, and the account with it when that account has no
    /// other way in.
    fn purge_identity(&self, provider_key: &str, subject: &str) -> Result<()> {
        let mut conn = self.pool.get()?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let row: Option<(String, Option<String>)> = transaction
            .query_row(
                "select i.username, u.password_hash from external_identities i
                 join users u on u.username = i.username
                 where i.provider_key = ? and i.subject = ?",
                [provider_key, subject],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((username, password_hash)) = row else {
            tracing::debug!(%provider_key, "account deletion event names an identity we do not have");
            return Ok(());
        };

        if password_hash.is_some() {
            // The account predates SSO or was attached with `link-oidc`. Losing
            // the IdP should not lose the account.
            transaction.execute(
                "delete from external_identities where provider_key = ? and subject = ?",
                [provider_key, subject],
            )?;
            transaction.commit()?;
            tracing::info!(%username, "unlinked an account whose IdP identity was deleted");
            return Ok(());
        }

        // The identity row goes with the user through the cascade.
        transaction.execute("delete from users where username = ?", [&username])?;
        transaction.execute("delete from sessions where lower(username) = lower(?)", [&username])?;
        transaction.execute("delete from team_users where username = ?", [&username])?;
        transaction.commit()?;
        tracing::info!(%username, "deleted an account whose IdP identity was deleted");
        Ok(())
    }

    /// The provider an account signs in through, if it has an identity at all.
    /// Drives the settings page: an SSO account has no password form, and gets a
    /// link out to the IdP instead.
    pub async fn account_for(&self, username: &str) -> Result<Option<ExternalAccount>> {
        let conn = self.pool.get()?;
        let provider_key: Option<String> = conn
            .query_row(
                "select provider_key from external_identities where username = ? order by provider_key limit 1",
                [username],
                |row| row.get(0),
            )
            .optional()?;
        let Some(provider_key) = provider_key else {
            return Ok(None);
        };

        // Identities are keyed on the discovered issuer, so a provider that was
        // renamed still matches; one that was removed falls back to the issuer.
        let matched = self
            .runtime
            .providers
            .iter()
            .find(|(_, provider)| provider.issuer_url().is_ok_and(|issuer| same_issuer(&issuer, &provider_key)));
        let Some((name, provider)) = matched else {
            // A provider that has since been taken out of the config entirely.
            return Ok(Some(ExternalAccount {
                provider_name: provider_key.clone(),
                display_name: provider_key,
                manage_url: None,
            }));
        };

        // Only Forseti advertises somewhere to send people; for anything else
        // this would be an IdP round-trip for nothing.
        let manage_url = if provider.kind == ProviderKind::Forseti {
            match self.provider(name).await {
                Ok(built) => built
                    .forseti
                    .as_ref()
                    .and_then(|document| forseti::manage_url(document, &provider.client_id, &self.runtime.base_url)),
                Err(error) => {
                    tracing::debug!(provider = %name, %error, "could not resolve the manage-account link");
                    None
                }
            }
        } else {
            None
        };

        Ok(Some(ExternalAccount {
            provider_name: name.clone(),
            display_name: provider.display_name().to_string(),
            manage_url,
        }))
    }

    fn find_user(&self, provider_key: &str, subject: &str) -> Result<Option<String>> {
        let conn = self.pool.get()?;
        Ok(conn
            .query_row(
                "select username from external_identities where provider_key = ? and subject = ?",
                [provider_key, subject],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn create_user(&self, identity: &ExternalIdentity) -> Result<String> {
        if identity.provider_key.is_empty() || identity.subject.is_empty() {
            bail!("external identity is missing a stable identifier");
        }

        let mut conn = self.pool.get()?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(username) = transaction
            .query_row(
                "select username from external_identities where provider_key = ? and subject = ?",
                [&identity.provider_key, &identity.subject],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(username);
        }

        let base = derive_username_base(
            identity.preferred_username.as_deref(),
            identity.email.as_deref(),
            identity.name.as_deref(),
            &identity.subject,
        );
        let username = {
            let mut exists = transaction.prepare_cached("select 1 from users where username = ? limit 1")?;
            let mut candidate = base.clone();
            let mut attempt = 1;
            loop {
                if validate::is_valid_username(&candidate) && !exists.exists([&candidate])? {
                    break candidate;
                }
                attempt += 1;
                if attempt > 10_000 {
                    bail!("could not allocate a unique username for {base}");
                }
                candidate = format!("{base}-{attempt}");
                if candidate.len() > 64 {
                    candidate = candidate[candidate.len() - 64..].to_string();
                }
            }
        };

        transaction.execute(
            "insert into users (username, password_hash, role) values (?, null, ?)",
            rusqlite::params![username, UserRole::User.to_string()],
        )?;
        transaction.execute(
            "insert into external_identities (provider_key, subject, username) values (?, ?, ?)",
            rusqlite::params![identity.provider_key, identity.subject, username],
        )?;
        transaction.commit()?;
        Ok(username)
    }

    /// Applies the group mapping to an SSO-only account: the role, and team
    /// membership replaced by what the mapping grants. Accounts with a local
    /// password are left alone.
    fn sync_access(&self, username: &str, config: &GroupsConfig, groups: &[String]) -> Result<()> {
        let (role, teams) = policy::resolve_role_and_teams(config, groups);
        let teams = serde_json::to_string(&teams)?;

        let mut conn = self.pool.get()?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let unknown: Vec<String> = transaction
            .prepare_cached("select value from json_each(?) where value not in (select id from teams)")?
            .query_map([&teams], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if !unknown.is_empty() {
            tracing::warn!(
                %username,
                teams = %unknown.join(", "),
                "group mapping names teams that do not exist; skipping them",
            );
        }

        let password_hash: Option<Option<String>> = transaction
            .query_row("select password_hash from users where username = ?", [username], |row| row.get(0))
            .optional()?;
        match password_hash {
            None => bail!("account {username} no longer exists"),
            Some(Some(_)) => {
                transaction.rollback()?;
                tracing::debug!(%username, "account has a local password; group mapping left it alone");
                return Ok(());
            }
            Some(None) => {}
        }

        transaction.execute(
            "update users set role = ? where username = ? and password_hash is null",
            rusqlite::params![role.to_string(), username],
        )?;

        transaction.execute("delete from team_users where username = ?", [username])?;
        let joined = transaction.execute(
            "insert into team_users (team_id, username)
             select value, ? from json_each(?) where value in (select id from teams)",
            rusqlite::params![username, teams],
        )?;
        transaction.commit()?;
        tracing::debug!(%username, %role, teams = joined, "applied group mapping");
        Ok(())
    }

    /// Ends the sessions and team memberships of the SSO-only account behind an
    /// identity the policy just turned away, and drops its role to `user`.
    fn revoke_access(&self, provider_key: &str, subject: &str) -> Result<()> {
        let mut conn = self.pool.get()?;
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let username: Option<String> = transaction
            .query_row(
                "select u.username from external_identities i
                 join users u on u.username = i.username
                 where i.provider_key = ? and i.subject = ? and u.password_hash is null",
                [provider_key, subject],
                |row| row.get(0),
            )
            .optional()?;
        let Some(username) = username else {
            return Ok(());
        };

        let sessions = transaction.execute("delete from sessions where lower(username) = lower(?)", [&username])?;
        let teams = transaction.execute("delete from team_users where username = ?", [&username])?;
        let user = UserRole::User.to_string();
        let demoted = transaction.execute(
            "update users set role = ? where username = ? and password_hash is null and role != ?",
            [&user, &username, &user],
        )? > 0;
        transaction.commit()?;
        tracing::info!(%username, sessions, teams, demoted, "revoked access after a rejected login");
        Ok(())
    }

    /// Test-only: read the nonce for a pending flow without consuming it, so a
    /// test can mint an ID token the flow will accept.
    #[cfg(any(test, feature = "__dev"))]
    pub fn peek_nonce(&self, state: &str) -> Option<String> {
        let flows = self.runtime.flows.lock().expect("external auth flow lock poisoned");
        flows.get(state).map(|flow| flow.secret.nonce_secret())
    }
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

/// Build a candidate Liwan username from the ID token's claims, preferring
/// preferred_username, then the verified email local-part, then the name, then
/// the subject. The result is an ASCII slug clamped to 3..=64 chars. Always
/// returns a string that passes `is_valid_username`.
fn derive_username_base(
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

/// A session id is only unique within its own issuer, so the stored value
/// carries both. Two providers cannot then end each other's sessions by issuing
/// the same string. The separator is a control character, which cannot appear in
/// an issuer URL.
fn scoped_sid(provider_key: &str, sid: &str) -> String {
    format!("{provider_key}{SID_SEPARATOR}{sid}")
}

const SID_SEPARATOR: char = '\u{1f}';

/// Issuers are compared as URLs: the configured string and the one discovery
/// reported often differ only in a trailing slash.
fn same_issuer(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn local_return_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return None;
    }

    let base = url::Url::parse("http://liwan.invalid").expect("valid return path base");
    let target = base.join(path).ok()?;
    if target.origin() != base.origin() {
        return None;
    }

    let mut normalized = target.path().to_string();
    if let Some(query) = target.query() {
        normalized.push('?');
        normalized.push_str(query);
    }
    if let Some(fragment) = target.fragment() {
        normalized.push('#');
        normalized.push_str(fragment);
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{app::Liwan, config::Config};

    fn identity(subject: &str, username_hint: Option<&str>) -> ExternalIdentity {
        ExternalIdentity {
            provider_key: "https://issuer.example".to_string(),
            subject: subject.to_string(),
            preferred_username: username_hint.map(str::to_string),
            ..Default::default()
        }
    }

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
    fn creates_external_users_without_passwords() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let identity = ExternalIdentity {
            provider_key: "https://issuer.example".to_string(),
            subject: "123".to_string(),
            name: Some("José Müller".to_string()),
            ..Default::default()
        };

        let username = app.external_auth.create_user(&identity).unwrap();
        assert_eq!(username, "jose-muller");
        assert_eq!(app.external_auth.find_user(&identity.provider_key, &identity.subject).unwrap(), Some(username));
        assert!(!app.users.check_login("jose-muller", "anything").unwrap());
    }

    #[test]
    fn reuses_identity_and_resolves_username_collisions() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        app.users.create("person", "password", UserRole::User).unwrap();

        let first = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();
        assert_eq!(first, "person-2");
        assert_eq!(app.external_auth.create_user(&identity("42", Some("person"))).unwrap(), first);

        let second = app.external_auth.create_user(&identity("43", Some("person"))).unwrap();
        assert_eq!(second, "person-3");
    }

    #[test]
    fn deleting_a_user_removes_auth_records() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let identity = identity("42", Some("person"));
        let username = app.external_auth.create_user(&identity).unwrap();
        app.sessions.create("session", &username, chrono::Utc::now() + chrono::Duration::hours(1)).unwrap();

        app.users.delete(&username).unwrap();
        assert_eq!(app.external_auth.find_user(&identity.provider_key, &identity.subject).unwrap(), None);
        assert!(app.sessions.get("session").unwrap().is_none());
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn teams_of(app: &Liwan, username: &str) -> Vec<String> {
        let mut teams: Vec<String> = app
            .teams
            .all()
            .unwrap()
            .into_iter()
            .filter(|team| team.users.iter().any(|user| user == username))
            .map(|team| team.id)
            .collect();
        teams.sort();
        teams
    }

    fn mapping(admin: &[&str], teams: &[(&str, &[&str])]) -> GroupsConfig {
        GroupsConfig {
            admin: strings(admin),
            teams: teams.iter().map(|(group, ids)| ((*group).to_string(), strings(ids))).collect(),
            ..Default::default()
        }
    }

    fn create_teams(app: &Liwan, ids: &[&str]) {
        for id in ids {
            app.teams.create_with_id(id, id).unwrap();
        }
    }

    fn in_an_hour() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    #[test]
    fn sync_access_sets_the_role_and_replaces_teams_on_every_login() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam", "docsTeam", "appTeam"]);
        let config =
            mapping(&["liwan-admins"], &[("marketing", &["blogTeam", "docsTeam"]), ("eng", &["appTeam", "docsTeam"])]);
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();
        assert!(teams_of(&app, &username).is_empty(), "provisioning grants no teams by itself");

        app.external_auth.sync_access(&username, &config, &strings(&["liwan-admins", "marketing"])).unwrap();
        assert_eq!(app.users.get(&username).unwrap().role, UserRole::Admin);
        assert_eq!(teams_of(&app, &username), strings(&["blogTeam", "docsTeam"]));

        app.external_auth.sync_access(&username, &config, &strings(&["eng"])).unwrap();
        assert_eq!(app.users.get(&username).unwrap().role, UserRole::User);
        assert_eq!(teams_of(&app, &username), strings(&["appTeam", "docsTeam"]));

        app.external_auth.sync_access(&username, &config, &[]).unwrap();
        assert_eq!(app.users.get(&username).unwrap().role, UserRole::User);
        assert!(teams_of(&app, &username).is_empty());
    }

    #[test]
    fn sync_access_adds_the_default_team_without_groups() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["everyone"]);
        let config = GroupsConfig { default_team: Some("everyone".to_string()), ..Default::default() };
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();

        app.external_auth.sync_access(&username, &config, &[]).unwrap();
        assert_eq!(teams_of(&app, &username), strings(&["everyone"]));
    }

    #[test]
    fn sync_access_skips_teams_that_do_not_exist() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        let config = mapping(&[], &[("marketing", &["blogTeam", "goneTeam"])]);
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();

        app.external_auth.sync_access(&username, &config, &strings(&["marketing"])).unwrap();
        assert_eq!(teams_of(&app, &username), strings(&["blogTeam"]));
    }

    #[test]
    fn sync_access_leaves_accounts_with_a_password_alone() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam", "opsTeam"]);
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        app.users.update("franz", UserRole::Admin, &strings(&["opsTeam"])).unwrap();
        let config = mapping(&[], &[("marketing", &["blogTeam"])]);

        app.external_auth.sync_access("franz", &config, &strings(&["marketing"])).unwrap();
        assert_eq!(app.users.get("franz").unwrap().role, UserRole::Admin, "a local admin is not demoted");
        assert_eq!(teams_of(&app, "franz"), strings(&["opsTeam"]));
    }

    #[test]
    fn sync_access_fails_for_a_deleted_account() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let config = mapping(&[], &[]);
        assert!(app.external_auth.sync_access("gone", &config, &[]).is_err());
    }

    #[test]
    fn sync_access_leaves_other_users_alone() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam", "opsTeam"]);
        let other = app.external_auth.create_user(&identity("7", Some("other"))).unwrap();
        app.users.update(&other, UserRole::Admin, &strings(&["opsTeam"])).unwrap();
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();

        app.external_auth.sync_access(&username, &mapping(&[], &[("marketing", &["blogTeam"])]), &[]).unwrap();
        assert_eq!(app.users.get(&other).unwrap().role, UserRole::Admin);
        assert_eq!(teams_of(&app, &other), strings(&["opsTeam"]));
    }

    #[test]
    fn a_synced_team_grants_its_projects_to_the_session() {
        use crate::app::models::{AccessScope, Project, ProjectVisibility};

        let app = Liwan::new_memory(Config::default()).unwrap();
        let project = Project {
            id: "blog".into(),
            display_name: "Blog".into(),
            visibility: ProjectVisibility::Private,
            secret: None,
        };
        app.projects.create(&project, &[]).unwrap();
        create_teams(&app, &["blogTeam"]);
        app.teams.update("blogTeam", "Blog", &[], &AccessScope::Selected(strings(&["blog"])), None).unwrap();
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();
        app.sessions.create("session", &username, in_an_hour()).unwrap();

        app.external_auth
            .sync_access(&username, &mapping(&[], &[("marketing", &["blogTeam"])]), &strings(&["marketing"]))
            .unwrap();
        let user = app.sessions.get("session").unwrap().unwrap();
        assert!(matches!(&user.access.projects, AccessScope::Selected(ids) if ids == &strings(&["blog"])));
    }

    #[test]
    fn purging_an_identity_removes_its_memberships() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        let identity = identity("42", Some("person"));
        let username = app.external_auth.create_user(&identity).unwrap();
        app.external_auth
            .sync_access(&username, &mapping(&[], &[("marketing", &["blogTeam"])]), &strings(&["marketing"]))
            .unwrap();

        app.external_auth.purge_identity(&identity.provider_key, &identity.subject).unwrap();
        assert!(app.users.get(&username).is_err());
        assert!(teams_of(&app, &username).is_empty());
    }

    #[test]
    fn link_replace_removes_the_holders_memberships() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        let duplicate = app.external_auth.create_user(&identity("sub-1", Some("franz-sso"))).unwrap();
        app.users.update(&duplicate, UserRole::User, &strings(&["blogTeam"])).unwrap();

        assert_eq!(
            app.external_auth.link("franz", "https://issuer.example", "sub-1", true).unwrap(),
            LinkOutcome::Linked
        );
        assert!(teams_of(&app, &duplicate).is_empty());
    }

    #[test]
    fn revoke_access_ends_sessions_teams_and_role_of_an_sso_only_account() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        let identity = identity("42", Some("person"));
        let username = app.external_auth.create_user(&identity).unwrap();
        app.users.update(&username, UserRole::Admin, &strings(&["blogTeam"])).unwrap();
        app.sessions.create("session", &username, in_an_hour()).unwrap();

        app.external_auth.revoke_access(&identity.provider_key, &identity.subject).unwrap();
        assert!(app.sessions.get("session").unwrap().is_none());
        assert!(teams_of(&app, &username).is_empty());
        assert_eq!(app.users.get(&username).unwrap().role, UserRole::User);
    }

    #[test]
    fn revoke_access_leaves_a_password_account_alone() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        app.users.update("franz", UserRole::Admin, &strings(&["blogTeam"])).unwrap();
        app.external_auth.link("franz", "https://issuer.example", "sub-1", false).unwrap();
        app.sessions.create("session", "franz", in_an_hour()).unwrap();

        app.external_auth.revoke_access("https://issuer.example", "sub-1").unwrap();
        assert!(app.sessions.get("session").unwrap().is_some());
        assert_eq!(teams_of(&app, "franz"), strings(&["blogTeam"]));
        assert_eq!(app.users.get("franz").unwrap().role, UserRole::Admin);
    }

    #[test]
    fn revoke_access_ignores_an_unknown_identity() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        create_teams(&app, &["blogTeam"]);
        let username = app.external_auth.create_user(&identity("42", Some("person"))).unwrap();
        app.users.update(&username, UserRole::User, &strings(&["blogTeam"])).unwrap();
        app.sessions.create("session", &username, in_an_hour()).unwrap();

        app.external_auth.revoke_access("https://issuer.example", "nobody").unwrap();
        assert!(app.sessions.get("session").unwrap().is_some());
        assert_eq!(teams_of(&app, &username), strings(&["blogTeam"]));
    }

    #[test]
    fn validates_and_normalizes_return_paths() {
        assert_eq!(local_return_path("/settings?tab=auth#provider"), Some("/settings?tab=auth#provider".to_string()));
        assert_eq!(local_return_path("/settings/../projects"), Some("/projects".to_string()));
        assert_eq!(local_return_path("https://example.com"), None);
        assert_eq!(local_return_path("//example.com"), None);
        assert_eq!(local_return_path("/\\example.com"), None);
        assert_eq!(local_return_path("/\texample.com"), None);
        assert_eq!(local_return_path("/path\r\nlocation:https://example.com"), None);
    }

    #[test]
    fn link_attaches_a_subject_to_an_account_that_already_exists() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let issuer = "https://issuer.example";
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        let team = app.teams.create("Editors").unwrap();
        app.users.update("franz", UserRole::Admin, std::slice::from_ref(&team)).unwrap();

        assert_eq!(app.external_auth.link("franz", issuer, "sub-1", false).unwrap(), LinkOutcome::Linked);
        assert_eq!(app.external_auth.find_user(issuer, "sub-1").unwrap().as_deref(), Some("franz"));

        // The account keeps everything it had, password included.
        let user = app.users.get("franz").unwrap();
        assert_eq!(user.role, UserRole::Admin);
        assert!(app.teams.all().unwrap().iter().any(|t| t.id == team && t.users == vec!["franz".to_string()]));
        assert!(app.users.check_login("franz", "correct-horse-battery").unwrap());

        // Idempotent, and the next sign-in finds the account rather than making one.
        assert_eq!(app.external_auth.link("franz", issuer, "sub-1", false).unwrap(), LinkOutcome::Linked);
        assert_eq!(app.external_auth.create_user(&identity("sub-1", Some("someone"))).unwrap(), "franz");
        assert_eq!(app.users.all().unwrap().len(), 1);

        assert_eq!(app.external_auth.link("nobody", issuer, "sub-2", false).unwrap(), LinkOutcome::UserNotFound);
    }

    #[test]
    fn link_replaces_an_sso_only_holder_and_its_sessions() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let issuer = "https://issuer.example";
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        let duplicate = app.external_auth.create_user(&identity("sub-1", Some("franz-sso"))).unwrap();
        app.sessions.create("duplicate-session", &duplicate, chrono::Utc::now() + chrono::Duration::hours(1)).unwrap();

        assert_eq!(
            app.external_auth.link("franz", issuer, "sub-1", false).unwrap(),
            LinkOutcome::SubjectHeldBy(duplicate.clone())
        );
        assert_eq!(app.external_auth.link("franz", issuer, "sub-1", true).unwrap(), LinkOutcome::Linked);

        assert_eq!(app.external_auth.find_user(issuer, "sub-1").unwrap().as_deref(), Some("franz"));
        assert!(app.users.get(&duplicate).is_err());
        assert!(app.sessions.get("duplicate-session").unwrap().is_none());
    }

    #[test]
    fn link_refuses_a_holder_with_a_password() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let issuer = "https://issuer.example";
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();
        app.users.create("other", "another-long-password", UserRole::User).unwrap();
        app.external_auth.link("other", issuer, "sub-1", false).unwrap();

        // `--replace` is for clearing up auto-provisioned duplicates, never for
        // deleting an account somebody actually uses.
        assert_eq!(
            app.external_auth.link("franz", issuer, "sub-1", true).unwrap(),
            LinkOutcome::HolderHasPassword("other".to_string())
        );
        assert!(app.users.get("other").is_ok());
        assert_eq!(app.external_auth.find_user(issuer, "sub-1").unwrap().as_deref(), Some("other"));
    }

    #[test]
    fn link_moves_an_account_to_a_new_subject() {
        // `(provider_key, username)` is unique, so re-linking has to replace.
        let app = Liwan::new_memory(Config::default()).unwrap();
        let issuer = "https://issuer.example";
        app.users.create("franz", "correct-horse-battery", UserRole::Admin).unwrap();

        app.external_auth.link("franz", issuer, "old-sub", false).unwrap();
        assert_eq!(app.external_auth.link("franz", issuer, "new-sub", false).unwrap(), LinkOutcome::Linked);
        assert_eq!(app.external_auth.find_user(issuer, "old-sub").unwrap(), None);
        assert_eq!(app.external_auth.find_user(issuer, "new-sub").unwrap().as_deref(), Some("franz"));
    }

    #[tokio::test]
    async fn begin_rejects_an_unknown_provider() {
        let app = Liwan::new_memory(Config::default()).unwrap();
        let error = app.external_auth.begin("nope", "/").await.unwrap_err();
        assert!(matches!(error, ExternalAuthError::UnknownProvider));
    }
}
