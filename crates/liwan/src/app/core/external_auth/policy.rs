use crate::{
    app::models::UserRole,
    config::{GroupsConfig, ProviderConfig, ProviderKind, Registration},
};

use super::ExternalIdentity;

/// Why a sign-in was refused. The code is what the login page maps to a message;
/// the detail stays in the server log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not in any of the provider's allowed groups.
    AccessDenied,
    /// Google's `hd` or Microsoft's `tid` did not match.
    TenantNotAllowed,
    EmailNotVerified,
    DomainNotAllowed,
    /// The IdP sent an overage marker instead of the full group list.
    GroupsIncomplete,
    RegistrationClosed,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::AccessDenied | Self::TenantNotAllowed => "access_denied",
            Self::EmailNotVerified => "email_not_verified",
            Self::DomainNotAllowed => "domain_not_allowed",
            Self::GroupsIncomplete => "groups_incomplete",
            Self::RegistrationClosed => "registration_closed",
        }
    }

    /// Whether the account behind the identity loses its sessions and teams.
    /// Only the allowed-groups and allowed-domains rules speak about the person;
    /// the rest are about the token or the provider.
    pub fn revokes_access(self) -> bool {
        matches!(self, Self::AccessDenied | Self::EmailNotVerified | Self::DomainNotAllowed)
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Checks that run on every sign-in, before the account is looked up: the
/// provider's own restriction, the email domain, and group membership.
pub fn evaluate_access(provider: &ProviderConfig, identity: &ExternalIdentity) -> Result<(), Rejection> {
    provider_access(provider, identity)?;
    domain_access(provider, identity)?;
    if identity.groups_overage && provider.groups.as_ref().is_some_and(GroupsConfig::reads_groups) {
        return Err(Rejection::GroupsIncomplete);
    }
    group_access(provider, identity)
}

/// Google hands out accounts from every Workspace domain and Microsoft from
/// every tenant, so the restriction has to be read off the token.
fn provider_access(provider: &ProviderConfig, identity: &ExternalIdentity) -> Result<(), Rejection> {
    match provider.kind {
        ProviderKind::Google if !provider.allowed_domains.is_empty() => {
            let hd = identity.hd.as_deref().ok_or(Rejection::TenantNotAllowed)?;
            let allowed = provider.allowed_domains.iter().any(|domain| domain.eq_ignore_ascii_case(hd));
            if allowed { Ok(()) } else { Err(Rejection::TenantNotAllowed) }
        }
        ProviderKind::Microsoft => {
            let tenant = provider.tenant_id.as_deref().ok_or(Rejection::TenantNotAllowed)?;
            let tid = identity.tid.as_deref().ok_or(Rejection::TenantNotAllowed)?;
            if tid.eq_ignore_ascii_case(tenant) { Ok(()) } else { Err(Rejection::TenantNotAllowed) }
        }
        _ => Ok(()),
    }
}

/// Google carries its restriction in `hd` instead, and Microsoft in `tid`, so
/// this covers the kinds that only have an email to go on.
fn domain_access(provider: &ProviderConfig, identity: &ExternalIdentity) -> Result<(), Rejection> {
    if provider.allowed_domains.is_empty()
        || !matches!(provider.kind, ProviderKind::Oidc | ProviderKind::Forseti | ProviderKind::Microsoft)
    {
        return Ok(());
    }

    let Some(email) = identity.email.as_deref() else {
        return Err(Rejection::EmailNotVerified);
    };
    let Some(domain) = email_domain(email) else {
        return Err(Rejection::DomainNotAllowed);
    };
    if provider.allowed_domains.iter().any(|allowed| allowed == &domain) {
        Ok(())
    } else {
        Err(Rejection::DomainNotAllowed)
    }
}

fn group_access(provider: &ProviderConfig, identity: &ExternalIdentity) -> Result<(), Rejection> {
    let Some(groups) = provider.groups.as_ref().filter(|groups| !groups.allowed.is_empty()) else {
        return Ok(());
    };
    let claimed = identity.groups.as_deref().unwrap_or_default();
    if claimed.iter().any(|group| groups.allowed.iter().any(|allowed| allowed == group)) {
        Ok(())
    } else {
        Err(Rejection::AccessDenied)
    }
}

/// Gates first-time provisioning only. A returning user, matched on the
/// provider's subject, always gets in.
pub fn evaluate_registration(registration: Registration, existing: bool) -> Result<(), Rejection> {
    if existing || registration == Registration::Open { Ok(()) } else { Err(Rejection::RegistrationClosed) }
}

/// The role and team ids the configured mapping grants for a group list.
/// Admin membership sets the role only; teams come from `default_team` and
/// `teams`, deduplicated and sorted.
pub fn resolve_role_and_teams(config: &GroupsConfig, groups: &[String]) -> (UserRole, Vec<String>) {
    let role = if groups.iter().any(|group| config.admin.contains(group)) { UserRole::Admin } else { UserRole::User };
    let mut teams: Vec<String> = config
        .default_team
        .iter()
        .chain(groups.iter().filter_map(|group| config.teams.get(group)).flatten())
        .cloned()
        .collect();
    teams.sort();
    teams.dedup();
    (role, teams)
}

/// The lowercased domain of an email address. Requires exactly one `@` and a `.`
/// in the domain. Matching is exact and case-insensitive, so subdomains do not
/// match a parent domain; configure IDN domains in punycode.
pub fn email_domain(email: &str) -> Option<String> {
    let mut parts = email.split('@');
    let _local = parts.next()?;
    let domain = parts.next()?;
    if parts.next().is_some() || domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ExternalIdentity {
        ExternalIdentity {
            provider_key: "https://idp.example.com".to_string(),
            subject: "sub-1".to_string(),
            email: None,
            preferred_username: None,
            name: None,
            hd: None,
            tid: None,
            sid: None,
            groups: None,
            groups_overage: false,
        }
    }

    fn provider(kind: ProviderKind) -> ProviderConfig {
        ProviderConfig { kind, ..Default::default() }
    }

    fn groups_config(allowed: &[&str], admin: &[&str]) -> GroupsConfig {
        GroupsConfig {
            allowed: allowed.iter().map(|value| (*value).to_string()).collect(),
            admin: admin.iter().map(|value| (*value).to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn email_domain_extracts_and_lowercases() {
        assert_eq!(email_domain("alice@example.com").as_deref(), Some("example.com"));
        assert_eq!(email_domain("ALICE@Example.COM").as_deref(), Some("example.com"));
    }

    #[test]
    fn email_domain_rejects_malformed() {
        assert_eq!(email_domain("a@b.com@evil.com"), None);
        assert_eq!(email_domain("noat"), None);
        assert_eq!(email_domain("a@localhost"), None);
        assert_eq!(email_domain("a@"), None);
    }

    #[test]
    fn google_checks_the_hd_claim() {
        let mut google = provider(ProviderKind::Google);
        google.allowed_domains = vec!["example.com".to_string()];

        let allowed = ExternalIdentity { hd: Some("Example.com".to_string()), ..identity() };
        assert_eq!(evaluate_access(&google, &allowed), Ok(()));

        let other = ExternalIdentity { hd: Some("other.com".to_string()), ..identity() };
        assert_eq!(evaluate_access(&google, &other), Err(Rejection::TenantNotAllowed));

        // A personal Google account has no `hd` at all.
        assert_eq!(evaluate_access(&google, &identity()), Err(Rejection::TenantNotAllowed));

        // Without a list, any Google account is acceptable.
        assert_eq!(evaluate_access(&provider(ProviderKind::Google), &identity()), Ok(()));
    }

    #[test]
    fn microsoft_checks_the_tenant() {
        let mut microsoft = provider(ProviderKind::Microsoft);
        microsoft.tenant_id = Some("72f988bf-86f1-41af-91ab-2d7cd011db47".to_string());

        let inside = ExternalIdentity { tid: Some("72F988BF-86F1-41AF-91AB-2D7CD011DB47".to_string()), ..identity() };
        assert_eq!(evaluate_access(&microsoft, &inside), Ok(()));

        let outside = ExternalIdentity { tid: Some("00000000-0000-0000-0000-000000000000".to_string()), ..identity() };
        assert_eq!(evaluate_access(&microsoft, &outside), Err(Rejection::TenantNotAllowed));
        assert_eq!(evaluate_access(&microsoft, &identity()), Err(Rejection::TenantNotAllowed));
    }

    #[test]
    fn allowed_domains_matrix() {
        let mut oidc = provider(ProviderKind::Oidc);
        oidc.allowed_domains = vec!["example.com".to_string(), "acme.org".to_string()];

        let allowed = ExternalIdentity { email: Some("alice@Example.COM".to_string()), ..identity() };
        assert_eq!(evaluate_access(&oidc, &allowed), Ok(()));

        let other = ExternalIdentity { email: Some("bob@other.net".to_string()), ..identity() };
        assert_eq!(evaluate_access(&oidc, &other), Err(Rejection::DomainNotAllowed));

        // Subdomains are not covered by their parent.
        let subdomain = ExternalIdentity { email: Some("eve@sub.example.com".to_string()), ..identity() };
        assert_eq!(evaluate_access(&oidc, &subdomain), Err(Rejection::DomainNotAllowed));

        // `email` is only ever set when the IdP marked it verified.
        assert_eq!(evaluate_access(&oidc, &identity()), Err(Rejection::EmailNotVerified));

        // An empty list means no domain restriction at all.
        assert_eq!(evaluate_access(&provider(ProviderKind::Oidc), &identity()), Ok(()));
    }

    #[test]
    fn google_ignores_allowed_domains_for_the_email() {
        // The `hd` check already covered it, and a Workspace user can have a
        // mail alias on another domain.
        let mut google = provider(ProviderKind::Google);
        google.allowed_domains = vec!["example.com".to_string()];
        let identity = ExternalIdentity {
            hd: Some("example.com".to_string()),
            email: Some("alice@alias.test".to_string()),
            ..identity()
        };
        assert_eq!(evaluate_access(&google, &identity), Ok(()));
    }

    #[test]
    fn groups_allowed_gates_sign_in() {
        let mut oidc = provider(ProviderKind::Oidc);
        oidc.groups = Some(groups_config(&["analytics"], &[]));

        let member = ExternalIdentity { groups: Some(vec!["analytics".to_string()]), ..identity() };
        assert_eq!(evaluate_access(&oidc, &member), Ok(()));

        let other = ExternalIdentity { groups: Some(vec!["sales".to_string()]), ..identity() };
        assert_eq!(evaluate_access(&oidc, &other), Err(Rejection::AccessDenied));

        // An absent claim counts as no groups.
        assert_eq!(evaluate_access(&oidc, &identity()), Err(Rejection::AccessDenied));

        // An empty `allowed` list does not gate anything.
        let mut ungated = provider(ProviderKind::Oidc);
        ungated.groups = Some(groups_config(&[], &["liwan-admins"]));
        assert_eq!(evaluate_access(&ungated, &identity()), Ok(()));
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn team_mapping() -> GroupsConfig {
        GroupsConfig {
            admin: strings(&["liwan-admins"]),
            teams: [("marketing", &["blog", "docs"][..]), ("eng", &["app", "docs"][..])]
                .into_iter()
                .map(|(group, teams)| (group.to_string(), strings(teams)))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn resolved_teams_are_the_union_deduplicated_and_sorted() {
        let (role, teams) = resolve_role_and_teams(&team_mapping(), &strings(&["marketing", "eng", "sales"]));
        assert_eq!(role, UserRole::User);
        assert_eq!(teams, strings(&["app", "blog", "docs"]));

        let with_default = GroupsConfig { default_team: Some("docs".to_string()), ..team_mapping() };
        let (_, teams) = resolve_role_and_teams(&with_default, &strings(&["eng"]));
        assert_eq!(teams, strings(&["app", "docs"]));
    }

    #[test]
    fn the_default_team_needs_no_groups() {
        let config = GroupsConfig { default_team: Some("everyone".to_string()), ..Default::default() };
        assert_eq!(resolve_role_and_teams(&config, &[]), (UserRole::User, strings(&["everyone"])));
    }

    #[test]
    fn the_admin_group_grants_no_team() {
        let (role, teams) = resolve_role_and_teams(&team_mapping(), &strings(&["liwan-admins"]));
        assert_eq!(role, UserRole::Admin);
        assert!(teams.is_empty());
        assert_eq!(resolve_role_and_teams(&team_mapping(), &[]), (UserRole::User, Vec::new()));
    }

    #[test]
    fn an_incomplete_group_list_is_rejected_only_when_the_mapping_reads_it() {
        let incomplete = ExternalIdentity { groups: Some(strings(&["analytics"])), groups_overage: true, ..identity() };
        let mut oidc = provider(ProviderKind::Oidc);
        assert_eq!(evaluate_access(&oidc, &incomplete), Ok(()), "no groups table");

        oidc.groups = Some(GroupsConfig { default_team: Some("everyone".to_string()), ..Default::default() });
        assert_eq!(evaluate_access(&oidc, &incomplete), Ok(()), "default_team alone does not read the list");

        for groups in [
            groups_config(&["analytics"], &[]),
            groups_config(&[], &["liwan-admins"]),
            GroupsConfig { teams: [("eng".to_string(), strings(&["app"]))].into(), ..Default::default() },
        ] {
            oidc.groups = Some(groups);
            assert_eq!(evaluate_access(&oidc, &incomplete), Err(Rejection::GroupsIncomplete));
            assert_eq!(Rejection::GroupsIncomplete.code(), "groups_incomplete");
        }
    }

    #[test]
    fn only_the_group_and_domain_rules_revoke() {
        assert!(Rejection::AccessDenied.revokes_access());
        assert!(Rejection::DomainNotAllowed.revokes_access());
        assert!(Rejection::EmailNotVerified.revokes_access());
        assert!(!Rejection::TenantNotAllowed.revokes_access());
        assert!(!Rejection::GroupsIncomplete.revokes_access());
        assert!(!Rejection::RegistrationClosed.revokes_access());
    }

    #[test]
    fn registration_only_gates_new_accounts() {
        assert_eq!(evaluate_registration(Registration::Open, false), Ok(()));
        assert_eq!(evaluate_registration(Registration::Open, true), Ok(()));
        assert_eq!(evaluate_registration(Registration::Closed, true), Ok(()));
        assert_eq!(evaluate_registration(Registration::Closed, false), Err(Rejection::RegistrationClosed));
    }
}
