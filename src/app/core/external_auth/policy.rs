use crate::{
    app::models::UserRole,
    config::{GroupsConfig, ProviderConfig, ProviderKind, Registration},
};

use super::ExternalIdentity;

/// Why a sign-in was refused. The code is what the login page maps to a message;
/// the detail stays in the server log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    AccessDenied,
    EmailNotVerified,
    DomainNotAllowed,
    RegistrationClosed,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::EmailNotVerified => "email_not_verified",
            Self::DomainNotAllowed => "domain_not_allowed",
            Self::RegistrationClosed => "registration_closed",
        }
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
    group_access(provider, identity)
}

/// Google hands out accounts from every Workspace domain and Microsoft from
/// every tenant, so the restriction has to be read off the token.
fn provider_access(provider: &ProviderConfig, identity: &ExternalIdentity) -> Result<(), Rejection> {
    match provider.kind {
        ProviderKind::Google if !provider.allowed_domains.is_empty() => {
            let hd = identity.hd.as_deref().ok_or(Rejection::AccessDenied)?;
            let allowed = provider.allowed_domains.iter().any(|domain| domain.eq_ignore_ascii_case(hd));
            if allowed { Ok(()) } else { Err(Rejection::AccessDenied) }
        }
        ProviderKind::Microsoft => {
            let tenant = provider.tenant_id.as_deref().ok_or(Rejection::AccessDenied)?;
            let tid = identity.tid.as_deref().ok_or(Rejection::AccessDenied)?;
            if tid.eq_ignore_ascii_case(tenant) { Ok(()) } else { Err(Rejection::AccessDenied) }
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

/// The role and project access a set of IdP groups grants. Project ids are not
/// checked against the database here; the caller does that.
pub fn resolve_role_and_projects(config: &GroupsConfig, groups: &[String]) -> (UserRole, Vec<String>) {
    let role = if groups.iter().any(|group| config.admin.iter().any(|admin| admin == group)) {
        UserRole::Admin
    } else {
        UserRole::User
    };

    let mut projects: Vec<String> = Vec::new();
    for group in groups {
        for project in config.projects.get(group).into_iter().flatten() {
            if !projects.contains(project) {
                projects.push(project.clone());
            }
        }
    }
    projects.sort();
    (role, projects)
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
    use std::collections::BTreeMap;

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
        }
    }

    fn provider(kind: ProviderKind) -> ProviderConfig {
        ProviderConfig { kind, ..Default::default() }
    }

    fn groups_config(allowed: &[&str], admin: &[&str], projects: &[(&str, &[&str])]) -> GroupsConfig {
        GroupsConfig {
            claim: "groups".to_string(),
            allowed: allowed.iter().map(|value| (*value).to_string()).collect(),
            admin: admin.iter().map(|value| (*value).to_string()).collect(),
            projects: projects
                .iter()
                .map(|(group, ids)| ((*group).to_string(), ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>()))
                .collect::<BTreeMap<_, _>>(),
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
        assert_eq!(evaluate_access(&google, &other), Err(Rejection::AccessDenied));

        // A personal Google account has no `hd` at all.
        assert_eq!(evaluate_access(&google, &identity()), Err(Rejection::AccessDenied));

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
        assert_eq!(evaluate_access(&microsoft, &outside), Err(Rejection::AccessDenied));
        assert_eq!(evaluate_access(&microsoft, &identity()), Err(Rejection::AccessDenied));
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
        oidc.groups = Some(groups_config(&["analytics"], &[], &[]));

        let member = ExternalIdentity { groups: Some(vec!["analytics".to_string()]), ..identity() };
        assert_eq!(evaluate_access(&oidc, &member), Ok(()));

        let other = ExternalIdentity { groups: Some(vec!["sales".to_string()]), ..identity() };
        assert_eq!(evaluate_access(&oidc, &other), Err(Rejection::AccessDenied));

        // An absent claim counts as no groups.
        assert_eq!(evaluate_access(&oidc, &identity()), Err(Rejection::AccessDenied));

        // An empty `allowed` list does not gate anything.
        let mut ungated = provider(ProviderKind::Oidc);
        ungated.groups = Some(groups_config(&[], &["liwan-admins"], &[]));
        assert_eq!(evaluate_access(&ungated, &identity()), Ok(()));
    }

    #[test]
    fn registration_only_gates_new_accounts() {
        assert_eq!(evaluate_registration(Registration::Open, false), Ok(()));
        assert_eq!(evaluate_registration(Registration::Open, true), Ok(()));
        assert_eq!(evaluate_registration(Registration::Closed, true), Ok(()));
        assert_eq!(evaluate_registration(Registration::Closed, false), Err(Rejection::RegistrationClosed));
    }

    #[test]
    fn resolves_role_and_projects_from_groups() {
        let config = groups_config(
            &[],
            &["liwan-admins"],
            &[("marketing", &["blog", "docs"]), ("eng", &["app", "blog"]), ("sales", &["crm"])],
        );

        let (role, projects) = resolve_role_and_projects(&config, &["marketing".to_string(), "eng".to_string()]);
        assert_eq!(role, UserRole::User);
        assert_eq!(projects, vec!["app".to_string(), "blog".to_string(), "docs".to_string()]);

        let (role, projects) = resolve_role_and_projects(&config, &["liwan-admins".to_string()]);
        assert_eq!(role, UserRole::Admin);
        assert!(projects.is_empty(), "the admin group grants no projects of its own");

        let (role, projects) = resolve_role_and_projects(&config, &[]);
        assert_eq!(role, UserRole::User);
        assert!(projects.is_empty());
    }
}
