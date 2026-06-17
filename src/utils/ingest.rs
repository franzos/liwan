use url::Url;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Utm {
    pub source: Option<String>,
    pub content: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub term: Option<String>,
}

fn extract_query(url: &mut Url, keys: &[&str]) -> Option<String> {
    let value = keys
        .iter()
        .find_map(|key| url.query_pairs().find(|(name, _)| name == *key).map(|(_, value)| value.into_owned()));

    if let Some(value) = &value {
        let filtered = url
            .query_pairs()
            .filter(|(name, _)| !keys.contains(&name.as_ref()))
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        drop(pairs);

        if !filtered.is_empty() {
            let mut pairs = url.query_pairs_mut();
            pairs.extend_pairs(filtered.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        }

        if value.trim().is_empty() {
            return None;
        }

        if value.len() > 255 {
            return None;
        }
    }

    value
}

/// Extract UTM parameters from the URL, removing them (and their aliases) from the query string
pub fn extract_utm(url: &mut Url) -> Utm {
    Utm {
        campaign: extract_query(url, &["utm_campaign", "campaign"]),
        content: extract_query(url, &["utm_content", "content"]),
        medium: extract_query(url, &["utm_medium", "medium"]),
        source: extract_query(url, &["utm_source", "source", "ref", "referrer", "referer"]),
        term: extract_query(url, &["utm_term", "term"]),
    }
}

/// Strip the query string and trailing slash, returning `(path, fqdn)`
pub fn normalize_url(mut url: Url) -> (String, String) {
    url.set_query(None);
    let path = url.path().to_string();
    let path = if path.len() > 1 && path.ends_with('/') { path.trim_end_matches('/').to_string() } else { path };
    let fqdn = url.host_str().unwrap_or_default().to_string();
    (path, fqdn)
}

/// Whether a URL host is loopback/localhost or a private/reserved IP literal (not internet-routable)
pub fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    let literal = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    literal.parse::<std::net::IpAddr>().is_ok_and(|ip| !crate::utils::ip_headers::is_public_ip(&ip))
}

/// Remove the `www.` prefix and ignore empty or short referrers
pub fn clean_referrer(referrer: Option<String>) -> Option<String> {
    let referrer = referrer.map(|r| r.trim_start_matches("www.").to_string());
    referrer.filter(|r| r.trim().len() > 3)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn extract_utm_strips_aliases_and_keeps_other_params() {
        let mut url = Url::parse(
            "https://example.com/path/?utm_source=newsletter&source=ignored&campaign=spring&utm_medium=email&foo=bar&ref=backup",
        )
        .expect("valid url");

        let utm = extract_utm(&mut url);

        assert_eq!(utm.source.as_deref(), Some("newsletter"));
        assert_eq!(utm.medium.as_deref(), Some("email"));
        assert_eq!(utm.campaign.as_deref(), Some("spring"));
        assert_eq!(utm.content, None);
        assert_eq!(utm.term, None);
        assert_eq!(url.as_str(), "https://example.com/path/?foo=bar");
    }

    #[test]
    fn extract_utm_matches_bare_source_and_ref_params() {
        let mut url = Url::parse("https://example.com/?source=duckduckgo").expect("valid url");
        assert_eq!(extract_utm(&mut url).source.as_deref(), Some("duckduckgo"));

        let mut url = Url::parse("https://example.com/?ref=producthunt").expect("valid url");
        assert_eq!(extract_utm(&mut url).source.as_deref(), Some("producthunt"));
    }

    #[test]
    fn normalize_url_strips_query_and_trailing_slash() {
        let url = Url::parse("https://example.com/blog/post/?foo=bar").expect("valid url");
        assert_eq!(normalize_url(url), ("/blog/post".to_string(), "example.com".to_string()));

        let url = Url::parse("https://example.com/").expect("valid url");
        assert_eq!(normalize_url(url), ("/".to_string(), "example.com".to_string()));
    }

    #[test]
    fn is_local_host_detects_loopback_private_and_localhost() {
        assert!(is_local_host("localhost"));
        assert!(is_local_host("LocalHost"));
        assert!(is_local_host("app.localhost"));
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("10.0.0.5"));
        assert!(is_local_host("192.168.1.1"));
        assert!(is_local_host("169.254.0.1"));
        assert!(is_local_host("[::1]"));
        assert!(is_local_host("::1"));

        assert!(!is_local_host("example.com"));
        assert!(!is_local_host("localhost.example.com"));
        assert!(!is_local_host("8.8.8.8"));
        assert!(!is_local_host("142.166.21.0"));
    }

    #[test]
    fn clean_referrer_strips_www_and_filters_short_values() {
        assert_eq!(clean_referrer(Some("www.example.com".to_string())), Some("example.com".to_string()));
        assert_eq!(clean_referrer(Some("a.b".to_string())), None);
        assert_eq!(clean_referrer(Some("   ".to_string())), None);
        assert_eq!(clean_referrer(None), None);
    }
}
