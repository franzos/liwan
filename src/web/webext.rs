use std::convert::Infallible;
use std::fmt::Display;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::config::Config;
use crate::utils::ip_headers::{
    TrustedHeader, TrustedProxy, parse_header_ip, public_ip, should_trust_forwarded_headers,
    should_trust_forwarded_headers_for_rate_limit,
};
use crate::web::Files;
use crate::web::RouterState;
use aide::axum::IntoApiResponse;
use aide::{OperationInput, OperationOutput};
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::response::IntoResponse;
use axum::{Json, extract};
use http::{Response, StatusCode, header};
use rust_embed::RustEmbed;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::json;
use tower::Service;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

pub type ApiResult<T, E = ApiError> = Result<T, E>;

#[rustfmt::skip]
pub trait AxumErrExt<T> {
    fn http_err(self, message: &str, status: StatusCode) -> ApiResult<T>;
    fn http_status(self, status: StatusCode) -> ApiResult<T>;
}

impl<T> AxumErrExt<T> for Option<T> {
    fn http_err(self, message: &str, status: StatusCode) -> ApiResult<T> {
        self.ok_or_else(|| ApiError { message: message.to_string(), status })
    }

    fn http_status(self, status: StatusCode) -> ApiResult<T> {
        self.ok_or_else(|| status.into())
    }
}

impl<T, E: Display> AxumErrExt<T> for Result<T, E> {
    fn http_err(self, message: &str, status: StatusCode) -> ApiResult<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                if status == StatusCode::INTERNAL_SERVER_ERROR {
                    tracing::error!("{message}: {err}", err = e);
                } else {
                    tracing::debug!("{message}: {err}", err = e);
                }
                Err(ApiError { message: message.to_string(), status })
            }
        }
    }

    fn http_status(self, status: StatusCode) -> ApiResult<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                if status == StatusCode::INTERNAL_SERVER_ERROR {
                    tracing::error!("{err}", err = e);
                } else {
                    tracing::debug!("{err}", err = e);
                }
                Err(status.into())
            }
        }
    }
}

pub struct ApiError {
    pub message: String,
    pub status: StatusCode,
}

impl OperationOutput for ApiError {
    type Inner = Self;
}

impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        ApiError { message: status.canonical_reason().unwrap_or("Unknown error").to_string(), status }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> http::Response<Body> {
        let body = Json(
            json!({ "status": self.status.canonical_reason(), "message": self.message, "code": self.status.as_u16() }),
        );
        (self.status, body).into_response()
    }
}

const CONFIG_PLACEHOLDER: &str = "__LIWAN_CONFIG__";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlConfig {
    base_url: String,
    disable_favicons: bool,
    oidc_enabled: bool,
    oidc_button_label: Option<String>,
}

pub(super) async fn serve(
    extract::State(state): extract::State<RouterState>,
    orig_uri: extract::OriginalUri,
    req: Request,
) -> Result<impl IntoResponse, StatusCode> {
    let mut path = req.uri().path().trim_start_matches('/').trim_end_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".to_string();
    }

    if req.method() != http::Method::GET {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }

    if path.starts_with("p/") {
        let mut parts = path.splitn(3, '/').collect::<Vec<&str>>();
        parts[1] = "project";
        path = parts.join("/");
    }

    if path.starts_with("settings/projects/") {
        let mut parts = path.splitn(4, '/').collect::<Vec<&str>>();
        parts[2] = "project";
        path = parts.join("/");
    }

    if path.starts_with("settings/entities/") {
        let mut parts = path.splitn(4, '/').collect::<Vec<&str>>();
        parts[2] = "entity";
        path = parts.join("/");
    }

    if path.starts_with("settings/users/") {
        let mut parts = path.splitn(4, '/').collect::<Vec<&str>>();
        parts[2] = "user";
        path = parts.join("/");
    }

    let file = if let Some(content) = Files::get(&path) {
        Some(content)
    } else {
        path = format!("{path}/index.html");
        Files::get(&path)
    };

    let orig_path = orig_uri.path();
    if orig_path.ends_with('/') && file.is_some() && orig_path.len() > 1 {
        let redirect = orig_uri.path().trim_start_matches('/').trim_end_matches('/');
        return Ok(Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, format!("/{redirect}"))
            .body(Body::empty())
            .unwrap());
    }

    let Some(content) = file else { return Err(StatusCode::NOT_FOUND) };

    let mime = content.metadata.mimetype();
    let is_html = mime == "text/html";

    let (body, hash) = if is_html {
        let html = std::str::from_utf8(&content.data).map_err(|err| {
            tracing::error!("failed to read embedded HTML as UTF-8: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let config = HtmlConfig {
            base_url: state.config.base_url.clone(),
            disable_favicons: state.config.disable_favicons,
            oidc_enabled: state.config.oidc.enabled(),
            oidc_button_label: state.config.oidc.button_label.clone(),
        };
        let config_json = serde_json::to_string(&config).map_err(|err| {
            tracing::error!("failed to serialize HTML config: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let body = html.replace(CONFIG_PLACEHOLDER, &config_json.replace('<', "\\u003c"));
        let hash = blake3::hash(body.as_bytes()).to_hex().to_string();
        (Body::from(body), hash)
    } else {
        let hash = hex::encode(content.metadata.sha256_hash());
        (Body::from(content.data), hash)
    };

    if let Some(etag) = req.headers().get(header::IF_NONE_MATCH)
        && etag.to_str().unwrap_or("000000") == hash
    {
        return Err(StatusCode::NOT_MODIFIED);
    }

    let mut builder = Response::builder().header(header::CONTENT_TYPE, mime).header(header::ETAG, hash);

    if path.starts_with("_astro/") {
        builder = builder.header(header::CACHE_CONTROL, "public, max-age=604800, immutable");
    }

    Ok(builder.body(body).unwrap())
}

#[derive(Clone)]
pub struct StaticFile<T>(&'static str, PhantomData<T>);

impl<T> StaticFile<T> {
    pub const fn new(file_path: &'static str) -> Self {
        StaticFile(file_path, PhantomData)
    }
}

impl<T: RustEmbed + Send + Sync> IntoResponse for StaticFile<T> {
    fn into_response(self) -> http::Response<Body> {
        match T::get(self.0) {
            Some(content) => ([(header::CONTENT_TYPE, content.metadata.mimetype())], content.data).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

impl<T: RustEmbed + Send + Sync> Service<Request<Body>> for StaticFile<T> {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async {
            Ok(match T::get(self.0) {
                Some(content) => Response::builder()
                    .header(header::CONTENT_TYPE, content.metadata.mimetype())
                    .body(Body::from(content.data))
                    .expect("failed to build response"),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .expect("failed to build response"),
            })
        })
    }
}

pub(crate) fn empty_response() -> impl IntoApiResponse {
    #[derive(Serialize, JsonSchema)]
    struct StatusResponse {
        status: String,
    }

    (StatusCode::OK, Json(StatusResponse { status: "OK".into() }))
}

macro_rules! http_bail {
    ($status:expr, $($arg:tt)*) => {
        return Err(crate::web::webext::ApiError {
            message: format!($($arg)*),
            status: $status,
        })
    };
}
pub(crate) use http_bail;

#[derive(Debug, Copy, Clone)]
pub struct ClientIp(pub Option<IpAddr>);
impl OperationInput for ClientIp {}

impl FromRequestParts<RouterState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &RouterState,
    ) -> Result<Self, Self::Rejection> {
        let peer_ip =
            ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await.ok().map(|ConnectInfo(addr)| addr.ip());

        if should_trust_forwarded_headers(state.config.use_forward_headers, peer_ip, &state.config.trusted_proxies) {
            for header in &state.config.trusted_headers {
                if let Some(ip) = public_ip(parse_header_ip(&parts.headers, header)) {
                    return Ok(ClientIp(Some(ip)));
                }
            }
        }

        Ok(ClientIp(public_ip(peer_ip)))
    }
}

/// Rate-limit bucket key: the forwarded client IP behind a listed proxy, the TCP
/// peer otherwise.
///
/// The stock extractors both get this wrong for liwan. `PeerIpKeyExtractor`
/// collapses every visitor behind a reverse proxy into one bucket, which drops
/// tracker events; `SmartIpKeyExtractor` trusts forwarded headers from anyone,
/// so a direct client escapes its bucket by rewriting the header.
#[derive(Clone)]
pub struct RateLimitKeyExtractor {
    use_forward_headers: bool,
    trusted_proxies: Arc<[TrustedProxy]>,
    trusted_headers: Arc<[TrustedHeader]>,
}

/// Bucket for requests that arrive without a peer address — the test harness has
/// no `ConnectInfo`. Erroring instead would turn every such request into a 500.
const RATE_LIMIT_FALLBACK_KEY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

impl RateLimitKeyExtractor {
    pub fn new(config: &Config) -> Self {
        Self {
            use_forward_headers: config.use_forward_headers,
            trusted_proxies: config.trusted_proxies.clone().into(),
            trusted_headers: config.trusted_headers.clone().into(),
        }
    }
}

impl KeyExtractor for RateLimitKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip());

        if should_trust_forwarded_headers_for_rate_limit(self.use_forward_headers, peer_ip, &self.trusted_proxies) {
            for header in self.trusted_headers.iter() {
                if let Some(ip) = parse_header_ip(req.headers(), header) {
                    return Ok(ip);
                }
            }
        }

        Ok(peer_ip.unwrap_or(RATE_LIMIT_FALLBACK_KEY))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_proxies(proxies: &[&str]) -> Config {
        let mut config = Config::default();
        config.use_forward_headers = true;
        config.trusted_proxies = proxies.iter().map(|p| p.parse().expect("valid proxy")).collect();
        config
    }

    fn request(peer: Option<&str>, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder();
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(()).expect("valid request");
        if let Some(peer) = peer {
            req.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().expect("valid peer")));
        }
        req
    }

    #[test]
    fn falls_back_to_fixed_key_without_connect_info() {
        let extractor = RateLimitKeyExtractor::new(&config_with_proxies(&["10.0.0.1"]));
        let key = extractor.extract(&request(None, &[("x-real-ip", "9.9.9.9")])).expect("extraction cannot fail");
        assert_eq!(key, RATE_LIMIT_FALLBACK_KEY);
    }

    #[test]
    fn keys_on_peer_when_proxies_not_trusted() {
        // An untrusted peer cannot talk its way out of its own bucket.
        let extractor = RateLimitKeyExtractor::new(&config_with_proxies(&["10.0.0.1"]));
        let key = extractor
            .extract(&request(Some("203.0.113.7:44321"), &[("x-real-ip", "9.9.9.9")]))
            .expect("extraction cannot fail");
        assert_eq!(key, "203.0.113.7".parse::<IpAddr>().unwrap());

        // An empty proxy list means no forwarded header is trusted.
        let extractor = RateLimitKeyExtractor::new(&config_with_proxies(&[]));
        let key = extractor
            .extract(&request(Some("10.0.0.1:44321"), &[("x-real-ip", "9.9.9.9")]))
            .expect("extraction cannot fail");
        assert_eq!(key, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn keys_on_forwarded_header_when_peer_is_a_trusted_proxy() {
        let extractor = RateLimitKeyExtractor::new(&config_with_proxies(&["10.0.0.0/8"]));
        let key = extractor
            .extract(&request(Some("10.4.5.6:44321"), &[("x-forwarded-for", "9.9.9.9, 8.8.8.8")]))
            .expect("extraction cannot fail");
        assert_eq!(key, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn keys_on_private_peer_addresses_too() {
        // No public_ip filtering: a LAN client gets its own bucket rather than
        // sharing the fallback with everyone else.
        let extractor = RateLimitKeyExtractor::new(&config_with_proxies(&[]));
        let key = extractor.extract(&request(Some("192.168.1.5:1234"), &[])).expect("extraction cannot fail");
        assert_eq!(key, "192.168.1.5".parse::<IpAddr>().unwrap());
    }
}
