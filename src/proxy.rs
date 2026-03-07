use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use url::Url;

use crate::providers::{AuthMethod, ProviderConfig};

const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB

#[derive(Debug)]
pub enum ProxyError {
    DomainNotAllowed(String),
    SsrfBlocked(String),
    InvalidUrl(String),
    InvalidMethod(String),
    HttpError(String),
    ResponseTooLarge,
    NoAuthMethod,
    NoBaseUrl,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainNotAllowed(d) => write!(f, "Domain not allowed: {}", d),
            Self::SsrfBlocked(r) => write!(f, "SSRF blocked: {}", r),
            Self::InvalidUrl(u) => write!(f, "Invalid URL: {}", u),
            Self::InvalidMethod(m) => write!(f, "Invalid HTTP method: {}", m),
            Self::HttpError(e) => write!(f, "HTTP error: {}", e),
            Self::ResponseTooLarge => write!(f, "Response exceeds 1MB limit"),
            Self::NoAuthMethod => {
                write!(f, "No auth method configured — use auth_override parameter")
            }
            Self::NoBaseUrl => write!(f, "No base URL configured and url is a relative path"),
        }
    }
}

/// Resolve a URL input (relative path or full URL) against a provider's base_url.
pub fn resolve_url(
    url_input: &str,
    provider: Option<&ProviderConfig>,
) -> Result<Url, ProxyError> {
    // If it looks like a full URL, parse directly
    if url_input.starts_with("https://") || url_input.starts_with("http://") {
        return Url::parse(url_input).map_err(|e| ProxyError::InvalidUrl(e.to_string()));
    }

    // Relative path — need a base_url
    let base = provider
        .and_then(|p| p.base_url.as_deref())
        .ok_or(ProxyError::NoBaseUrl)?;

    let full = if url_input.starts_with('/') {
        format!("{}{}", base, url_input)
    } else {
        format!("{}/{}", base, url_input)
    };

    Url::parse(&full).map_err(|e| ProxyError::InvalidUrl(e.to_string()))
}

/// Validate a URL against SSRF protections and provider's allowed domains.
pub fn validate_url(
    url: &Url,
    allowed_domains: &[String],
) -> Result<(), ProxyError> {
    // Must be HTTPS
    if url.scheme() != "https" {
        return Err(ProxyError::SsrfBlocked(format!(
            "Only HTTPS allowed, got: {}",
            url.scheme()
        )));
    }

    let host_str = url
        .host_str()
        .ok_or_else(|| ProxyError::InvalidUrl("No host in URL".into()))?;

    // Block IP literals (both IPv4 and IPv6)
    match url.host() {
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {
            return Err(ProxyError::SsrfBlocked(
                "IP addresses not allowed — use domain name".into(),
            ));
        }
        None => {
            return Err(ProxyError::InvalidUrl("No host in URL".into()));
        }
        _ => {}
    }

    // Block localhost and internal hostnames
    let lower = host_str.to_lowercase();
    if lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "metadata.google.internal"
        || lower == "169.254.169.254"
    {
        return Err(ProxyError::SsrfBlocked(format!(
            "Internal hostname blocked: {}",
            host_str
        )));
    }

    // Check against allowed domains
    if allowed_domains.is_empty() {
        return Err(ProxyError::DomainNotAllowed(
            "No allowed domains configured".into(),
        ));
    }

    let domain_ok = allowed_domains.iter().any(|pattern| {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".googleapis.com"
            lower.ends_with(suffix) || lower == pattern[2..]
        } else {
            lower == pattern.to_lowercase()
        }
    });

    if !domain_ok {
        return Err(ProxyError::DomainNotAllowed(format!(
            "{} not in allowed domains: {:?}",
            host_str, allowed_domains
        )));
    }

    Ok(())
}

/// Parse an auth_override string into an AuthMethod.
/// Formats: "bearer", "basic", "header:X-Custom-Key", "query:api_key"
pub fn parse_auth_override(override_str: &str) -> Result<AuthMethod, ProxyError> {
    let lower = override_str.to_lowercase();
    if lower == "bearer" {
        Ok(AuthMethod::BearerToken)
    } else if lower == "basic" {
        Ok(AuthMethod::BasicAuth)
    } else if let Some(header_name) = override_str.strip_prefix("header:") {
        Ok(AuthMethod::CustomHeader {
            header_name: header_name.to_string(),
        })
    } else if let Some(param_name) = override_str.strip_prefix("query:") {
        Ok(AuthMethod::QueryParam {
            param_name: param_name.to_string(),
        })
    } else {
        Err(ProxyError::NoAuthMethod)
    }
}

/// Inject auth credentials into the request builder based on the auth method.
pub fn inject_auth(
    headers: &mut HeaderMap,
    url: &mut Url,
    key_value: &str,
    auth_method: &AuthMethod,
) -> Result<(), ProxyError> {
    match auth_method {
        AuthMethod::BearerToken => {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", key_value))
                    .map_err(|e| ProxyError::HttpError(e.to_string()))?,
            );
        }
        AuthMethod::CustomHeader { header_name } => {
            let name = HeaderName::from_bytes(header_name.as_bytes())
                .map_err(|e| ProxyError::HttpError(format!("Invalid header name: {}", e)))?;
            headers.insert(
                name,
                HeaderValue::from_str(key_value)
                    .map_err(|e| ProxyError::HttpError(e.to_string()))?,
            );
        }
        AuthMethod::BasicAuth => {
            let encoded = BASE64.encode(format!("{}:", key_value));
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", encoded))
                    .map_err(|e| ProxyError::HttpError(e.to_string()))?,
            );
        }
        AuthMethod::QueryParam { param_name } => {
            url.query_pairs_mut()
                .append_pair(param_name, key_value);
        }
    }
    Ok(())
}

/// Parse an HTTP method string into reqwest::Method.
pub fn parse_method(method: &str) -> Result<reqwest::Method, ProxyError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "HEAD" => Ok(reqwest::Method::HEAD),
        _ => Err(ProxyError::InvalidMethod(method.to_string())),
    }
}

/// Execute a proxied HTTP request.
pub async fn execute_proxy(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: Url,
    headers: HeaderMap,
    body: Option<String>,
    extra_headers: Option<&HashMap<String, String>>,
    extra_query: Option<&HashMap<String, String>>,
) -> Result<String, ProxyError> {
    let mut builder = client.request(method, url).headers(headers);

    if let Some(extra) = extra_headers {
        let mut hm = HeaderMap::new();
        for (k, v) in extra {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| ProxyError::HttpError(format!("Invalid header: {}", e)))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| ProxyError::HttpError(format!("Invalid header value: {}", e)))?;
            hm.insert(name, val);
        }
        builder = builder.headers(hm);
    }

    if let Some(q) = extra_query {
        builder = builder.query(q);
    }

    if let Some(b) = body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(b);
    }

    let response = builder
        .send()
        .await
        .map_err(|e| ProxyError::HttpError(e.to_string()))?;

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Check if binary response
    let is_text = content_type.contains("json")
        || content_type.contains("text")
        || content_type.contains("xml")
        || content_type.contains("html")
        || content_type.is_empty();

    if !is_text {
        let size = response
            .content_length()
            .map(|l| format!("{} bytes", l))
            .unwrap_or_else(|| "unknown size".into());
        return Ok(format!(
            "Status: {} {}\n[Binary response: {}, {}]",
            status.as_u16(),
            status.canonical_reason().unwrap_or(""),
            content_type,
            size
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| ProxyError::HttpError(e.to_string()))?;

    let truncated = bytes.len() > MAX_RESPONSE_BYTES;
    let body_str = if truncated {
        let s = String::from_utf8_lossy(&bytes[..MAX_RESPONSE_BYTES]).to_string();
        format!("{}\n\n--- RESPONSE TRUNCATED (1MB limit) ---", s)
    } else {
        String::from_utf8_lossy(&bytes).to_string()
    };

    Ok(format!(
        "Status: {} {}\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        body_str
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_url tests ---

    #[test]
    fn test_resolve_url_relative_path() {
        let provider = ProviderConfig {
            name: "test".into(),
            display_name: "Test".into(),
            requests_per_minute: None,
            requests_per_day: None,
            requests_per_month: None,
            cost_per_request: 0.0,
            key_pattern: None,
            rotation_days: 90,
            base_url: Some("https://api.example.com".into()),
            auth_method: Some(AuthMethod::BearerToken),
            allowed_domains: vec!["api.example.com".into()],
            verify_path: None,
        };
        let url = resolve_url("/v1/test", Some(&provider)).unwrap();
        assert_eq!(url.as_str(), "https://api.example.com/v1/test");
    }

    #[test]
    fn test_resolve_url_full_url() {
        let url = resolve_url("https://api.stripe.com/v1/balance", None).unwrap();
        assert_eq!(url.as_str(), "https://api.stripe.com/v1/balance");
    }

    #[test]
    fn test_resolve_url_relative_no_base() {
        let result = resolve_url("/v1/test", None);
        assert!(matches!(result, Err(ProxyError::NoBaseUrl)));
    }

    // --- validate_url tests ---

    #[test]
    fn test_validate_url_https_required() {
        let url = Url::parse("http://api.example.com/test").unwrap();
        let result = validate_url(&url, &["api.example.com".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_no_ip_literal() {
        let url = Url::parse("https://127.0.0.1/test").unwrap();
        let result = validate_url(&url, &["127.0.0.1".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_no_localhost() {
        let url = Url::parse("https://localhost/test").unwrap();
        let result = validate_url(&url, &["localhost".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_no_internal() {
        let url = Url::parse("https://foo.internal/test").unwrap();
        let result = validate_url(&url, &["foo.internal".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_no_metadata() {
        let url = Url::parse("https://metadata.google.internal/computeMetadata").unwrap();
        let result = validate_url(&url, &["metadata.google.internal".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_no_local() {
        let url = Url::parse("https://myhost.local/test").unwrap();
        let result = validate_url(&url, &["myhost.local".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_allowed_domain() {
        let url = Url::parse("https://api.stripe.com/v1/balance").unwrap();
        let result = validate_url(&url, &["api.stripe.com".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_wrong_domain() {
        let url = Url::parse("https://evil.com/steal").unwrap();
        let result = validate_url(&url, &["api.stripe.com".into()]);
        assert!(matches!(result, Err(ProxyError::DomainNotAllowed(_))));
    }

    #[test]
    fn test_validate_url_wildcard_domain() {
        let url = Url::parse("https://sheets.googleapis.com/v4/spreadsheets").unwrap();
        let result = validate_url(&url, &["*.googleapis.com".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_wildcard_exact() {
        let url = Url::parse("https://googleapis.com/test").unwrap();
        let result = validate_url(&url, &["*.googleapis.com".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_empty_allowed() {
        let url = Url::parse("https://api.stripe.com/v1").unwrap();
        let result = validate_url(&url, &[]);
        assert!(matches!(result, Err(ProxyError::DomainNotAllowed(_))));
    }

    #[test]
    fn test_validate_url_ipv6() {
        let url = Url::parse("https://[::1]/test").unwrap();
        let result = validate_url(&url, &["::1".into()]);
        assert!(matches!(result, Err(ProxyError::SsrfBlocked(_))));
    }

    // --- inject_auth tests ---

    #[test]
    fn test_inject_auth_bearer() {
        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://api.example.com/test").unwrap();
        inject_auth(&mut headers, &mut url, "sk-test123", &AuthMethod::BearerToken).unwrap();
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk-test123"
        );
    }

    #[test]
    fn test_inject_auth_custom_header() {
        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://api.example.com/test").unwrap();
        inject_auth(
            &mut headers,
            &mut url,
            "my-key-123",
            &AuthMethod::CustomHeader {
                header_name: "x-api-key".into(),
            },
        )
        .unwrap();
        assert_eq!(
            headers.get("x-api-key").unwrap().to_str().unwrap(),
            "my-key-123"
        );
    }

    #[test]
    fn test_inject_auth_basic() {
        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://api.example.com/test").unwrap();
        inject_auth(&mut headers, &mut url, "sk_live_xxx", &AuthMethod::BasicAuth).unwrap();
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("Basic "));
        let decoded = BASE64.decode(auth.strip_prefix("Basic ").unwrap()).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "sk_live_xxx:");
    }

    #[test]
    fn test_inject_auth_query_param() {
        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://api.example.com/test").unwrap();
        inject_auth(
            &mut headers,
            &mut url,
            "AIzaXXX",
            &AuthMethod::QueryParam {
                param_name: "key".into(),
            },
        )
        .unwrap();
        assert!(url.as_str().contains("key=AIzaXXX"));
        assert!(headers.is_empty());
    }

    // --- parse_method tests ---

    #[test]
    fn test_parse_method_valid() {
        assert_eq!(parse_method("GET").unwrap(), reqwest::Method::GET);
        assert_eq!(parse_method("post").unwrap(), reqwest::Method::POST);
        assert_eq!(parse_method("Put").unwrap(), reqwest::Method::PUT);
        assert_eq!(parse_method("PATCH").unwrap(), reqwest::Method::PATCH);
        assert_eq!(parse_method("DELETE").unwrap(), reqwest::Method::DELETE);
        assert_eq!(parse_method("HEAD").unwrap(), reqwest::Method::HEAD);
    }

    #[test]
    fn test_parse_method_invalid() {
        assert!(matches!(
            parse_method("CONNECT"),
            Err(ProxyError::InvalidMethod(_))
        ));
    }

    // --- parse_auth_override tests ---

    #[test]
    fn test_parse_auth_override_bearer() {
        let m = parse_auth_override("bearer").unwrap();
        assert!(matches!(m, AuthMethod::BearerToken));
    }

    #[test]
    fn test_parse_auth_override_basic() {
        let m = parse_auth_override("basic").unwrap();
        assert!(matches!(m, AuthMethod::BasicAuth));
    }

    #[test]
    fn test_parse_auth_override_header() {
        let m = parse_auth_override("header:X-Custom-Key").unwrap();
        match m {
            AuthMethod::CustomHeader { header_name } => {
                assert_eq!(header_name, "X-Custom-Key")
            }
            _ => panic!("Expected CustomHeader"),
        }
    }

    #[test]
    fn test_parse_auth_override_query() {
        let m = parse_auth_override("query:api_key").unwrap();
        match m {
            AuthMethod::QueryParam { param_name } => assert_eq!(param_name, "api_key"),
            _ => panic!("Expected QueryParam"),
        }
    }

    #[test]
    fn test_parse_auth_override_invalid() {
        assert!(parse_auth_override("unknown").is_err());
    }
}
