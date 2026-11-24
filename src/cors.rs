//! CORS for browser clients (Corliss #69, #74).
//!
//! A browser app reads the relay cross-origin, and a browser refuses to hand
//! it a response that does not name its origin. Two levels, and only two,
//! the same rule Corliss keeps:
//!
//! - **The public resource document** is readable by any origin (`*`). It
//!   holds no member data, and the request carries no credential.
//! - **`/v1/`** answers browser clients by name, never `*`, including the
//!   preflight: loopback over `http` (`127.0.0.1`, `localhost`, `[::1]`, any
//!   port) **or any well-formed `https` origin**. CORS is not the access
//!   control here — the bearer token is — and a client may bring its own https
//!   deployment rather than only a page on this machine. Any other origin gets
//!   no CORS headers at all, so the browser keeps the answer from it.
//!
//! Nothing sends `Access-Control-Allow-Credentials`: the relay has no cookie,
//! and a token travels in the header or the query where the page put it.
//!
//! A loopback host is compared as written. A name that only resolves to
//! 127.0.0.1 (a DNS-rebound one) is refused, because the page behind it is not
//! on this machine — and an `https` origin is a real origin whatever it
//! resolves to.
//!
//! The `/v1/sync` WebSocket does not check `Origin`. A WebSocket is not
//! covered by CORS, and its only credential is the token in the query, which
//! a page on another origin does not have.

use axum::{
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// The methods `/v1/` uses. A preflight names one of them.
const METHODS: &str = "GET, HEAD, POST";
/// `Authorization` for the member's token, `Content-Type` for a JSON body or an
/// attachment, `X-Content-SHA256` for an attachment upload.
const HEADERS: &str = "Authorization, Content-Type, X-Content-SHA256";

/// Whether a browser `Origin` header names a page on this machine.
///
/// An origin is scheme, host and port and nothing more, so a path,
/// credentials, a query or a fragment mean it is not one. The `null` origin
/// a sandboxed page sends is refused, and so is `https`: a loopback page has
/// no certificate to serve it.
pub fn is_loopback_origin(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    // `port` keeps its leading `:`, so a bare trailing colon is told apart
    // from no port at all.
    let (host, port) = match authority.strip_prefix("[::1]") {
        Some(rest) => ("[::1]", rest),
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    let port_ok = match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(digits) => {
            !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u32>().is_ok_and(|n| n <= 65535)
        }
    };
    port_ok && matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Whether a browser `Origin` header is one of our clients.
///
/// **Loopback over `http`, or any well-formed `https` origin.** CORS decides
/// whether a page may read a response, not whether it may act: the bearer token
/// does that, and the page had to obtain it from its own user. So the question
/// here is "could this be a browser client of ours", and a client that serves
/// its own client metadata document over https is exactly that — even though it
/// is not on this machine.
pub fn is_browser_origin(origin: &str) -> bool {
    is_loopback_origin(origin) || is_https_origin(origin)
}

/// Whether this is a bare `https` origin: scheme, host, optional port, nothing
/// else. A path, query, fragment or credentials mean it is not an origin.
fn is_https_origin(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '@' | '\\')
        })
    {
        return false;
    }

    // An IPv6 (or IPvFuture) host is bracketed, so the colon that belongs to the
    // host cannot be mistaken for the one before the port.
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return false;
        };
        let is_address = !inside.is_empty()
            && inside
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        return is_address && valid_port(after);
    }

    let (host, port) = authority.split_at(authority.find(':').unwrap_or(authority.len()));
    let is_hostname = !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    is_hostname && valid_port(port)
}

/// Nothing, or `:port` with a port a browser could be on.
fn valid_port(rest: &str) -> bool {
    match rest.strip_prefix(':') {
        None => rest.is_empty(),
        Some(digits) => {
            !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u32>().is_ok_and(|n| n <= 65535)
        }
    }
}

/// Let any origin read a public document.
pub fn public_document(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// Let a browser client call these routes, including the preflight.
///
/// Any other origin gets no CORS headers, and its preflight falls through to
/// the router, which refuses the method.
pub async fn browser_clients(request: Request, next: Next) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .filter(|value| value.to_str().is_ok_and(is_browser_origin))
        .cloned();

    let mut response = match &origin {
        Some(_) if request.method() == Method::OPTIONS => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(METHODS),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(HEADERS),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
            response
        }
        _ => next.run(request).await,
    };

    let headers = response.headers_mut();
    if let Some(origin) = origin {
        // Named on errors too: the client has to read a refusal to act on it.
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    // The answer depends on the Origin, so a cache must not reuse it.
    headers.append(header::VARY, HeaderValue::from_static("origin"));
    response
}

#[cfg(test)]
mod tests {
    use super::{is_browser_origin, is_loopback_origin};

    #[test]
    fn everything_but_loopback_is_refused() {
        for origin in [
            "",
            "null",
            "https://127.0.0.1:5173",
            "http://127.0.0.1.evil.example",
            "http://localhost.evil.example:5173",
            "http://example.test:5173",
            "http://127.0.0.1:5173/",
            "http://127.0.0.1:5173/path",
            "http://user@127.0.0.1:5173",
            "http://127.0.0.1:notaport",
            "http://127.0.0.1:",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:5173?x",
            "http://127.0.0.1:5173#x",
            "http://[::1]evil",
            "http://::1:3000",
            "http://127.0.0.2:5173",
            "HTTP://127.0.0.1:5173",
        ] {
            assert!(!is_loopback_origin(origin), "{origin:?}");
        }
    }

    #[test]
    fn https_origins_are_browser_clients() {
        for origin in [
            "https://boris.tngl.io",
            "https://example.test:8443",
            "https://xn--bcher-kva.example",
            "https://[2001:db8::1]:8443",
        ] {
            assert!(is_browser_origin(origin), "{origin:?}");
        }
    }

    #[test]
    fn loopback_is_a_browser_client() {
        for origin in [
            "http://127.0.0.1:5173",
            "http://localhost",
            "http://[::1]:3000",
        ] {
            assert!(is_browser_origin(origin), "{origin:?}");
        }
    }

    #[test]
    fn what_is_not_an_origin_is_refused() {
        for origin in [
            "",
            "null",
            "https://",
            "https://example.test/",
            "https://example.test/path",
            "https://example.test?x",
            "https://example.test#x",
            "https://user@example.test",
            "https://example.test:notaport",
            "https://example.test:",
            "https://example.test:65536",
            "https://example..test",
            "https://-lead.example",
            "http://example.test:5173",
            "HTTPS://example.test",
        ] {
            assert!(!is_browser_origin(origin), "{origin:?}");
        }
    }

    #[test]
    fn loopback_origins_on_any_port() {
        for origin in [
            "http://127.0.0.1:5173",
            "http://127.0.0.1",
            "http://localhost:8000",
            "http://[::1]:3000",
            "http://[::1]",
        ] {
            assert!(is_loopback_origin(origin), "{origin:?}");
        }
    }
}
