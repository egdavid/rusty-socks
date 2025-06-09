//! Security headers for HTTP responses
//! 
//! This module provides security headers that should be added to all HTTP responses
//! to protect against common web vulnerabilities.

use warp::reply::Response;
use warp::http::HeaderValue;
use warp::Filter;

/// Secure Content Security Policy without unsafe-inline
const SECURE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;";

/// Strict Content Security Policy for API endpoints
const STRICT_CSP: &str = "default-src 'none'; connect-src 'self'; frame-ancestors 'none';";

/// Content Security Policy for WebSocket connections
const WEBSOCKET_CSP: &str = "default-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none';";

/// Add security headers to a response
pub fn add_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    
    // Prevent clickjacking
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    
    // Prevent MIME type sniffing
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    
    // Enable XSS protection
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    
    // Referrer policy - don't leak referrer information
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    
    // Content Security Policy - secure policy without unsafe-inline
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(SECURE_CSP)
    );
    
    // Permissions Policy - disable dangerous features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
    );
    
    // Remove server information disclosure
    headers.remove("Server");
    
    response
}

/// Security headers middleware for Warp
pub fn security_headers() -> impl warp::Filter<Extract = (), Error = std::convert::Infallible> + Clone {
    warp::any().map(|| ()).untuple_one()
}

/// Wrap a reply with security headers (general purpose)
pub fn with_security_headers<T: warp::Reply>(reply: T) -> impl warp::Reply {
    // Chain multiple with_header calls since with_headers doesn't exist
    let reply = warp::reply::with_header(reply, "X-Frame-Options", "DENY");
    let reply = warp::reply::with_header(reply, "X-Content-Type-Options", "nosniff");
    let reply = warp::reply::with_header(reply, "X-XSS-Protection", "1; mode=block");
    let reply = warp::reply::with_header(reply, "Referrer-Policy", "strict-origin-when-cross-origin");
    let reply = warp::reply::with_header(reply, "Content-Security-Policy", SECURE_CSP);
    warp::reply::with_header(reply, "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
}

/// Wrap a reply with strict security headers for API endpoints
pub fn with_api_security_headers<T: warp::Reply>(reply: T) -> impl warp::Reply {
    let reply = warp::reply::with_header(reply, "X-Frame-Options", "DENY");
    let reply = warp::reply::with_header(reply, "X-Content-Type-Options", "nosniff");
    let reply = warp::reply::with_header(reply, "X-XSS-Protection", "1; mode=block");
    let reply = warp::reply::with_header(reply, "Referrer-Policy", "no-referrer");
    let reply = warp::reply::with_header(reply, "Content-Security-Policy", STRICT_CSP);
    let reply = warp::reply::with_header(reply, "Cache-Control", "no-cache, no-store, must-revalidate");
    warp::reply::with_header(reply, "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
}

/// Wrap a reply with WebSocket-appropriate security headers
pub fn with_websocket_security_headers<T: warp::Reply>(reply: T) -> impl warp::Reply {
    let reply = warp::reply::with_header(reply, "X-Frame-Options", "DENY");
    let reply = warp::reply::with_header(reply, "X-Content-Type-Options", "nosniff");
    let reply = warp::reply::with_header(reply, "Referrer-Policy", "strict-origin-when-cross-origin");
    let reply = warp::reply::with_header(reply, "Content-Security-Policy", WEBSOCKET_CSP);
    warp::reply::with_header(reply, "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_csp_no_unsafe_inline() {
        // Verify that our CSP policies do not contain unsafe-inline
        assert!(!SECURE_CSP.contains("unsafe-inline"), "SECURE_CSP should not contain unsafe-inline");
        assert!(!STRICT_CSP.contains("unsafe-inline"), "STRICT_CSP should not contain unsafe-inline");
        assert!(!WEBSOCKET_CSP.contains("unsafe-inline"), "WEBSOCKET_CSP should not contain unsafe-inline");
    }

    #[test]
    fn test_secure_csp_contains_security_directives() {
        // Verify that our CSP contains important security directives
        assert!(SECURE_CSP.contains("default-src 'self'"));
        assert!(SECURE_CSP.contains("script-src 'self'"));
        assert!(SECURE_CSP.contains("style-src 'self'"));
        assert!(SECURE_CSP.contains("object-src 'none'"));
        assert!(SECURE_CSP.contains("frame-src 'none'"));
        assert!(SECURE_CSP.contains("base-uri 'self'"));
        assert!(SECURE_CSP.contains("upgrade-insecure-requests"));
    }

    #[test]
    fn test_strict_csp_for_api() {
        // Verify that strict CSP for APIs is very restrictive
        assert!(STRICT_CSP.contains("default-src 'none'"));
        assert!(STRICT_CSP.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_websocket_csp() {
        // Verify that WebSocket CSP allows WebSocket connections
        assert!(WEBSOCKET_CSP.contains("connect-src 'self' ws: wss:"));
        assert!(WEBSOCKET_CSP.contains("frame-ancestors 'none'"));
    }
}