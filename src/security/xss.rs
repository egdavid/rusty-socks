//! XSS (Cross-Site Scripting) protection module
//! 
//! This module provides comprehensive XSS protection including:
//! - HTML entity encoding
//! - JavaScript string escaping
//! - URL encoding
//! - Content validation

use serde_json::Value;

/// HTML entities for encoding special characters
const HTML_ENTITIES: &[(&str, &str)] = &[
    ("&", "&amp;"),   // Must be first to avoid double encoding
    ("<", "&lt;"),
    (">", "&gt;"),
    ("\"", "&quot;"),
    ("'", "&#x27;"),
    ("/", "&#x2F;"),
    ("`", "&#x60;"),
    ("=", "&#x3D;"),
];

/// JavaScript special characters that need escaping
const JS_ESCAPES: &[(&str, &str)] = &[
    ("\\", "\\\\"),   // Must be first
    ("\"", "\\\""),
    ("'", "\\'"),
    ("\n", "\\n"),
    ("\r", "\\r"),
    ("\t", "\\t"),
    ("\u{08}", "\\b"),
    ("\u{0C}", "\\f"),
    ("/", "\\/"),
];


/// URL schemes that are potentially dangerous
const DANGEROUS_SCHEMES: &[&str] = &[
    "javascript:", "data:", "vbscript:", "file:", "ftp:"
];

/// Encode HTML entities to prevent XSS attacks
pub fn encode_html(input: &str) -> String {
    let mut result = input.to_string();
    
    for (char, entity) in HTML_ENTITIES {
        result = result.replace(char, entity);
    }
    
    result
}

/// Decode HTML entities (for internal processing only)
pub fn decode_html(input: &str) -> String {
    let mut result = input.to_string();
    
    // Reverse order to avoid issues with overlapping replacements
    for (char, entity) in HTML_ENTITIES.iter().rev() {
        result = result.replace(entity, char);
    }
    
    result
}

/// Escape JavaScript strings to prevent injection
pub fn escape_javascript(input: &str) -> String {
    let mut result = input.to_string();
    
    for (char, escape) in JS_ESCAPES {
        result = result.replace(char, escape);
    }
    
    result
}

/// Sanitize content by removing dangerous HTML
pub fn sanitize_html(input: &str) -> String {
    let mut result = input.to_string();
    
    // First, encode all HTML to prevent any injection
    result = encode_html(&result);
    
    // Additional aggressive filtering for dangerous patterns
    let dangerous_words = ["script", "javascript", "vbscript", "onload", "onclick", "alert", "eval"];
    for word in dangerous_words {
        result = result.replace(word, &format!("[removed-{}]", word));
    }
    
    result
}

/// Validate and sanitize URLs to prevent XSS
pub fn sanitize_url(url: &str) -> Option<String> {
    let url_lower = url.to_lowercase().trim().to_string();
    
    // Check for dangerous schemes
    for scheme in DANGEROUS_SCHEMES {
        if url_lower.starts_with(scheme) {
            log::warn!("Blocked dangerous URL scheme: {}", scheme);
            return None;
        }
    }
    
    // Allow only http, https, and relative URLs
    if url_lower.starts_with("http://") || url_lower.starts_with("https://") || url_lower.starts_with("/") {
        Some(encode_html(url))
    } else {
        log::warn!("Blocked potentially unsafe URL: {}", url);
        None
    }
}

/// Comprehensive XSS protection for user content
pub fn protect_user_content(content: &str) -> String {
    // Step 1: Use sanitize_html which includes encoding
    let mut protected = sanitize_html(content);
    
    // Step 2: Length limit to prevent DoS
    if protected.len() > 10000 {
        log::warn!("Content truncated due to excessive length");
        protected.truncate(10000);
        protected.push_str("...[truncated]");
    }
    
    protected
}

/// Validate and sanitize JSON content for XSS
pub fn sanitize_json_content(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(protect_user_content(s)),
        Value::Array(arr) => {
            Value::Array(arr.iter().map(sanitize_json_content).collect())
        }
        Value::Object(obj) => {
            let mut sanitized = serde_json::Map::new();
            for (k, v) in obj {
                let safe_key = protect_user_content(k);
                let safe_value = sanitize_json_content(v);
                sanitized.insert(safe_key, safe_value);
            }
            Value::Object(sanitized)
        }
        _ => value.clone(),
    }
}

/// Check if content contains potential XSS patterns
pub fn contains_xss_patterns(content: &str) -> bool {
    let content_lower = content.to_lowercase();
    
    let xss_patterns = [
        "javascript:",
        "vbscript:",
        "data:",
        "<script",
        "</script",
        "onload=",
        "onclick=",
        "onerror=",
        "onmouseover=",
        "onfocus=",
        "eval(",
        "expression(",
        "url(",
        "import(",
    ];
    
    for pattern in &xss_patterns {
        if content_lower.contains(pattern) {
            log::warn!("Potential XSS pattern detected: {}", pattern);
            return true;
        }
    }
    
    false
}

/// Content Security Policy nonce generator
pub fn generate_csp_nonce() -> String {
    use rand::Rng;
    use base64::Engine;
    
    let mut rng = rand::thread_rng();
    let nonce_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    base64::engine::general_purpose::STANDARD.encode(&nonce_bytes)
}

/// Validate that content is safe for embedding in HTML attributes
pub fn validate_html_attribute(content: &str) -> bool {
    // Check for quotes and other dangerous characters
    let dangerous_chars = ['<', '>', '"', '\'', '&', '\n', '\r', '\t'];
    
    for &ch in &dangerous_chars {
        if content.contains(ch) {
            return false;
        }
    }
    
    !contains_xss_patterns(content)
}

/// Clean and validate user input for room names, usernames, etc.
pub fn clean_user_input(input: &str) -> Option<String> {
    let trimmed = input.trim();
    
    // Basic validation
    if trimmed.is_empty() || trimmed.len() > 100 {
        return None;
    }
    
    // Check for XSS patterns
    if contains_xss_patterns(trimmed) {
        log::warn!("Input rejected due to XSS patterns: {}", trimmed);
        return None;
    }
    
    // Allow only alphanumeric, spaces, hyphens, underscores, dots
    let cleaned: String = trimmed
        .chars()
        .filter(|&c| c.is_alphanumeric() || c.is_whitespace() || c == '-' || c == '_' || c == '.')
        .collect();
    
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_encoding() {
        assert_eq!(encode_html("<script>alert('xss')</script>"), 
                   "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;");
        assert_eq!(encode_html("Hello & goodbye"), "Hello &amp; goodbye");
        assert_eq!(encode_html("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_javascript_escaping() {
        assert_eq!(escape_javascript("alert('test')"), "alert(\\'test\\')");
        assert_eq!(escape_javascript("var x = \"hello\";"), "var x = \\\"hello\\\";");
        assert_eq!(escape_javascript("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_url_sanitization() {
        assert_eq!(sanitize_url("https://example.com"), Some("https:&#x2F;&#x2F;example.com".to_string()));
        assert_eq!(sanitize_url("javascript:alert(1)"), None);
        assert_eq!(sanitize_url("data:text/html,<script>"), None);
        assert_eq!(sanitize_url("/relative/path"), Some("&#x2F;relative&#x2F;path".to_string()));
    }

    #[test]
    fn test_xss_pattern_detection() {
        assert!(contains_xss_patterns("<script>alert(1)</script>"));
        assert!(contains_xss_patterns("javascript:alert(1)"));
        assert!(contains_xss_patterns("onload=alert(1)"));
        assert!(!contains_xss_patterns("Hello world"));
        assert!(!contains_xss_patterns("This is safe content"));
    }

    #[test]
    fn test_html_attribute_validation() {
        assert!(validate_html_attribute("safe-value"));
        assert!(validate_html_attribute("123"));
        assert!(!validate_html_attribute("value\"with\"quotes"));
        assert!(!validate_html_attribute("<script>"));
        assert!(!validate_html_attribute("javascript:alert(1)"));
    }

    #[test]
    fn test_user_input_cleaning() {
        assert_eq!(clean_user_input("  valid-name_123  "), Some("valid-name_123".to_string()));
        assert_eq!(clean_user_input("<script>alert(1)</script>"), None);
        assert_eq!(clean_user_input("user@domain.com"), Some("userdomain.com".to_string())); // @ is removed, . is kept
        assert_eq!(clean_user_input(""), None);
        assert_eq!(clean_user_input("   "), None);
    }

    #[test]
    fn test_comprehensive_protection() {
        let malicious = "<script>alert('xss')</script>";
        let protected = protect_user_content(malicious);
        assert!(!protected.contains("<script"));
        assert!(!protected.contains("alert('xss')")); // The actual dangerous pattern should be gone
        assert!(protected.contains("[removed-")); // Should contain removal markers
    }

    #[test]
    fn test_json_sanitization() {
        let malicious_json = serde_json::json!({
            "message": "<script>alert('xss')</script>",
            "user": "safe_user",
            "nested": {
                "dangerous": "javascript:alert(1)"
            }
        });
        
        let sanitized = sanitize_json_content(&malicious_json);
        let sanitized_str = sanitized.to_string();
        assert!(!sanitized_str.contains("<script"));
        assert!(!sanitized_str.contains("alert('xss')")); // The actual dangerous pattern should be gone
        assert!(sanitized_str.contains("[removed-")); // Should contain removal markers
    }
}