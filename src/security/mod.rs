//! Security utilities and middleware

pub mod headers;
pub mod timing;
pub mod csrf;
pub mod unicode_validation;
pub mod xss;
pub mod production_warnings;

pub use headers::{add_security_headers, security_headers, with_security_headers};
pub use timing::{constant_time_eq, constant_time_eq_bytes, add_auth_delay, AuthTimer};
pub use csrf::{CSRFProtection, CSRFValidationResult};
pub use unicode_validation::{
    UnicodeSecurityValidator, UnicodeSecurityConfig, UnicodeSecurityError, 
    SafeUnicodeText, UnicodeScript
};
pub use xss::{
    encode_html, escape_javascript, sanitize_html, sanitize_url, protect_user_content,
    sanitize_json_content, contains_xss_patterns, clean_user_input, validate_html_attribute
};
pub use production_warnings::{
    ProductionChecker, ProductionWarning, init_production_warnings, get_production_checker
};