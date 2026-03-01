//! Worker-only utilities (panic hook for readable Cloudflare logs).

use console_error_panic_hook;

/// Set panic hook so panics show up as readable messages in Cloudflare logs.
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}
