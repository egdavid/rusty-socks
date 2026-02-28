# Security Model

Rusty Socks v0.2.0 follows a **Security-First** approach aligned with the 2026 security audit. This document covers XSS/CSRF protections, Unicode validation, and connection-exhaustion protection.

## Security-First Approach (2026 Baseline)

The 2026 audit established a baseline for secure WebSocket servers: defense in depth, safe handling of user input, protection against cross-site and abuse vectors, and resource limits to prevent exhaustion. Rusty Socks v0.2.0 implements these principles as follows:

- **No blocking in the request path** — avoids runtime stalls and improves resilience under load.
- **Layered validation** — CSRF and origin checks before upgrade; IP rate limiting; then authentication and message/Unicode validation.
- **Strict input validation** — Unicode security and XSS mitigations on all user-supplied content.
- **Resource caps** — thread pool task limits, per-IP connection limits, and per-user message rate limits to prevent connection and memory exhaustion.

These improvements are cited as stemming from the 2026 audit baseline.

## XSS and CSRF Protections

### CSRF (Cross-Site Request Forgery)

WebSocket connections are validated for CSRF **before** the upgrade handshake. The `CSRFProtection` type (`security::csrf`) is used in a Warp filter that runs on every WebSocket request.

**`validate_websocket_connection(&self, headers: &HeaderMap) -> CSRFValidationResult`** performs:

1. **Origin header** — Must match the configured allowed origins (or, in development mode with no list, allowed localhost origins). Requests with missing or disallowed `Origin` are rejected.
2. **Host header** — Checked for suspicious values to mitigate Host header injection.
3. **Automation headers** — Presence of headers that often indicate scripts/bots can result in `Suspicious`.
4. **Upgrade header** — Must be present and equal to `websocket` (case-insensitive); otherwise `MissingHeaders` or `Suspicious`.

Results are one of: `Valid`, `InvalidOrigin`, `InvalidToken`, `InvalidReferer`, `MissingHeaders`, `Suspicious`. The server applies `csrf_validation_filter` in the WebSocket route; any result other than `Valid` leads to rejection (e.g. `CSRFRejection`). Configuration uses `RUSTY_SOCKS_ALLOWED_ORIGINS`, `development_mode`, and a dedicated `RUSTY_SOCKS_CSRF_SECRET` (distinct from the JWT secret).

### XSS (Cross-Site Scripting)

The `security::xss` module provides output encoding and sanitization so user content cannot be interpreted as HTML or script:

- **`encode_html`** — Encodes `&`, `<`, `>`, `"`, `'`, `/`, `` ` ``, `=` to HTML entities.
- **`escape_javascript`** — Escapes backslash, quotes, newlines, and other characters for safe use in JS strings.
- **`sanitize_html`** — Applies HTML encoding and replaces dangerous tokens (e.g. `script`, `javascript`, `onload`, `onclick`, `alert`, `eval`) with safe placeholders.
- **`sanitize_url`** — Rejects dangerous schemes (`javascript:`, `data:`, `vbscript:`, `file:`, `ftp:`) and returns a safe encoded string or `None`.
- **`protect_user_content`** / **`sanitize_json_content`** — Used to sanitize user-supplied strings and JSON before rendering or storage.

Message content is validated for Unicode first (see below), then XSS protections are applied before broadcast or persistence, reducing the risk of stored or reflected XSS.

## Unicode Validation

User-supplied text (messages, room names) is validated with **`UnicodeSecurityValidator`** (`security::unicode_validation`) to block Unicode-based abuse and spoofing.

### Error Types (`UnicodeSecurityError`)

- **ControlCharacters** — Dangerous control characters (e.g. C0/C1, BiDi formatting).
- **BidirectionalOverride** — Use of override isolates/embeds (e.g. RLO, LRO) that can hide or reorder text.
- **HomographAttack** — Lookalike characters (e.g. Cyrillic/Greek lookalikes for Latin) used to deceive.
- **MixedScriptAttack** — Mixed scripts in a single string in a way that is disallowed by config.
- **InvalidUnicode** — Invalid or non-character code points.
- **NormalizationAttack** / **NormalizationExpansion** — Abuse of normalization or excessive length after normalization.
- **InvisibleCharacters** — Zero-width or other invisible characters.
- **PrivateUseCharacters** — Characters from private use areas.

Configuration is via **`UnicodeSecurityConfig`** (e.g. `max_normalized_length`, `allow_mixed_scripts`, `allow_bidirectional`, `allow_private_use`, `allowed_scripts`, `max_normalization_expansion`). The message handler and room-creation logic call the validator and reject invalid content with clear error codes (e.g. `INVALID_MESSAGE`, `INVALID_UNICODE`, `NORMALIZATION_ATTACK`).

## Connection-Exhaustion Protection

Multiple layers prevent a single client or a flood of connections from exhausting server resources.

### Thread Pool Limits

The custom **ThreadPool** (`core::thread_pool`) enforces:

- **Max queued tasks** — No more than `max_queued_tasks` (default 1000) concurrent tasks; additional submissions receive `None` from `execute()`.
- **Task submission rate** — At most `(workers * 100).min(1000)` tasks per second; excess submissions are rejected.

When the pool rejects a connection, the server does not upgrade the WebSocket and releases the IP slot (e.g. via `unregister_ip_connection`), so the connection count does not grow unbounded.

### Per-IP Connection Limit

**ConnectionLimiter** (`core::rate_limiter`) caps the number of simultaneous WebSocket connections per IP. Before each upgrade, the server calls `can_ip_connect(client_ip)` and then `register_ip_connection(client_ip)`. If either fails, the request is rejected with HTTP 429. The limit is configured by `max_connections_per_ip` (e.g. `RUSTY_SOCKS_MAX_CONNECTIONS_PER_IP`). An **IpConnectionGuard** in the WebSocket handler ensures the slot is released on disconnect (see [Rate Limiting](../guide/rate-limiting.md)).

### Per-User and Global Message Limits

**MessageRateLimiter** (`core::rate_limiter`) limits how many messages each user can send per minute (sliding window) and enforces a global cap. It also bounds the number of tracked users (e.g. 10_000) to avoid unbounded memory use. When a user exceeds the limit, the server returns a rate-limit error (e.g. `RATE_LIMITED`) instead of processing the message.

Together, thread pool limits, per-IP connection limits, and per-user message limits form the connection-exhaustion protection that the 2026 audit recommends for production WebSocket servers.
