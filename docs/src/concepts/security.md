# Security Model

We take a **security-first** approach. This page explains how we think about it (and how the 2026 audit shaped our choices), then walks through XSS/CSRF, Unicode validation, and connection-exhaustion protection. If you're contributing or deploying, you'll want to understand these layers.

## How We Think About Security (2026 Baseline)

The 2026 audit gave us a clear baseline: defense in depth, safe handling of user input, protection against cross-site and abuse, and hard limits so one bad actor can't exhaust resources. We've wired that into the design:

- **No blocking in the request path** — keeps the runtime responsive and avoids a whole class of stalls under load.
- **Layered validation** — we check CSRF and origin before we even upgrade; then IP rate limit; then auth and message/Unicode validation. So by the time we're doing real work, we've already said no to a lot of bad traffic.
- **Strict input validation** — every user-supplied string goes through Unicode security and XSS mitigations. We'd rather reject weird input than risk it later.
- **Resource caps** — thread pool, per-IP connections, and per-user message rate limits. Together they prevent connection and memory exhaustion.

You'll find it useful to keep "layers" in mind: we don't rely on one check; we stack them.

<div class="callout security-alert">

The layered approach (CSRF before upgrade, then rate limit, then auth and validation) was explicitly recommended in the 2026 audit to reduce attack surface before any application logic runs.

</div>

## XSS and CSRF Protections

### CSRF: We Validate Before the Handshake

We validate WebSocket connections for CSRF **before** the upgrade. So if the Origin (or Host, or something else) looks wrong, we never open the WebSocket. The `CSRFProtection` type lives in `security::csrf` and is used in a Warp filter that runs on every WebSocket request.

`validate_websocket_connection` does the following: (1) **Origin** must match our allowed list (or localhost in dev when the list is empty); (2) **Host** is checked for suspicious values; (3) we look for headers that often indicate scripts/bots and mark the request **Suspicious** if we see them; (4) the **Upgrade** header must be present and equal to `websocket`. If any of that fails, we reject with a `CSRFRejection`. Configuration is via `RUSTY_SOCKS_ALLOWED_ORIGINS`, `development_mode`, and a dedicated `RUSTY_SOCKS_CSRF_SECRET`—we keep that separate from the JWT secret so a leak in one doesn't compromise the other.

### XSS: Encode and Sanitize Before Output

The `security::xss` module is there so user content never gets interpreted as HTML or script. We have `encode_html`, `escape_javascript`, `sanitize_html`, `sanitize_url`, and helpers like `protect_user_content` / `sanitize_json_content`.

<div class="callout developer-insight">

When adding a new code path that outputs user-supplied data, always run it through Unicode validation first, then through the appropriate XSS helper (`encode_html`, `sanitize_json_content`, etc.) before it hits the wire or storage. That way we avoid stored and reflected XSS.

</div>

## Unicode Validation

User text (messages, room names) goes through **UnicodeSecurityValidator** in `security::unicode_validation`. We block control characters, bidirectional overrides (that can hide or reorder text), homograph lookalikes, mixed scripts when we don't allow them, invalid or private-use characters, invisible/zero-width characters, and normalization abuse. The validator returns clear error types (`UnicodeSecurityError`) so the message handler can send back something like `INVALID_MESSAGE` or `NORMALIZATION_ATTACK` instead of a generic 500. You'll find the config in `UnicodeSecurityConfig` (max length, whether we allow mixed scripts, etc.). We use it in both message handling and room creation.

## Connection-Exhaustion Protection

We don't want a single IP or a flood of connections to exhaust the server. So we cap things in three places.

### Thread Pool

The custom **ThreadPool** won't accept more than `max_queued_tasks` concurrent tasks, and it rate-limits how many tasks we accept per second. When the pool says no, we don't upgrade the WebSocket and we release the IP slot, so the total connection count doesn't grow unbounded.

### Per-IP Connection Limit

**ConnectionLimiter** (`core::rate_limiter`) caps how many WebSockets one IP can have open. Before each upgrade we call `can_ip_connect` and then `register_ip_connection`. If either fails, we return HTTP 429. The limit is configured by `max_connections_per_ip` (e.g. `RUSTY_SOCKS_MAX_CONN_PER_IP`). Releasing the slot when the client disconnects is handled by **IpConnectionGuard**—we have a whole section on that in the [Rate Limiting](../guide/rate-limiting.md) guide, including why the 2026 audit pushed us to do it with a guard.

### Per-User and Global Message Limits

**MessageRateLimiter** limits messages per user per minute (sliding window) and enforces a global cap. We also cap how many users we track (e.g. 10k) so memory doesn't blow up. When a user goes over the limit, we return a rate-limit error for that message instead of processing it. Together with the thread pool and per-IP limits, this is the connection-exhaustion story the 2026 audit asked for.
