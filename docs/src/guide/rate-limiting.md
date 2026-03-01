# Rate Limiting

This guide covers our **IP-based** connection rate limiting and per-user message limits. We'll explain how to configure them, how the **IpConnectionGuard** makes sure we always release an IP slot when a connection ends (even on panic or early return), and what clients see when they hit a limit (HTTP 429). If you're integrating a client or tuning for production, you'll find this useful.

## IP-Based Rate Limiting

### What Happens Before the Upgrade

Before we upgrade a WebSocket, we: (1) figure out the client IP (from headers or remote address), (2) check whether that IP is allowed to open another connection (`can_ip_connect`), and (3) reserve a slot for that IP (`register_ip_connection`). If either the check or the reservation fails, we **reject the request with HTTP 429** and never upgrade. So the client never gets a WebSocket handler; they just get a 429 and should back off.

### Configuration

Limits are read from the environment when we build `ServerConfig` (e.g. `ServerConfig::from_env()`).

| Environment variable | What it does | Default |
|----------------------|--------------|---------|
| `RUSTY_SOCKS_MAX_CONN_PER_IP` | Max simultaneous WebSocket connections per IP | `10` |

The server passes this into `ServerManager::with_rate_limits(...)`, and the `ConnectionLimiter` inside the manager enforces it. Be careful with very low values: legitimate multi-tab or multi-device users from the same NAT can hit the limit quickly.

### In Code

**ConnectionLimiter** (`core::rate_limiter`) has: `allow_connection(ip)` (are we under the cap?), `add_connection(ip)` (reserve a slot; returns `false` if already at limit), and `remove_connection(ip)` (release the slot). In the WebSocket route we call `can_ip_connect` then `register_ip_connection`; if either fails we reject with `RateLimitRejection`. When the handler eventually exits (or never runs because the pool rejected the task), we need to release the slot—that's the **IpConnectionGuard**'s job, below.

## IpConnectionGuard: Why We Use a Guard and Drop

Each WebSocket handler holds an **IpConnectionGuard** that ties the connection's lifetime to the IP slot. When the handler exits—whether it returns normally, returns early after an auth failure, or panics—the guard is dropped and we release the slot. You don't have to remember to call `unregister_ip_connection` yourself.

> **Developer Insight**  
> The 2026 audit pointed out that it's easy to leak connection slots if you only call `unregister_ip_connection` on the "happy path." Any early return or panic could skip that call, and over time you'd run out of slots for that IP (or globally). We chose a **RAII guard** so that release happens in `Drop`—Rust guarantees `Drop` runs when the guard goes out of scope, no matter how we left the function. So we get cleanup on success, on error, and on panic. That's why you'll see the guard created at the very start of `handle_ws_client` and held for the whole function.

### How It's Implemented

`Drop` in Rust is synchronous and can't be `async`, so we can't directly `await unregister_ip_connection` inside `drop`. Instead we spawn a small task that does the async unregister. The guard just holds the `ServerManager` and the IP; when it's dropped, we `tokio::spawn` that task and the slot gets released when the task runs. Because the guard lives in the handler's stack frame, it's always dropped when the handler returns or panics—so we never leak the slot.

```rust
/// Guard that calls `unregister_ip_connection` when dropped (e.g. on any return path or panic).
/// Uses `tokio::spawn` in `Drop` because `Drop` cannot be async.
struct IpConnectionGuard {
    server_manager: SharedServerManager,
    ip: IpAddr,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        let server_manager = self.server_manager.clone();
        let ip = self.ip;
        tokio::spawn(async move {
            server_manager.unregister_ip_connection(ip).await;
        });
    }
}
```

At the top of `handle_ws_client` we create the guard and keep it for the duration:

```rust
let _ip_guard = IpConnectionGuard {
    server_manager: server_manager.clone(),
    ip: client_ip,
};
```

You'll find it useful to keep this pattern in mind if you ever add new exit paths in the handler: the guard will still run, so you don't need to add manual cleanup there.

## HTTP 429: What the Client Sees

When we reject a request for rate limiting, we use a custom rejection type (`RateLimitRejection`) and a recovery handler so the client gets a proper HTTP response instead of a generic error.

We use `RateLimitRejection` when: `can_ip_connect` returns `false` (IP already at its connection limit), or `register_ip_connection` returns `false` (e.g. limit hit in a race). Our `handle_rejection` function turns that into **429 Too Many Requests** with a JSON body `{"error":"Too Many Requests"}`. So when you're testing or building a client, treat 429 as "too many connections from this IP; back off and maybe close some connections before retrying." We don't return 429 for per-user *message* rate limiting—that's handled inside the WebSocket with a different error (e.g. `RATE_LIMITED`). The 429 here is specifically for **connection** rate limiting.

Example response:

```text
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"error":"Too Many Requests"}
```

Clients should back off (e.g. exponential backoff) and avoid opening more connections from the same IP until some are closed.

## Per-User Message Rate Limiting

Besides per-IP connection limits, we limit how many messages each user can send per minute. That's configured via `RUSTY_SOCKS_RATE_LIMIT_MSG_PER_MIN` (default 60). When a user exceeds it, we don't close the WebSocket or return 429 on the HTTP side—we reject the individual message and can send a WebSocket frame with a rate-limit error (e.g. `RATE_LIMITED`). So: 429 = too many *connections* from this IP; in-stream rate limit = too many *messages* from this user. See the message handler and server API for the exact payloads.
