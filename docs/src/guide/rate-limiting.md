# Rate Limiting

Rusty Socks v0.2.0 provides **IP-based rate limiting** for WebSocket connections and per-user message rate limiting. This guide explains how to configure and use them, how the **IpConnectionGuard** ensures cleanup via the `Drop` trait, and how HTTP 429 rejections are returned.

## IP-Based Rate Limiting

### Overview

Before a WebSocket connection is upgraded, the server:

1. Extracts the client IP (from headers or remote address).
2. Checks whether that IP is allowed to open another connection (`can_ip_connect`).
3. Reserves a slot for that IP (`register_ip_connection`).

If either the check or the registration fails, the request is **rejected with HTTP 429 Too Many Requests**. The connection is never upgraded, so the client does not consume a WebSocket handler slot.

### Configuration

Connection limits are read from the environment when building `ServerConfig` (e.g. `ServerConfig::from_env()`).

| Environment variable | Description | Default |
|----------------------|-------------|---------|
| `RUSTY_SOCKS_MAX_CONN_PER_IP` | Maximum simultaneous WebSocket connections per IP | `10` |

The server builds the `ServerManager` with these values (e.g. `ServerManager::with_rate_limits(max_connections_per_ip, max_messages_per_minute)`), so the `ConnectionLimiter` inside the manager uses the configured cap.

### How It Works in Code

- **ConnectionLimiter** (`core::rate_limiter`):
  - `allow_connection(ip)` — returns whether `current_count < max_connections_per_ip`.
  - `add_connection(ip)` — increments the count for that IP if under the limit; returns `false` if the limit is already reached.
  - `remove_connection(ip)` — decrements the count and removes the entry when it reaches zero.

- In the WebSocket route (`src/bin/server.rs`), the flow is:
  - `server_manager.can_ip_connect(client_ip).await` → if `false`, reject with `RateLimitRejection`.
  - `server_manager.register_ip_connection(client_ip).await` → if `false` (e.g. race where the limit was reached), reject with `RateLimitRejection`.
  - Then proceed to upgrade. When the handler finishes (or is never run because the pool rejected the task), the IP slot must be released; that is done by **IpConnectionGuard** (see below).

## IpConnectionGuard and Resource Cleanup via Drop

Each WebSocket connection handler holds an **IpConnectionGuard** that ties the connection’s lifetime to the IP slot. When the handler exits (normally or by panic), the guard is dropped and the slot is released.

### Definition (`handlers::websocket`)

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

At the start of `handle_ws_client`, the handler creates a guard and keeps it for the duration of the function:

```rust
let _ip_guard = IpConnectionGuard {
    server_manager: server_manager.clone(),
    ip: client_ip,
};
```

### Why Drop and tokio::spawn

- `Drop` in Rust is synchronous and cannot be `async`. So the guard cannot directly `await unregister_ip_connection`.
- The implementation therefore spawns a new task that performs `unregister_ip_connection(ip).await`. That task runs on the current runtime and eventually decrements the IP’s connection count and removes the slot if it reaches zero.
- Because the guard is stored in the handler’s stack frame, it is always dropped when the handler returns or panics. That guarantees the IP slot is released even on early returns (e.g. after an authentication failure) or on panic, avoiding connection-count leaks.

This pattern is the RAII approach for async cleanup: the guard owns the “reservation” of the IP slot, and `Drop` ensures release regardless of control flow.

## HTTP 429 Rejections

When the server rejects a request due to rate limiting, it uses a custom rejection type and a recovery handler so the client receives a proper HTTP response.

### Rejection Type

In `src/bin/server.rs`:

```rust
struct RateLimitRejection;

impl warp::reject::Reject for RateLimitRejection {}
```

This type is used when:

- `can_ip_connect(client_ip)` returns `false` (IP already at its connection limit).
- `register_ip_connection(client_ip)` returns `false` (e.g. limit reached in a race).
- Optionally, other rate-limit conditions could be mapped to the same rejection in the future.

### Recovery and Response Body

The `handle_rejection` function maps `RateLimitRejection` to HTTP 429 with a JSON body:

```rust
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    if err.find::<RateLimitRejection>().is_some() {
        let body = warp::reply::json(&serde_json::json!({"error": "Too Many Requests"}));
        return Ok(warp::reply::with_status(body, StatusCode::TOO_MANY_REQUESTS));
    }
    // ... other rejections
}
```

### Example Client-Side Behavior

When the server returns 429:

- **Status code**: `429 Too Many Requests`.
- **Body** (typical): `{"error":"Too Many Requests"}`.

Example with `curl` (connection refused at application level after TCP connect; the server may close the connection or respond with 429 depending on where the limit is applied):

```text
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"error":"Too Many Requests"}
```

Clients should treat 429 as a signal to back off (e.g. exponential backoff or retry-after if the server adds that header in the future) and not open more connections from the same IP until some connections are closed.

## Per-User Message Rate Limiting

In addition to IP-based connection limits, the server limits how many messages each user can send per minute. This is configured via `RUSTY_SOCKS_RATE_LIMIT_MSG_PER_MIN` (default 60). When exceeded, the server does not return HTTP 429 for the WebSocket upgrade; instead, it rejects the individual message and can send a WebSocket frame or message with a rate-limit error (e.g. `RATE_LIMITED`). See the message handler and server API for the exact error payloads. The 429 response described above is specifically for **connection** rate limiting (too many connections per IP).
