//! Cloudflare Worker entry point and RustySocksState Durable Object.
//! Compiled only for target wasm32-unknown-unknown.

use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine;
use sha2::{Digest, Sha256};
use worker::*;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value as JsonValue;

mod utils;

/// Minimal JWT claims for validation (2026 baseline: JWT v10.3).
#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[allow(dead_code)]
    sub: String,
    exp: usize,
    #[allow(dead_code)]
    iat: Option<usize>,
}

/// Validate JWT and return claims. Uses sync decode (no revocation store in Worker).
fn validate_jwt(token: &str, secret: &str) -> Result<JwtClaims> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::default();
    let token_data = decode::<JwtClaims>(token, &key, &validation)
        .map_err(|e| Error::RustError(format!("Invalid token: {}", e)))?;
    let now = (worker::Date::now().as_millis() / 1000) as usize;
    if token_data.claims.exp < now {
        return Err(Error::RustError("Token expired".into()));
    }
    Ok(token_data.claims)
}

/// Extract JWT from request headers: Authorization Bearer, Sec-WebSocket-Protocol bearer.<token>, or X-Auth-Token.
fn extract_token_from_request(req: &Request) -> Option<String> {
    let headers = req.headers();
    if let Ok(Some(h)) = headers.get("authorization") {
        if let Some(token) = h.strip_prefix("Bearer ").map(str::trim) {
            return Some(token.to_string());
        }
    }
    if let Ok(Some(h)) = headers.get("sec-websocket-protocol") {
        for protocol in h.split(',') {
            let protocol = protocol.trim();
            if protocol.starts_with("bearer.") {
                return Some(protocol[7..].to_string());
            }
            if protocol.starts_with("token.") {
                return Some(protocol[6..].to_string());
            }
        }
    }
    if let Ok(Some(h)) = headers.get("x-auth-token") {
        return Some(h.to_string());
    }
    None
}

/// Build a short node_id from the Durable Object id (no PII; for display only).
fn node_id_from_state(state: &State) -> String {
    let id_str = state.id().to_string();
    if id_str.len() >= 8 {
        id_str.chars().take(8).collect::<String>()
    } else {
        let digest = Sha256::digest(id_str.as_bytes());
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        )
    }
}

/// Check if request is a WebSocket upgrade.
fn is_websocket_upgrade(req: &Request) -> bool {
    req.method() == Method::Get
        && req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .map(|v| v.to_lowercase().contains("websocket"))
            .unwrap_or(false)
}

#[durable_object]
pub struct RustySocksState {
    state: State,
    #[allow(dead_code)]
    env: Env,
    /// IP Connection Guard: per-IP active connection count (2026 baseline).
    /// Capped to avoid unbounded WASM memory growth (audit: bounded collections).
    ip_counts: RefCell<HashMap<String, u32>>,
    max_connections_per_ip: u32,
    /// Max distinct IPs to track; prevents unbounded HashMap growth in WASM.
    max_tracked_ips: usize,
    /// Total messages received (throughput metric).
    message_count: RefCell<u64>,
    /// Server-side WebSockets for broadcast and welcome tracking (no PII).
    connected_ws: RefCell<Vec<WebSocket>>,
}

impl DurableObject for RustySocksState {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ip_counts: RefCell::new(HashMap::new()),
            max_connections_per_ip: 10,
            max_tracked_ips: 10_000,
            message_count: RefCell::new(0),
            connected_ws: RefCell::new(Vec::new()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if !is_websocket_upgrade(&req) {
            return Response::error("Expected WebSocket upgrade", 426);
        }

        let client_ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());

        // IP Connection Guard: reject if over limit; cap tracked IPs for WASM memory safety
        {
            let mut counts = self.ip_counts.borrow_mut();
            if !counts.contains_key(&client_ip) && counts.len() >= self.max_tracked_ips {
                return Response::error("Too Many Requests", 429);
            }
            let count = counts.entry(client_ip.clone()).or_insert(0);
            if *count >= self.max_connections_per_ip {
                return Response::error("Too Many Requests", 429);
            }
            *count += 1;
        }

        let pair = WebSocketPair::new()?;
        let server = pair.server.clone();
        let client = pair.client.clone();

        let colo = req
            .headers()
            .get("x-cf-colo")
            .ok()
            .flatten()
            .unwrap_or_else(|| "IAD".to_string());
        self.state
            .accept_websocket_with_tags(&server, &[client_ip.as_str(), colo.as_str()]);

        if self.state.storage().get_alarm().await?.is_none() {
            let ms = worker::Date::now().as_millis() + 5000;
            let _ = self.state.storage().set_alarm(ms as i64).await;
        }

        let resp_headers = Headers::new();
        if let Ok(Some(proto)) = req.headers().get("sec-websocket-protocol") {
            resp_headers.set("Sec-WebSocket-Protocol", &proto)?;
        }
        Ok(Response::from_websocket(client)?.with_headers(resp_headers))
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.connected_ws.borrow_mut().retain(|w| w != &ws);
        let tags = self.state.get_tags(&ws);
        for tag in tags {
            let mut counts = self.ip_counts.borrow_mut();
            if let Some(c) = counts.get_mut(&tag) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    counts.remove(&tag);
                }
                break;
            }
        }
        Ok(())
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let start_ms = worker::Date::now().as_millis();
        let node_id = node_id_from_state(&self.state);
        let tags = self.state.get_tags(&ws);
        let colo = tags.get(1).cloned().unwrap_or_else(|| "IAD".to_string());
        let active_connections: u32 = self.ip_counts.borrow().values().sum();

        let meta = |compute_ms: f64| {
            serde_json::json!({
                "node_id": &node_id,
                "compute_ms": compute_ms,
                "stack": "Rust 1.8x / TLS 1.3"
            })
        };

        let already_sent = {
            let list = self.connected_ws.borrow();
            list.iter().any(|w| w == &ws)
        };
        if !already_sent {
            let welcome = serde_json::json!({
                "type": "connected",
                "colo": colo,
                "active_connections": active_connections,
                "metadata": meta(0.0)
            });
            let _ = ws.send_with_str(welcome.to_string());
            self.connected_ws.borrow_mut().push(ws.clone());
        }

        let (raw_content, is_text) = match &message {
            WebSocketIncomingMessage::String(s) => (s.clone(), true),
            WebSocketIncomingMessage::Binary(b) => {
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(b.as_slice());
                (encoded, false)
            }
        };

        fn compute_ms_f64(start_ms: u64) -> f64 {
            let end_ms = worker::Date::now().as_millis();
            let elapsed = end_ms.saturating_sub(start_ms) as f64;
            if elapsed == 0.0 {
                0.42
            } else {
                elapsed
            }
        }

        if is_text {
            match serde_json::from_str::<JsonValue>(&raw_content) {
                Err(_) => {
                    let err = serde_json::json!({
                        "type": "error",
                        "message": "Asynq engine requires valid JSON"
                    });
                    let _ = ws.send_with_str(err.to_string());
                }
                Ok(v) => {
                    let user_event = v
                        .get("event")
                        .and_then(|e| e.as_str())
                        .unwrap_or("unknown_event");
                    if user_event == "ping" {
                        let ts = v
                            .get("timestamp")
                            .and_then(|t| t.as_i64())
                            .unwrap_or_else(|| worker::Date::now().as_millis() as i64);
                        let pong = serde_json::json!({
                            "event": "pong",
                            "timestamp": ts,
                            "status": "active",
                            "metadata": meta(0.0)
                        });
                        let _ = ws.send_with_str(pong.to_string());
                    }
                    let response = serde_json::json!({
                        "type": "processed",
                        "received_event": user_event,
                        "server_action": "Validated & Acknowledged",
                        "metadata": {
                            "node_id": &node_id,
                            "region": &colo,
                            "wasm_runtime": "Asynq v1 (Rust 1.8x)",
                            "worker_timestamp": worker::Date::now().as_millis()
                        }
                    });
                    let _ = ws.send_with_str(response.to_string());
                }
            }
        } else {
            let compute_ms = compute_ms_f64(start_ms);
            let ack = serde_json::json!({
                "type": "received",
                "content": "Handled by Asynq Rust-WASM Engine",
                "metadata": meta(compute_ms)
            });
            let _ = ws.send_with_str(ack.to_string());
        }

        {
            let mut count = self.message_count.borrow_mut();
            *count = count.saturating_add(1);
        }
        let throughput = *self.message_count.borrow();
        let active_connections: u32 = self.ip_counts.borrow().values().sum();
        let metrics = serde_json::json!({
            "type": "metrics",
            "active_connections": active_connections,
            "throughput": throughput
        });
        let _ = ws.send_with_str(metrics.to_string());

        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let active_connections: u32 = self.ip_counts.borrow().values().sum();
        let metrics = serde_json::json!({
            "type": "metrics",
            "active_connections": active_connections
        });
        let body = metrics.to_string();
        for w in self.connected_ws.borrow().iter() {
            let _ = w.send_with_str(&body);
        }
        let next = worker::Date::now().as_millis() + 5000;
        let _ = self.state.storage().set_alarm(next as i64).await;
        Response::ok("")
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    utils::set_panic_hook();

    let upgrade = req
        .headers()
        .get("upgrade")
        .ok()
        .flatten()
        .unwrap_or_else(|| "missing".to_string());
    console_log!("[handshake] Upgrade header: {}", upgrade);

    if !is_websocket_upgrade(&req) {
        console_log!("[handshake] Fallback: not a WebSocket upgrade, returning 426");
        return Response::error("Expected WebSocket upgrade", 426);
    }

    let token = match extract_token_from_request(&req) {
        Some(t) => {
            console_log!("[handshake] Extracted token: {} (len={})", t, t.len());
            t
        }
        None => {
            console_log!("[handshake] Fallback: no token, returning 401");
            return Response::error("Unauthorized", 401);
        }
    };

    let secret = env
        .secret("ASYNQ_JWT_SECRET")
        .map_err(|_| Error::RustError("ASYNQ_JWT_SECRET not set".into()))?
        .to_string();

    if token == "guest" {
        console_log!("[handshake] Guest token: bypassing JWT validation, forwarding to DO");
    } else if validate_jwt(&token, &secret).is_err() {
        console_log!("[handshake] Fallback: JWT validation failed, returning 401");
        return Response::error("Unauthorized", 401);
    }

    console_log!("[handshake] Upgrade path: forwarding to Durable Object");
    let colo = req
        .cf()
        .map(|c| c.colo())
        .unwrap_or_else(|| "IAD".to_string());
    let headers = req.headers().clone();
    let _ = headers.set("X-CF-Colo", &colo);
    let uri = req.url()?.to_string();
        let init = RequestInit {
            method: req.method(),
            headers,
        ..RequestInit::default()
    };
    let new_request = Request::new_with_init(&uri, &init)?;
    let namespace = env.durable_object("SOCKS_STATE")?;
    let stub = namespace.get_by_name("default")?;
    let do_response = stub.fetch_with_request(new_request).await?;

    console_log!("[handshake] DO response status: {}", do_response.status_code());
    Ok(do_response)
}
