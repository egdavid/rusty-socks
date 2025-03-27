use std::convert::Infallible;
use warp::{self, Filter};
use log::{info, error, warn};
use std::net::SocketAddr;

use rusty_socks::config::ServerConfig;
use rusty_socks::constants::WS_PATH;
use rusty_socks::core::session::create_session_manager;
use rusty_socks::core::Sessions;
use rusty_socks::handlers::websocket::handle_ws_client;

#[tokio::main]
async fn main() {

    // Initialize env
    match dotenv::dotenv() {
        Ok(_) => info!("Environment variables loaded from .env file"),
        Err(e) => warn!("Failed to load .env file: {}", e)
    };

    // Initialize logging
    env_logger::init();

    // Load config from .env
    let config = ServerConfig::from_env();

    info!("Configuration: host={}, port={}", config.host, config.port);

    // Create session manager
    let sessions = create_session_manager();

    // Create WebSocket route
    let ws_route = warp::path(WS_PATH)
        .and(warp::ws())
        .and(with_sessions(sessions.clone()))
        .map(|ws: warp::ws::Ws, sessions| {
            info!("New websocket connection");
            ws.on_upgrade(move |socket| handle_ws_client(socket, sessions))
        });

    // Create health check route
    let health_route = warp::path("health")
        .map(|| "OK");

    // Combine routes
    let routes = ws_route.or(health_route);

    // Build the server address
    let addr: SocketAddr = match format!("{}:{}", config.host, config.port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to parse server address: {}", e);
            std::process::exit(1);
        }
    };

    // Start the server
    info!("Starting Rusty Socks server on {}", addr);

    // Note: Warp's serve().run() doesn't return a result, so we can't directly handle errors here.
    // TODO: Implement custom error handlers or a middleware for error handling during server operation
    warp::serve(routes)
        .run(addr)
        .await;
}

// Helper function to include sessions state in request
fn with_sessions(sessions: Result<Sessions, rusty_socks::error::RustySocksError>)
                 -> impl Filter<Extract = (Sessions,), Error = Infallible> + Clone
{
    warp::any().map(move || sessions.clone().unwrap_or_else(|e| {
        error!("Failed to initialize sessions: {}", e);
        panic!("Cannot proceed without sessions")
    }))
}