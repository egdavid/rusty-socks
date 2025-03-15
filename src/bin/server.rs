use std::convert::Infallible;
use warp::{self, Filter};
use log::info;
use std::net::SocketAddr;

use rusty_socks::config::ServerConfig;
use rusty_socks::constants::WS_PATH;
use rusty_socks::core::session::create_session_manager;
use rusty_socks::handlers::websocket::handle_ws_client;

#[tokio::main]
async fn main() {

    // Initialize env
    dotenv::dotenv().ok();

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
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid address");

    // Start the server
    info!("Starting Rusty Socks server on {}", addr);
    warp::serve(routes)
        .run(addr)
        .await;
}

// Helper function to include sessions state in request
fn with_sessions(sessions: rusty_socks::core::session::Sessions)
                 -> impl Filter<Extract = (rusty_socks::core::session::Sessions,), Error = Infallible> + Clone
{
    warp::any().map(move || sessions.clone())
}