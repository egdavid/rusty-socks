use log::{error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use warp::{self, Filter};

use rusty_socks::config::ServerConfig;
use rusty_socks::constants::WS_PATH;
use rusty_socks::core::session::create_session_manager;
use rusty_socks::core::thread_pool::create_thread_pool;
use rusty_socks::core::{Sessions, SharedThreadPool};
use rusty_socks::handlers::websocket::handle_ws_client;

#[tokio::main]
async fn main() {
    // Initialize env
    match dotenv::dotenv() {
        Ok(_) => info!("Environment variables loaded from .env file"),
        Err(e) => warn!("Failed to load .env file: {}", e),
    };

    // Initialize logging
    env_logger::init();

    // Load config from .env
    let config = ServerConfig::from_env();

    info!(
        "Configuration: host={}, port={}, thread_pool_size={}",
        config.host, config.port, config.thread_pool_size
    );

    // Create session manager
    let sessions = match create_session_manager() {
        Ok(sessions) => sessions,
        Err(e) => {
            error!("Failed to create session manager: {}", e);
            std::process::exit(1);
        }
    };

    // Create thread pool
    let thread_pool = match create_thread_pool(&config) {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to create thread pool: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        "Thread pool created with {} worker threads",
        thread_pool.worker_count()
    );

    // Create WebSocket route with thread pool
    let ws_route = warp::path(WS_PATH)
        .and(warp::ws())
        .and(with_sessions(sessions.clone()))
        .and(with_thread_pool(thread_pool.clone()))
        .map(
            |ws: warp::ws::Ws, sessions: Sessions, thread_pool: SharedThreadPool| {
                info!("New websocket connection");
                ws.on_upgrade(move |socket| {
                    // Use the thread pool to handle the WebSocket client
                    let handle_client = handle_ws_client(socket, sessions);
                    match thread_pool.execute(handle_client) {
                        Some(_) => info!("WebSocket connection processing assigned to thread pool"),
                        None => error!("Thread pool is at capacity, connection rejected"),
                    }

                    // Since we are now using the thread pool to handle the WebSocket client,
                    // we need to return a future that completes immediately
                    async {}
                })
            },
        );

    // Create health check route
    let health_route = warp::path("health").map(|| "OK");

    // Create thread pool stats route
    let stats_route = warp::path("stats")
        .and(with_thread_pool(thread_pool.clone()))
        .map(|thread_pool: SharedThreadPool| {
            let active_tasks = thread_pool.active_task_count().unwrap_or(0);
            warp::reply::json(&serde_json::json!({
                "worker_threads": thread_pool.worker_count(),
                "active_tasks": active_tasks
            }))
        });

    // Combine routes
    let routes = ws_route.or(health_route).or(stats_route);

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

    warp::serve(routes).run(addr).await;
}

// Helper function to include sessions state in request
fn with_sessions(
    sessions: Sessions,
) -> impl Filter<Extract = (Sessions,), Error = Infallible> + Clone {
    warp::any().map(move || sessions.clone())
}

// Helper function to include thread pool in request
fn with_thread_pool(
    thread_pool: SharedThreadPool,
) -> impl Filter<Extract = (SharedThreadPool,), Error = Infallible> + Clone {
    warp::any().map(move || thread_pool.clone())
}
