use log::{error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use warp::{self, Filter};

use rusty_socks::auth::token::TokenManager;
use rusty_socks::config::ServerConfig;
use rusty_socks::constants::WS_PATH;
use rusty_socks::core::thread_pool::create_thread_pool;
use rusty_socks::core::{ServerManager, SharedServerManager, SharedThreadPool};
use rusty_socks::handlers::websocket::handle_ws_client;

#[tokio::main]
async fn main() {
    // Initialize env
    match dotenvy::dotenv() {
        Ok(_) => info!("Environment variables loaded from .env file"),
        Err(e) => warn!("Failed to load .env file: {}", e),
    };

    // Initialize logging
    env_logger::init();

    // Load config from .env
    let config = match ServerConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        "Configuration: host={}, port={}, thread_pool_size={}",
        config.host, config.port, config.thread_pool_size
    );

    // Create integrated server manager with rate limiting
    let server_manager = std::sync::Arc::new(ServerManager::with_rate_limits(
        config.max_connections_per_ip,
        config.rate_limit_messages_per_minute,
    ));
    info!("Server manager initialized with rate limiting");

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

    // Create token manager
    let token_manager = std::sync::Arc::new(TokenManager::new(&config.jwt_secret));
    info!("JWT authentication initialized");

    // Start cleanup task for stale connections
    server_manager.clone().start_cleanup_task(
        std::time::Duration::from_secs(60), // Check every minute
        config.connection_timeout,           // Timeout from config
    );
    info!("Stale connection cleanup task started");

    // Create WebSocket route with thread pool
    let ws_route = warp::path(WS_PATH)
        .and(warp::ws())
        .and(warp::filters::query::raw().or(warp::any().map(|| String::new())).unify())
        .and(with_server_manager(server_manager.clone()))
        .and(with_thread_pool(thread_pool.clone()))
        .and(with_token_manager(token_manager.clone()))
        .map(
            |ws: warp::ws::Ws,
             query: String,
             server_manager: SharedServerManager,
             thread_pool: SharedThreadPool,
             token_manager: std::sync::Arc<TokenManager>| {
                info!("New websocket connection");

                // Extract token from query string
                let token = extract_token_from_query(&query);

                ws.on_upgrade(move |socket| {
                    // Use the thread pool to handle the WebSocket client
                    let handle_client =
                        handle_ws_client(socket, server_manager, token, token_manager);
                    match thread_pool.execute(handle_client) {
                        Some(_) => info!("WebSocket connection processing assigned to thread pool"),
                        None => error!("Thread pool is at capacity, connection rejected"),
                    }
                    // Return a future that resolves when the client is handled
                    async {}
                })
            },
        );

    // Create health check route with security headers
    let health_route = warp::path("health")
        .map(|| "OK")
        .with(warp::reply::with::header("X-Content-Type-Options", "nosniff"))
        .with(warp::reply::with::header("X-Frame-Options", "DENY"))
        .with(warp::reply::with::header("X-XSS-Protection", "1; mode=block"))
        .with(warp::reply::with::header("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .with(warp::reply::with::header("Referrer-Policy", "strict-origin-when-cross-origin"))
        .with(warp::reply::with::header("Content-Security-Policy", "default-src 'self'"));

    // Create thread pool stats route with security headers
    let stats_route = warp::path("stats")
        .and(with_thread_pool(thread_pool.clone()))
        .map(|thread_pool: SharedThreadPool| {
            let active_tasks = thread_pool.active_task_count().unwrap_or(0);
            warp::reply::json(&serde_json::json!({
                "worker_threads": thread_pool.worker_count(),
                "active_tasks": active_tasks
            }))
        })
        .with(warp::reply::with::header("X-Content-Type-Options", "nosniff"))
        .with(warp::reply::with::header("X-Frame-Options", "DENY"))
        .with(warp::reply::with::header("X-XSS-Protection", "1; mode=block"))
        .with(warp::reply::with::header("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .with(warp::reply::with::header("Referrer-Policy", "strict-origin-when-cross-origin"))
        .with(warp::reply::with::header("Content-Security-Policy", "default-src 'self'"));

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

// Helper function to include server manager in request
fn with_server_manager(
    server_manager: SharedServerManager,
) -> impl Filter<Extract = (SharedServerManager,), Error = Infallible> + Clone {
    warp::any().map(move || server_manager.clone())
}

// Helper function to include thread pool in request
fn with_thread_pool(
    thread_pool: SharedThreadPool,
) -> impl Filter<Extract = (SharedThreadPool,), Error = Infallible> + Clone {
    warp::any().map(move || thread_pool.clone())
}

// Helper function to include token manager in request
fn with_token_manager(
    token_manager: std::sync::Arc<TokenManager>,
) -> impl Filter<Extract = (std::sync::Arc<TokenManager>,), Error = Infallible> + Clone {
    warp::any().map(move || token_manager.clone())
}

// Helper function to extract token from query string
fn extract_token_from_query(query: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let mut parts = pair.split('=');
        match (parts.next(), parts.next()) {
            (Some("token"), Some(value)) => Some(value.to_string()),
            _ => None,
        }
    })
}
