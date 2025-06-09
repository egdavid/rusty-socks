use log::{error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::{self, Filter};

use rusty_socks::auth::token::TokenManager;
use rusty_socks::storage::token_revocation::create_memory_revocation_store;
use rusty_socks::config::ServerConfig;
use rusty_socks::constants::WS_PATH;
use rusty_socks::core::thread_pool::create_thread_pool;
use rusty_socks::core::{extract_client_ip, IpExtractionConfig, ServerManager, SharedServerManager, SharedThreadPool};
use rusty_socks::handlers::websocket::handle_ws_client;
use rusty_socks::security::{CSRFProtection, CSRFValidationResult, init_production_warnings};
use rusty_socks::security::headers::{with_security_headers, with_api_security_headers};
use rusty_socks::security_logger::init_security_logger;
use rusty_socks::tls::TlsConfigBuilder;

// Custom rejection for CSRF validation failures
#[derive(Debug)]
struct CSRFRejection;

impl warp::reject::Reject for CSRFRejection {}

#[tokio::main]
async fn main() {
    // Initialize env
    match dotenvy::dotenv() {
        Ok(_) => info!("Environment variables loaded from .env file"),
        Err(e) => warn!("Failed to load .env file: {}", e),
    };

    // Initialize logging
    env_logger::init();
    
    // Initialize security logging and production warnings
    init_security_logger();
    init_production_warnings().await;

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

    // Create token revocation store
    let revocation_store = create_memory_revocation_store();
    
    // Create token manager with revocation support
    let token_manager = std::sync::Arc::new(TokenManager::with_revocation_store(
        &config.jwt_secret,
        revocation_store.clone()
    ));
    info!("JWT authentication initialized with token revocation support");

    // Create CSRF protection
    let allowed_origins = std::env::var("RUSTY_SOCKS_ALLOWED_ORIGINS")
        .map(|origins| origins.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|_| Vec::new());
    
    let csrf_protection = std::sync::Arc::new(CSRFProtection::new(
        allowed_origins,
        config.development_mode,
        config.csrf_secret.clone(), // Use dedicated CSRF secret (separated from JWT for security)
    ));
    info!("CSRF protection initialized");

    // Create IP extraction configuration
    let ip_config = if config.development_mode {
        IpExtractionConfig::development()
    } else {
        // In production, configure trusted proxies from environment
        let trusted_proxies = std::env::var("RUSTY_SOCKS_TRUSTED_PROXIES")
            .map(|proxies| {
                proxies.split(',')
                    .filter_map(|ip_str| {
                        match ip_str.trim().parse() {
                            Ok(ip) => Some(ip),
                            Err(e) => {
                                warn!("Invalid trusted proxy IP '{}': {}", ip_str.trim(), e);
                                None
                            }
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|_| Vec::new());
        
        if trusted_proxies.is_empty() {
            info!("No trusted proxies configured, using direct connection IPs only");
            IpExtractionConfig::default()
        } else {
            info!("Configured {} trusted proxies", trusted_proxies.len());
            IpExtractionConfig::production_with_proxy(trusted_proxies)
        }
    };
    let ip_config = std::sync::Arc::new(ip_config);

    // Start cleanup task for stale connections
    server_manager.clone().start_cleanup_task(
        std::time::Duration::from_secs(60), // Check every minute
        config.connection_timeout,           // Timeout from config
    );
    info!("Stale connection cleanup task started");

    // Create WebSocket route with thread pool and CSRF protection
    let ws_route = warp::path(WS_PATH)
        .and(warp::ws())
        .and(warp::header::headers_cloned())
        .and(csrf_validation_filter(csrf_protection.clone()))
        .and(warp::path::full())
        .and(warp::addr::remote())
        .and(with_server_manager(server_manager.clone()))
        .and(with_thread_pool(thread_pool.clone()))
        .and(with_token_manager(token_manager.clone()))
        .and(with_ip_config(ip_config.clone()))
        .and(with_config(Arc::new(config.clone())))
        .map(
            |ws: warp::ws::Ws,
             headers: warp::hyper::HeaderMap,
             path: warp::path::FullPath,
             remote_addr: Option<std::net::SocketAddr>,
             server_manager: SharedServerManager,
             thread_pool: SharedThreadPool,
             token_manager: std::sync::Arc<TokenManager>,
             ip_config: std::sync::Arc<IpExtractionConfig>,
             config: Arc<ServerConfig>| {
                // SECURITY: Extract real client IP address
                let client_ip = extract_client_ip(&headers, remote_addr, &ip_config);
                info!("New websocket connection from IP: {}", client_ip);

                // SECURITY: Extract token from secure headers only (no URL tokens allowed)
                let token = {
                    use rusty_socks::handlers::auth::extract_token_comprehensive;
                    extract_token_comprehensive(&path.as_str().parse().unwrap_or_default(), &headers)
                };

                ws.on_upgrade(move |socket| {
                    // Use the thread pool to handle the WebSocket client
                    let handle_client =
                        handle_ws_client(socket, server_manager, token, token_manager, config, client_ip);
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
        .map(|| with_security_headers("OK"));

    // Create thread pool stats route with security headers
    let stats_route = warp::path("stats")
        .and(with_thread_pool(thread_pool.clone()))
        .map(|thread_pool: SharedThreadPool| {
            let active_tasks = thread_pool.active_task_count().unwrap_or(0);
            let json_response = warp::reply::json(&serde_json::json!({
                "worker_threads": thread_pool.worker_count(),
                "active_tasks": active_tasks
            }));
            with_api_security_headers(json_response)
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

    // Start the server with optional TLS
    if config.enable_tls {
        // TLS configuration
        let _tls_config = if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
            info!("Loading TLS configuration...");
            match TlsConfigBuilder::new(cert_path.clone(), key_path.clone()).build() {
                Ok(tls_config) => {
                    info!("TLS configuration loaded successfully");
                    tls_config
                },
                Err(e) => {
                    error!("Failed to load TLS configuration: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            error!("TLS is enabled but certificate or key path is missing");
            std::process::exit(1);
        };

        info!("Starting SECURE Rusty Socks server (HTTPS/WSS) on {}", addr);
        warp::serve(routes)
            .tls()
            .cert_path(config.tls_cert_path.as_ref().unwrap())
            .key_path(config.tls_key_path.as_ref().unwrap())
            .run(addr)
            .await;
    } else {
        if !config.development_mode {
            warn!("⚠️  SECURITY WARNING: Running in INSECURE mode (HTTP/WS) in production!");
            warn!("⚠️  Enable TLS by setting RUSTY_SOCKS_ENABLE_TLS=true");
            warn!("⚠️  Provide certificate with RUSTY_SOCKS_TLS_CERT_PATH and RUSTY_SOCKS_TLS_KEY_PATH");
        }
        
        info!("Starting Rusty Socks server (HTTP/WS) on {}", addr);
        warp::serve(routes).run(addr).await;
    }
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

// Helper function to include config in request
fn with_config(
    config: Arc<ServerConfig>,
) -> impl Filter<Extract = (Arc<ServerConfig>,), Error = Infallible> + Clone {
    warp::any().map(move || config.clone())
}


// Helper function to include IP config in request
fn with_ip_config(
    ip_config: std::sync::Arc<IpExtractionConfig>,
) -> impl Filter<Extract = (std::sync::Arc<IpExtractionConfig>,), Error = Infallible> + Clone {
    warp::any().map(move || ip_config.clone())
}

// CSRF validation filter that rejects connections before WebSocket upgrade
fn csrf_validation_filter(
    csrf_protection: std::sync::Arc<CSRFProtection>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::headers_cloned()
        .and_then(move |headers: warp::hyper::HeaderMap| {
            let csrf = csrf_protection.clone();
            async move {
                match csrf.validate_websocket_connection(&headers) {
                    CSRFValidationResult::Valid => {
                        info!("CSRF validation passed for WebSocket connection");
                        Ok(())
                    }
                    CSRFValidationResult::InvalidOrigin(msg) => {
                        error!("CSRF validation failed - Invalid origin: {}", msg);
                        Err(warp::reject::custom(CSRFRejection))
                    }
                    CSRFValidationResult::MissingHeaders(msg) => {
                        error!("CSRF validation failed - Missing headers: {}", msg);
                        Err(warp::reject::custom(CSRFRejection))
                    }
                    CSRFValidationResult::Suspicious(msg) => {
                        error!("CSRF validation failed - Suspicious request: {}", msg);
                        Err(warp::reject::custom(CSRFRejection))
                    }
                    _ => {
                        error!("CSRF validation failed for WebSocket connection");
                        Err(warp::reject::custom(CSRFRejection))
                    }
                }
            }
        })
        .untuple_one()
}

