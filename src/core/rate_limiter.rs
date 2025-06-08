//! Rate limiting module to prevent abuse

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter for connections per IP
pub struct ConnectionLimiter {
    connections_per_ip: RwLock<HashMap<IpAddr, usize>>,
    max_connections_per_ip: usize,
}

impl ConnectionLimiter {
    pub fn new(max_connections_per_ip: usize) -> Self {
        Self {
            connections_per_ip: RwLock::new(HashMap::new()),
            max_connections_per_ip,
        }
    }

    /// Check if a new connection from this IP is allowed
    pub async fn allow_connection(&self, ip: IpAddr) -> bool {
        let connections = self.connections_per_ip.read().await;
        let current_count = connections.get(&ip).unwrap_or(&0);
        *current_count < self.max_connections_per_ip
    }

    /// Register a new connection from an IP
    pub async fn add_connection(&self, ip: IpAddr) -> bool {
        let mut connections = self.connections_per_ip.write().await;
        let count = connections.entry(ip).or_insert(0);
        if *count < self.max_connections_per_ip {
            *count += 1;
            true
        } else {
            false
        }
    }

    /// Remove a connection from an IP
    pub async fn remove_connection(&self, ip: IpAddr) {
        let mut connections = self.connections_per_ip.write().await;
        if let Some(count) = connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(&ip);
            }
        }
    }

    /// Get current connection count for an IP
    pub async fn get_connection_count(&self, ip: IpAddr) -> usize {
        let connections = self.connections_per_ip.read().await;
        *connections.get(&ip).unwrap_or(&0)
    }
}

/// Rate limiter for messages per user with memory protection
pub struct MessageRateLimiter {
    user_message_times: RwLock<HashMap<String, Vec<Instant>>>,
    max_messages_per_minute: u32,
    window_duration: Duration,
    /// Maximum number of users to track to prevent memory exhaustion
    max_tracked_users: usize,
    /// Global message counter across all users
    global_message_counter: RwLock<Vec<Instant>>,
    max_global_messages_per_minute: u32,
}

impl MessageRateLimiter {
    pub fn new(max_messages_per_minute: u32) -> Self {
        Self {
            user_message_times: RwLock::new(HashMap::new()),
            max_messages_per_minute,
            window_duration: Duration::from_secs(60),
            max_tracked_users: 10000, // Limit memory usage
            global_message_counter: RwLock::new(Vec::new()),
            max_global_messages_per_minute: max_messages_per_minute * 100, // Global limit
        }
    }

    /// Check if a user can send another message (with memory protection and global limits)
    pub async fn allow_message(&self, user_id: &str) -> bool {
        let now = Instant::now();
        
        // First check global rate limit
        {
            let mut global_times = self.global_message_counter.write().await;
            global_times.retain(|&time| now.duration_since(time) < self.window_duration);
            
            if global_times.len() >= self.max_global_messages_per_minute as usize {
                return false;
            }
            global_times.push(now);
        }
        
        // Then check per-user rate limit
        let mut times = self.user_message_times.write().await;
        
        // Enforce memory limit by removing oldest user if needed
        if times.len() >= self.max_tracked_users {
            // Find user with oldest last message
            let now_fallback = Instant::now();
            let oldest_user = times.iter()
                .min_by_key(|(_, user_times)| user_times.last().unwrap_or(&now_fallback))
                .map(|(user, _)| user.clone());
            
            if let Some(oldest) = oldest_user {
                times.remove(&oldest);
                log::debug!("Removed oldest user from rate limiter to prevent memory exhaustion");
            }
        }
        
        // Get or create user's message times
        let user_times = times.entry(user_id.to_string()).or_insert_with(Vec::new);
        
        // Remove old messages outside the window
        user_times.retain(|&time| now.duration_since(time) < self.window_duration);
        
        // Check if under the per-user limit
        if user_times.len() < self.max_messages_per_minute as usize {
            user_times.push(now);
            true
        } else {
            false
        }
    }

    /// Get current message count for user in the window
    pub async fn get_message_count(&self, user_id: &str) -> usize {
        let times = self.user_message_times.read().await;
        if let Some(user_times) = times.get(user_id) {
            let now = Instant::now();
            user_times.iter()
                .filter(|&&time| now.duration_since(time) < self.window_duration)
                .count()
        } else {
            0
        }
    }

    /// Clean up old entries to prevent memory leaks
    pub async fn cleanup_old_entries(&self) {
        let now = Instant::now();
        
        // Clean up per-user rate limits
        {
            let mut times = self.user_message_times.write().await;
            times.retain(|_, user_times| {
                user_times.retain(|&time| now.duration_since(time) < self.window_duration);
                !user_times.is_empty()
            });
        }
        
        // Clean up global rate limit
        {
            let mut global_times = self.global_message_counter.write().await;
            global_times.retain(|&time| now.duration_since(time) < self.window_duration);
        }
    }
    
    /// Get current global message count
    pub async fn get_global_message_count(&self) -> usize {
        let global_times = self.global_message_counter.read().await;
        let now = Instant::now();
        global_times.iter()
            .filter(|&&time| now.duration_since(time) < self.window_duration)
            .count()
    }
    
    /// Get number of tracked users
    pub async fn get_tracked_users_count(&self) -> usize {
        let times = self.user_message_times.read().await;
        times.len()
    }
}

/// Combined rate limiter manager
pub struct RateLimiterManager {
    pub connection_limiter: ConnectionLimiter,
    pub message_limiter: MessageRateLimiter,
}

impl RateLimiterManager {
    pub fn new(max_connections_per_ip: usize, max_messages_per_minute: u32) -> Self {
        Self {
            connection_limiter: ConnectionLimiter::new(max_connections_per_ip),
            message_limiter: MessageRateLimiter::new(max_messages_per_minute),
        }
    }

    /// Start cleanup task for rate limiters
    pub fn start_cleanup_task(self: std::sync::Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Cleanup every 5 minutes
            loop {
                interval.tick().await;
                self.message_limiter.cleanup_old_entries().await;
            }
        });
    }
}