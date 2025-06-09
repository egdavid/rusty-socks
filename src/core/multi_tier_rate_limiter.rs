//! Multi-tier rate limiting system with progressive penalties and adaptive limits

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// User tier for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserTier {
    /// Anonymous users (most restrictive)
    Anonymous,
    /// Authenticated regular users
    Authenticated,
    /// Premium/trusted users (less restrictive)
    Premium,
    /// Moderators and admins (least restrictive)
    Privileged,
}

/// Operation type for differentiated rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Regular chat messages
    Message,
    /// Join/leave room operations
    RoomManagement,
    /// User management operations (ban, kick, etc.)
    Moderation,
    /// Room creation
    RoomCreation,
    /// Private messages
    PrivateMessage,
}

/// Rate limit configuration for different tiers and operations
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per minute for normal operation
    pub requests_per_minute: u32,
    /// Burst allowance (extra requests allowed in short time)
    pub burst_allowance: u32,
    /// Burst window duration (how long burst allowance resets)
    pub burst_window: Duration,
    /// Penalty multiplier when user exceeds limits
    pub penalty_multiplier: f32,
    /// Maximum penalty duration
    pub max_penalty_duration: Duration,
}

impl RateLimitConfig {
    /// Default configuration for anonymous users
    pub fn anonymous() -> Self {
        Self {
            requests_per_minute: 30,
            burst_allowance: 5,
            burst_window: Duration::from_secs(10),
            penalty_multiplier: 2.0,
            max_penalty_duration: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Default configuration for authenticated users
    pub fn authenticated() -> Self {
        Self {
            requests_per_minute: 60,
            burst_allowance: 10,
            burst_window: Duration::from_secs(10),
            penalty_multiplier: 1.5,
            max_penalty_duration: Duration::from_secs(180), // 3 minutes
        }
    }

    /// Default configuration for premium users
    pub fn premium() -> Self {
        Self {
            requests_per_minute: 120,
            burst_allowance: 20,
            burst_window: Duration::from_secs(10),
            penalty_multiplier: 1.2,
            max_penalty_duration: Duration::from_secs(60), // 1 minute
        }
    }

    /// Default configuration for privileged users
    pub fn privileged() -> Self {
        Self {
            requests_per_minute: 300,
            burst_allowance: 50,
            burst_window: Duration::from_secs(10),
            penalty_multiplier: 1.0,
            max_penalty_duration: Duration::from_secs(30),
        }
    }
}

/// User's rate limiting state
#[derive(Debug)]
struct UserRateState {
    /// Recent request timestamps
    request_times: Vec<Instant>,
    /// Burst tokens available
    burst_tokens: u32,
    /// Last burst token refill time
    last_burst_refill: Instant,
    /// Current penalty level (1.0 = no penalty, higher = more restrictive)
    penalty_level: f32,
    /// When penalty was last applied
    penalty_start_time: Option<Instant>,
    /// Number of violations
    violation_count: u32,
}

impl UserRateState {
    fn new(burst_allowance: u32) -> Self {
        let now = Instant::now();
        Self {
            request_times: Vec::new(),
            burst_tokens: burst_allowance,
            last_burst_refill: now,
            penalty_level: 1.0,
            penalty_start_time: None,
            violation_count: 0,
        }
    }
}

/// Adaptive rate limiter that adjusts based on server load
pub struct AdaptiveRateLimiter {
    /// Current server load factor (1.0 = normal, higher = more loaded)
    server_load_factor: AtomicU64, // Store as u64 bits of f64
    /// Total requests in last minute (for load calculation)
    total_requests_counter: RwLock<Vec<Instant>>,
    /// Load calculation interval
    load_calculation_interval: Duration,
    /// Last load calculation time
    last_load_calculation: RwLock<Instant>,
}

impl AdaptiveRateLimiter {
    fn new() -> Self {
        Self {
            server_load_factor: AtomicU64::new(1.0f64.to_bits()),
            total_requests_counter: RwLock::new(Vec::new()),
            load_calculation_interval: Duration::from_secs(10),
            last_load_calculation: RwLock::new(Instant::now()),
        }
    }

    /// Update server load factor based on recent request volume
    async fn update_load_factor(&self) {
        let now = Instant::now();
        let mut last_calc = self.last_load_calculation.write().await;
        
        if now.duration_since(*last_calc) < self.load_calculation_interval {
            return; // Not time to recalculate yet
        }
        
        *last_calc = now;
        
        let mut counter = self.total_requests_counter.write().await;
        counter.retain(|&time| now.duration_since(time) < Duration::from_secs(60));
        
        let requests_per_minute = counter.len() as f64;
        
        // Calculate load factor based on request volume
        // Assuming 1000 requests/minute is "normal" load
        let base_load = 1000.0;
        let load_factor = if requests_per_minute > base_load {
            1.0 + (requests_per_minute - base_load) / base_load
        } else {
            1.0
        }.min(5.0); // Cap at 5x load factor
        
        self.server_load_factor.store(load_factor.to_bits(), Ordering::Relaxed);
        
        if load_factor > 2.0 {
            log::warn!("High server load detected: {:.2}x normal ({}. requests/min)", load_factor, requests_per_minute);
        }
    }

    /// Get current server load factor
    fn get_load_factor(&self) -> f64 {
        f64::from_bits(self.server_load_factor.load(Ordering::Relaxed))
    }

    /// Record a request for load calculation
    async fn record_request(&self) {
        let mut counter = self.total_requests_counter.write().await;
        counter.push(Instant::now());
    }
}

/// Multi-tier rate limiter with progressive penalties and adaptive limits
pub struct MultiTierRateLimiter {
    /// Rate limit configurations for different tiers and operations
    configs: HashMap<(UserTier, OperationType), RateLimitConfig>,
    /// User rate limiting states
    user_states: RwLock<HashMap<String, UserRateState>>,
    /// IP-based rate limiting (additional layer)
    ip_states: RwLock<HashMap<IpAddr, UserRateState>>,
    /// Adaptive rate limiter for server load
    adaptive_limiter: AdaptiveRateLimiter,
    /// Maximum number of users to track
    max_tracked_users: usize,
    /// Maximum number of IPs to track
    max_tracked_ips: usize,
}

impl MultiTierRateLimiter {
    pub fn new() -> Self {
        let mut configs = HashMap::new();
        
        // Configure different rate limits for each tier and operation type
        for user_tier in [UserTier::Anonymous, UserTier::Authenticated, UserTier::Premium, UserTier::Privileged] {
            for op_type in [
                OperationType::Message,
                OperationType::RoomManagement,
                OperationType::Moderation,
                OperationType::RoomCreation,
                OperationType::PrivateMessage,
            ] {
                let base_config = match user_tier {
                    UserTier::Anonymous => RateLimitConfig::anonymous(),
                    UserTier::Authenticated => RateLimitConfig::authenticated(),
                    UserTier::Premium => RateLimitConfig::premium(),
                    UserTier::Privileged => RateLimitConfig::privileged(),
                };
                
                // Adjust config based on operation type
                let config = match op_type {
                    OperationType::Message => base_config,
                    OperationType::RoomManagement => RateLimitConfig {
                        requests_per_minute: base_config.requests_per_minute / 4, // More restrictive
                        burst_allowance: base_config.burst_allowance / 2,
                        ..base_config
                    },
                    OperationType::Moderation => RateLimitConfig {
                        requests_per_minute: base_config.requests_per_minute / 6, // Most restrictive
                        burst_allowance: base_config.burst_allowance / 3,
                        ..base_config
                    },
                    OperationType::RoomCreation => RateLimitConfig {
                        requests_per_minute: (base_config.requests_per_minute / 10).max(1), // Very restrictive
                        burst_allowance: 1,
                        ..base_config
                    },
                    OperationType::PrivateMessage => RateLimitConfig {
                        requests_per_minute: base_config.requests_per_minute / 2, // Somewhat restrictive
                        burst_allowance: base_config.burst_allowance / 2,
                        ..base_config
                    },
                };
                
                configs.insert((user_tier, op_type), config);
            }
        }
        
        Self {
            configs,
            user_states: RwLock::new(HashMap::new()),
            ip_states: RwLock::new(HashMap::new()),
            adaptive_limiter: AdaptiveRateLimiter::new(),
            max_tracked_users: 50000,
            max_tracked_ips: 10000,
        }
    }

    /// Check if a request is allowed for a user
    pub async fn allow_request(
        &self,
        user_id: &str,
        user_ip: IpAddr,
        user_tier: UserTier,
        operation: OperationType,
    ) -> bool {
        // Record request for load calculation
        self.adaptive_limiter.record_request().await;
        
        // Update server load factor
        self.adaptive_limiter.update_load_factor().await;
        
        // Get configuration for this tier and operation
        let config = match self.configs.get(&(user_tier.clone(), operation.clone())) {
            Some(config) => config.clone(),
            None => {
                log::warn!("No rate limit config found for tier {:?} and operation {:?}", user_tier, operation);
                return false;
            }
        };
        
        // Apply adaptive rate limiting based on server load
        let load_factor = self.adaptive_limiter.get_load_factor();
        let adjusted_config = RateLimitConfig {
            requests_per_minute: ((config.requests_per_minute as f64) / load_factor).max(1.0) as u32,
            burst_allowance: ((config.burst_allowance as f64) / load_factor).max(1.0) as u32,
            ..config
        };
        
        // Check both user-based and IP-based rate limits
        let user_allowed = self.check_user_rate_limit(user_id, &adjusted_config).await;
        let ip_allowed = self.check_ip_rate_limit(user_ip, &adjusted_config).await;
        
        user_allowed && ip_allowed
    }

    /// Check user-specific rate limit
    async fn check_user_rate_limit(&self, user_id: &str, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        
        let mut states = self.user_states.write().await;
        
        // Memory protection: remove oldest users if needed
        if states.len() >= self.max_tracked_users {
            let oldest_user = states.iter()
                .min_by_key(|(_, state)| {
                    state.request_times.last().copied().unwrap_or(now)
                })
                .map(|(user, _)| user.clone());
            
            if let Some(oldest) = oldest_user {
                states.remove(&oldest);
                log::debug!("Removed oldest user from rate limiter: memory protection");
            }
        }
        
        let state = states.entry(user_id.to_string())
            .or_insert_with(|| UserRateState::new(config.burst_allowance));
        
        self.check_rate_limit_internal(state, config, now)
    }

    /// Check IP-specific rate limit
    async fn check_ip_rate_limit(&self, ip: IpAddr, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        
        let mut states = self.ip_states.write().await;
        
        // Memory protection for IPs
        if states.len() >= self.max_tracked_ips {
            let oldest_ip = states.iter()
                .min_by_key(|(_, state)| {
                    state.request_times.last().copied().unwrap_or(now)
                })
                .map(|(ip, _)| *ip);
            
            if let Some(oldest) = oldest_ip {
                states.remove(&oldest);
                log::debug!("Removed oldest IP from rate limiter: memory protection");
            }
        }
        
        let state = states.entry(ip)
            .or_insert_with(|| UserRateState::new(config.burst_allowance));
        
        self.check_rate_limit_internal(state, config, now)
    }

    /// Internal rate limit checking logic
    fn check_rate_limit_internal(
        &self,
        state: &mut UserRateState,
        config: &RateLimitConfig,
        now: Instant,
    ) -> bool {
        // Update penalty if needed
        self.update_penalty(state, config, now);
        
        // Refill burst tokens
        self.refill_burst_tokens(state, config, now);
        
        // Clean old request times
        state.request_times.retain(|&time| now.duration_since(time) < Duration::from_secs(60));
        
        // Calculate effective limits with penalty
        let effective_requests_per_minute = 
            ((config.requests_per_minute as f32) / state.penalty_level).max(1.0) as u32;
        
        // Check if request is allowed
        let recent_requests = state.request_times.len() as u32;
        
        if recent_requests < effective_requests_per_minute {
            // Under normal limit
            state.request_times.push(now);
            true
        } else if state.burst_tokens > 0 {
            // Use burst token
            state.burst_tokens -= 1;
            state.request_times.push(now);
            true
        } else {
            // Rate limit exceeded
            self.apply_penalty(state, config);
            false
        }
    }

    /// Update penalty based on time elapsed
    fn update_penalty(&self, state: &mut UserRateState, config: &RateLimitConfig, now: Instant) {
        if let Some(penalty_start) = state.penalty_start_time {
            let penalty_duration = now.duration_since(penalty_start);
            
            if penalty_duration >= config.max_penalty_duration {
                // Penalty expired
                state.penalty_level = 1.0;
                state.penalty_start_time = None;
                state.violation_count = 0;
            } else {
                // Gradually reduce penalty over time
                let reduction_factor = penalty_duration.as_secs_f32() / config.max_penalty_duration.as_secs_f32();
                state.penalty_level = (state.penalty_level - reduction_factor).max(1.0);
            }
        }
    }

    /// Refill burst tokens
    fn refill_burst_tokens(&self, state: &mut UserRateState, config: &RateLimitConfig, now: Instant) {
        if now.duration_since(state.last_burst_refill) >= config.burst_window {
            state.burst_tokens = config.burst_allowance;
            state.last_burst_refill = now;
        }
    }

    /// Apply penalty for rate limit violation
    fn apply_penalty(&self, state: &mut UserRateState, config: &RateLimitConfig) {
        state.violation_count += 1;
        state.penalty_level = (state.penalty_level * config.penalty_multiplier).min(10.0); // Cap at 10x penalty
        state.penalty_start_time = Some(Instant::now());
        
        log::warn!("Rate limit penalty applied: level {:.2}x, violations: {}", 
                   state.penalty_level, state.violation_count);
    }

    /// Get current rate limit status for a user
    pub async fn get_user_status(&self, user_id: &str) -> Option<RateLimitStatus> {
        let states = self.user_states.read().await;
        states.get(user_id).map(|state| {
            let now = Instant::now();
            let recent_requests = state.request_times.iter()
                .filter(|&&time| now.duration_since(time) < Duration::from_secs(60))
                .count();
            
            RateLimitStatus {
                recent_requests: recent_requests as u32,
                burst_tokens_remaining: state.burst_tokens,
                penalty_level: state.penalty_level,
                violation_count: state.violation_count,
            }
        })
    }

    /// Clean up old entries to prevent memory leaks
    pub async fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let cutoff = Duration::from_secs(3600); // Keep entries for 1 hour
        
        // Clean user states
        {
            let mut states = self.user_states.write().await;
            states.retain(|_, state| {
                state.request_times.retain(|&time| now.duration_since(time) < cutoff);
                !state.request_times.is_empty() || state.penalty_level > 1.0
            });
        }
        
        // Clean IP states
        {
            let mut states = self.ip_states.write().await;
            states.retain(|_, state| {
                state.request_times.retain(|&time| now.duration_since(time) < cutoff);
                !state.request_times.is_empty() || state.penalty_level > 1.0
            });
        }
        
        log::debug!("Rate limiter cleanup completed");
    }

    /// Start cleanup task
    pub fn start_cleanup_task(self: std::sync::Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Cleanup every 5 minutes
            loop {
                interval.tick().await;
                self.cleanup_old_entries().await;
            }
        });
    }

    /// Get server load factor for monitoring
    pub fn get_server_load_factor(&self) -> f64 {
        self.adaptive_limiter.get_load_factor()
    }
}

/// Rate limit status for monitoring
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    pub recent_requests: u32,
    pub burst_tokens_remaining: u32,
    pub penalty_level: f32,
    pub violation_count: u32,
}