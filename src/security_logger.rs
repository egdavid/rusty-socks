//! Security-focused logging module to track security events

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Types of security events to track
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    // Authentication events
    AuthenticationFailed { user_id: Option<String>, ip: Option<IpAddr>, reason: String },
    AuthenticationSuccess { user_id: String, ip: Option<IpAddr> },
    TokenRevoked { user_id: String, token_id: String, reason: String },
    TokenValidationFailed { token_id: Option<String>, ip: Option<IpAddr>, reason: String },
    
    // Authorization events
    PermissionDenied { user_id: String, action: String, resource: Option<String> },
    UnauthorizedAccess { user_id: Option<String>, ip: Option<IpAddr>, resource: String },
    
    // Rate limiting and abuse
    RateLimitExceeded { user_id: String, ip: Option<IpAddr>, limit_type: String },
    SuspiciousActivity { user_id: Option<String>, ip: Option<IpAddr>, description: String },
    
    // Input validation and attacks
    InvalidInput { user_id: Option<String>, input_type: String, details: String },
    XSSAttempt { user_id: Option<String>, ip: Option<IpAddr>, content: String },
    CSRFAttempt { user_id: Option<String>, ip: Option<IpAddr>, origin: String },
    UnicodeAttack { user_id: Option<String>, ip: Option<IpAddr>, attack_type: String },
    
    // Connection and network security
    ConnectionBlocked { ip: IpAddr, reason: String },
    SuspiciousOrigin { ip: Option<IpAddr>, origin: String, reason: String },
    TLSError { ip: Option<IpAddr>, error: String },
    
    // System security
    ConfigurationError { component: String, error: String },
    SecurityPolicyViolation { user_id: Option<String>, policy: String, violation: String },
    ProductionModeWarning { component: String, warning: String },
}

/// Security event with timestamp
#[derive(Debug, Clone)]
struct TimestampedEvent {
    event: SecurityEvent,
    timestamp: Instant,
}

/// Security logger for tracking and alerting on security events
pub struct SecurityLogger {
    events: Arc<RwLock<Vec<TimestampedEvent>>>,
    event_counts: Arc<RwLock<HashMap<String, usize>>>,
    max_events: usize,
    alert_thresholds: HashMap<String, usize>,
}

impl SecurityLogger {
    /// Create a new security logger
    pub fn new() -> Self {
        let mut alert_thresholds = HashMap::new();
        // Authentication
        alert_thresholds.insert("auth_failed".to_string(), 5);
        alert_thresholds.insert("token_validation_failed".to_string(), 10);
        
        // Authorization
        alert_thresholds.insert("permission_denied".to_string(), 20);
        alert_thresholds.insert("unauthorized_access".to_string(), 5);
        
        // Rate limiting and abuse
        alert_thresholds.insert("rate_limit".to_string(), 10);
        alert_thresholds.insert("suspicious_activity".to_string(), 3);
        
        // Attack attempts
        alert_thresholds.insert("xss_attempt".to_string(), 1);
        alert_thresholds.insert("csrf_attempt".to_string(), 1);
        alert_thresholds.insert("unicode_attack".to_string(), 1);
        
        // Network security
        alert_thresholds.insert("connection_blocked".to_string(), 15);
        alert_thresholds.insert("suspicious_origin".to_string(), 5);
        alert_thresholds.insert("tls_error".to_string(), 10);
        
        // System security
        alert_thresholds.insert("config_error".to_string(), 1);
        alert_thresholds.insert("security_policy_violation".to_string(), 1);
        
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            event_counts: Arc::new(RwLock::new(HashMap::new())),
            max_events: 10000,
            alert_thresholds,
        }
    }
    
    /// Log a security event
    pub async fn log_event(&self, event: SecurityEvent) {
        let event_key = self.get_event_key(&event);
        let timestamped_event = TimestampedEvent {
            event: event.clone(),
            timestamp: Instant::now(),
        };
        
        // Add to events list
        {
            let mut events = self.events.write().await;
            events.push(timestamped_event);
            
            // Limit memory usage
            if events.len() > self.max_events {
                let events_to_remove = events.len() - self.max_events;
                events.drain(0..events_to_remove);
            }
        }
        
        // Update counters and check for alerts
        {
            let mut counts = self.event_counts.write().await;
            let count = counts.entry(event_key.clone()).or_insert(0);
            *count += 1;
            
            // Check if alert threshold reached
            if let Some(&threshold) = self.alert_thresholds.get(&event_key) {
                if *count >= threshold {
                    self.trigger_alert(&event_key, *count, &event).await;
                    *count = 0; // Reset counter after alert
                }
            }
        }
        
        // Log the event
        match event {
            // Authentication events
            SecurityEvent::AuthenticationFailed { user_id, ip, reason } => {
                log::warn!("SECURITY: Authentication failed - User: {:?}, IP: {:?}, Reason: {}", user_id, ip, reason);
            }
            SecurityEvent::AuthenticationSuccess { user_id, ip } => {
                log::info!("SECURITY: Authentication success - User: {}, IP: {:?}", user_id, ip);
            }
            SecurityEvent::TokenRevoked { user_id, token_id, reason } => {
                log::warn!("SECURITY: Token revoked - User: {}, Token: {}, Reason: {}", user_id, token_id, reason);
            }
            SecurityEvent::TokenValidationFailed { token_id, ip, reason } => {
                log::warn!("SECURITY: Token validation failed - Token: {:?}, IP: {:?}, Reason: {}", token_id, ip, reason);
            }
            
            // Authorization events
            SecurityEvent::PermissionDenied { user_id, action, resource } => {
                log::warn!("SECURITY: Permission denied - User: {}, Action: {}, Resource: {:?}", user_id, action, resource);
            }
            SecurityEvent::UnauthorizedAccess { user_id, ip, resource } => {
                log::error!("SECURITY: Unauthorized access attempt - User: {:?}, IP: {:?}, Resource: {}", user_id, ip, resource);
            }
            
            // Rate limiting and abuse
            SecurityEvent::RateLimitExceeded { user_id, ip, limit_type } => {
                log::warn!("SECURITY: Rate limit exceeded - User: {}, IP: {:?}, Type: {}", user_id, ip, limit_type);
            }
            SecurityEvent::SuspiciousActivity { user_id, ip, description } => {
                log::error!("SECURITY: Suspicious activity - User: {:?}, IP: {:?}, Description: {}", user_id, ip, description);
            }
            
            // Attack attempts
            SecurityEvent::InvalidInput { user_id, input_type, details } => {
                log::warn!("SECURITY: Invalid input - User: {:?}, Type: {}, Details: {}", user_id, input_type, details);
            }
            SecurityEvent::XSSAttempt { user_id, ip, content } => {
                log::error!("SECURITY: XSS attempt detected - User: {:?}, IP: {:?}, Content: {}", user_id, ip, content);
            }
            SecurityEvent::CSRFAttempt { user_id, ip, origin } => {
                log::error!("SECURITY: CSRF attempt detected - User: {:?}, IP: {:?}, Origin: {}", user_id, ip, origin);
            }
            SecurityEvent::UnicodeAttack { user_id, ip, attack_type } => {
                log::error!("SECURITY: Unicode attack detected - User: {:?}, IP: {:?}, Type: {}", user_id, ip, attack_type);
            }
            
            // Network security
            SecurityEvent::ConnectionBlocked { ip, reason } => {
                log::warn!("SECURITY: Connection blocked - IP: {}, Reason: {}", ip, reason);
            }
            SecurityEvent::SuspiciousOrigin { ip, origin, reason } => {
                log::warn!("SECURITY: Suspicious origin - IP: {:?}, Origin: {}, Reason: {}", ip, origin, reason);
            }
            SecurityEvent::TLSError { ip, error } => {
                log::error!("SECURITY: TLS error - IP: {:?}, Error: {}", ip, error);
            }
            
            // System security
            SecurityEvent::ConfigurationError { component, error } => {
                log::error!("SECURITY: Configuration error - Component: {}, Error: {}", component, error);
            }
            SecurityEvent::SecurityPolicyViolation { user_id, policy, violation } => {
                log::error!("SECURITY: Policy violation - User: {:?}, Policy: {}, Violation: {}", user_id, policy, violation);
            }
            SecurityEvent::ProductionModeWarning { component, warning } => {
                log::warn!("SECURITY: Production mode warning - Component: {}, Warning: {}", component, warning);
            }
        }
    }
    
    /// Get event key for tracking
    fn get_event_key(&self, event: &SecurityEvent) -> String {
        match event {
            // Authentication events
            SecurityEvent::AuthenticationFailed { .. } => "auth_failed".to_string(),
            SecurityEvent::AuthenticationSuccess { .. } => "auth_success".to_string(),
            SecurityEvent::TokenRevoked { .. } => "token_revoked".to_string(),
            SecurityEvent::TokenValidationFailed { .. } => "token_validation_failed".to_string(),
            
            // Authorization events
            SecurityEvent::PermissionDenied { .. } => "permission_denied".to_string(),
            SecurityEvent::UnauthorizedAccess { .. } => "unauthorized_access".to_string(),
            
            // Rate limiting and abuse
            SecurityEvent::RateLimitExceeded { .. } => "rate_limit".to_string(),
            SecurityEvent::SuspiciousActivity { .. } => "suspicious_activity".to_string(),
            
            // Attack attempts
            SecurityEvent::InvalidInput { .. } => "invalid_input".to_string(),
            SecurityEvent::XSSAttempt { .. } => "xss_attempt".to_string(),
            SecurityEvent::CSRFAttempt { .. } => "csrf_attempt".to_string(),
            SecurityEvent::UnicodeAttack { .. } => "unicode_attack".to_string(),
            
            // Network security
            SecurityEvent::ConnectionBlocked { .. } => "connection_blocked".to_string(),
            SecurityEvent::SuspiciousOrigin { .. } => "suspicious_origin".to_string(),
            SecurityEvent::TLSError { .. } => "tls_error".to_string(),
            
            // System security
            SecurityEvent::ConfigurationError { .. } => "config_error".to_string(),
            SecurityEvent::SecurityPolicyViolation { .. } => "security_policy_violation".to_string(),
            SecurityEvent::ProductionModeWarning { .. } => "production_warning".to_string(),
        }
    }
    
    /// Trigger security alert
    async fn trigger_alert(&self, event_type: &str, count: usize, sample_event: &SecurityEvent) {
        log::error!("SECURITY ALERT: {} events of type '{}' detected", count, event_type);
        log::error!("Sample event: {:?}", sample_event);
        
        // Additional alerting actions can be implemented here:
        // Email/SMS notifications, SIEM integration, automated responses
    }
    
    /// Get recent security events
    pub async fn get_recent_events(&self, duration: Duration) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        let cutoff = Instant::now() - duration;
        
        events
            .iter()
            .filter(|event| event.timestamp > cutoff)
            .map(|event| event.event.clone())
            .collect()
    }
    
    /// Get event statistics
    pub async fn get_event_stats(&self) -> HashMap<String, usize> {
        let counts = self.event_counts.read().await;
        counts.clone()
    }
    
    /// Clean up old events
    pub async fn cleanup_old_events(&self, max_age: Duration) {
        let mut events = self.events.write().await;
        let cutoff = Instant::now() - max_age;
        
        events.retain(|event| event.timestamp > cutoff);
    }
    
    /// Start periodic cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                self.cleanup_old_events(Duration::from_secs(3600 * 24)).await; // Keep 24 hours
            }
        });
    }
}

/// Global security logger instance - thread-safe singleton
static SECURITY_LOGGER: OnceLock<Arc<SecurityLogger>> = OnceLock::new();

/// Initialize the global security logger
pub fn init_security_logger() {
    SECURITY_LOGGER.get_or_init(|| {
        let logger = Arc::new(SecurityLogger::new());
        logger.clone().start_cleanup_task();
        logger
    });
}

/// Get the global security logger
pub fn get_security_logger() -> Option<Arc<SecurityLogger>> {
    SECURITY_LOGGER.get().cloned()
}

/// Log a security event using the global logger
pub async fn log_security_event(event: SecurityEvent) {
    if let Some(logger) = get_security_logger() {
        logger.log_event(event).await;
    }
}