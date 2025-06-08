//! Security-focused logging module to track security events

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Types of security events to track
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    AuthenticationFailed { user_id: Option<String>, ip: Option<IpAddr> },
    RateLimitExceeded { user_id: String, ip: Option<IpAddr> },
    SuspiciousActivity { user_id: Option<String>, ip: Option<IpAddr>, description: String },
    PermissionDenied { user_id: String, action: String },
    InvalidInput { user_id: Option<String>, input_type: String },
    ConnectionBlocked { ip: IpAddr, reason: String },
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
        alert_thresholds.insert("auth_failed".to_string(), 5);
        alert_thresholds.insert("rate_limit".to_string(), 10);
        alert_thresholds.insert("permission_denied".to_string(), 20);
        alert_thresholds.insert("suspicious_activity".to_string(), 3);
        
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
            SecurityEvent::AuthenticationFailed { user_id, ip } => {
                log::warn!("Authentication failed - User: {:?}, IP: {:?}", user_id, ip);
            }
            SecurityEvent::RateLimitExceeded { user_id, ip } => {
                log::warn!("Rate limit exceeded - User: {}, IP: {:?}", user_id, ip);
            }
            SecurityEvent::SuspiciousActivity { user_id, ip, description } => {
                log::warn!("Suspicious activity - User: {:?}, IP: {:?}, Description: {}", user_id, ip, description);
            }
            SecurityEvent::PermissionDenied { user_id, action } => {
                log::info!("Permission denied - User: {}, Action: {}", user_id, action);
            }
            SecurityEvent::InvalidInput { user_id, input_type } => {
                log::info!("Invalid input - User: {:?}, Type: {}", user_id, input_type);
            }
            SecurityEvent::ConnectionBlocked { ip, reason } => {
                log::warn!("Connection blocked - IP: {}, Reason: {}", ip, reason);
            }
        }
    }
    
    /// Get event key for tracking
    fn get_event_key(&self, event: &SecurityEvent) -> String {
        match event {
            SecurityEvent::AuthenticationFailed { .. } => "auth_failed".to_string(),
            SecurityEvent::RateLimitExceeded { .. } => "rate_limit".to_string(),
            SecurityEvent::SuspiciousActivity { .. } => "suspicious_activity".to_string(),
            SecurityEvent::PermissionDenied { .. } => "permission_denied".to_string(),
            SecurityEvent::InvalidInput { .. } => "invalid_input".to_string(),
            SecurityEvent::ConnectionBlocked { .. } => "connection_blocked".to_string(),
        }
    }
    
    /// Trigger security alert
    async fn trigger_alert(&self, event_type: &str, count: usize, sample_event: &SecurityEvent) {
        log::error!("SECURITY ALERT: {} events of type '{}' detected", count, event_type);
        log::error!("Sample event: {:?}", sample_event);
        
        // In a real system, this would trigger additional actions:
        // - Send email/SMS alerts
        // - Notify monitoring systems
        // - Trigger automatic defensive measures
        // - Log to SIEM system
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

/// Global security logger instance
static mut SECURITY_LOGGER: Option<Arc<SecurityLogger>> = None;
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global security logger
pub fn init_security_logger() {
    INIT.call_once(|| {
        let logger = Arc::new(SecurityLogger::new());
        logger.clone().start_cleanup_task();
        
        unsafe {
            SECURITY_LOGGER = Some(logger);
        }
    });
}

/// Get the global security logger
pub fn get_security_logger() -> Option<Arc<SecurityLogger>> {
    unsafe { SECURITY_LOGGER.clone() }
}

/// Log a security event using the global logger
pub async fn log_security_event(event: SecurityEvent) {
    if let Some(logger) = get_security_logger() {
        logger.log_event(event).await;
    }
}