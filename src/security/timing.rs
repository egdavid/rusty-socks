//! Timing attack protection utilities
//! 
//! This module provides utilities to prevent timing attacks, particularly
//! important for authentication and authorization checks.

use std::time::{Duration, Instant};

/// Constant-time string comparison to prevent timing attacks
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }
    
    result == 0
}

/// Constant-time byte array comparison
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    
    result == 0
}

/// Add artificial delay to prevent timing analysis
/// This ensures authentication failures take a minimum amount of time
pub async fn add_auth_delay(start_time: Instant, min_duration: Duration) {
    let elapsed = start_time.elapsed();
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }
}

/// Authentication timing helper
pub struct AuthTimer {
    start: Instant,
    min_duration: Duration,
}

impl AuthTimer {
    /// Create a new auth timer with minimum duration
    pub fn new(min_duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            min_duration,
        }
    }
    
    /// Create with default minimum duration (100ms)
    pub fn default() -> Self {
        Self::new(Duration::from_millis(100))
    }
    
    /// Wait until minimum duration has elapsed
    pub async fn wait(self) {
        add_auth_delay(self.start, self.min_duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell"));
        assert!(!constant_time_eq("", "a"));
    }
    
    #[test]
    fn test_constant_time_eq_bytes() {
        assert!(constant_time_eq_bytes(b"hello", b"hello"));
        assert!(!constant_time_eq_bytes(b"hello", b"world"));
        assert!(!constant_time_eq_bytes(b"hello", b"hell"));
        assert!(!constant_time_eq_bytes(b"", b"a"));
    }
    
    #[tokio::test]
    async fn test_auth_timer() {
        let timer = AuthTimer::new(Duration::from_millis(10));
        let start = Instant::now();
        timer.wait().await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }
}