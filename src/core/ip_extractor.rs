//! IP extraction utilities for WebSocket connections
//! 
//! This module provides secure IP extraction from HTTP headers and connection metadata
//! while protecting against IP spoofing attacks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use warp::hyper::HeaderMap;
use log::{debug, warn};

/// Configuration for IP extraction behavior
#[derive(Debug, Clone)]
pub struct IpExtractionConfig {
    /// Whether to trust proxy headers (X-Forwarded-For, X-Real-IP, etc.)
    pub trust_proxy_headers: bool,
    /// List of trusted proxy IP ranges (CIDR notation would be ideal, but simplified for now)
    pub trusted_proxies: Vec<IpAddr>,
    /// Whether to allow private/local IPs (for development)
    pub allow_private_ips: bool,
}

impl Default for IpExtractionConfig {
    fn default() -> Self {
        Self {
            trust_proxy_headers: false, // Secure by default
            trusted_proxies: Vec::new(),
            allow_private_ips: false, // Secure by default
        }
    }
}

impl IpExtractionConfig {
    /// Create configuration for development environment
    pub fn development() -> Self {
        Self {
            trust_proxy_headers: true,
            trusted_proxies: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // localhost
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), // ::1
            ],
            allow_private_ips: true,
        }
    }

    /// Create configuration for production behind trusted proxies
    pub fn production_with_proxy(trusted_proxies: Vec<IpAddr>) -> Self {
        Self {
            trust_proxy_headers: true,
            trusted_proxies,
            allow_private_ips: false,
        }
    }
}

/// Extract the real client IP address from headers and connection info
/// 
/// This function implements defense against IP spoofing by:
/// 1. Only trusting proxy headers from explicitly trusted proxies
/// 2. Validating IP format and ranges
/// 3. Preferring direct connection IP over headers when not behind trusted proxy
/// 4. Logging suspicious activity for security monitoring
pub fn extract_client_ip(
    headers: &HeaderMap,
    remote_addr: Option<std::net::SocketAddr>,
    config: &IpExtractionConfig,
) -> IpAddr {
    // Get the direct connection IP
    let direct_ip = remote_addr.map(|addr| addr.ip());
    
    // If we don't trust proxy headers or don't have a direct IP, use direct connection
    if !config.trust_proxy_headers {
        if let Some(ip) = direct_ip {
            if config.allow_private_ips || !is_private_ip(ip) {
                debug!("Using direct connection IP: {}", ip);
                return ip;
            } else {
                warn!("Direct connection from private IP {} rejected in production mode", ip);
            }
        }
        
        // Fallback to localhost if no valid IP available
        warn!("No valid direct IP available, falling back to localhost");
        return IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    }

    // Check if the direct connection is from a trusted proxy
    let is_trusted_proxy = if let Some(ip) = direct_ip {
        config.trusted_proxies.contains(&ip)
    } else {
        false
    };

    // If behind trusted proxy, extract from headers
    if is_trusted_proxy {
        // Try X-Forwarded-For header (most common)
        if let Some(forwarded_for) = headers.get("x-forwarded-for") {
            if let Ok(header_value) = forwarded_for.to_str() {
                // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                // We want the leftmost (original client) IP
                let client_ip = header_value.split(',').next().unwrap_or("").trim();
                if let Ok(ip) = client_ip.parse::<IpAddr>() {
                    if config.allow_private_ips || !is_private_ip(ip) {
                        debug!("Extracted IP from X-Forwarded-For: {}", ip);
                        return validate_and_return_ip(ip, config);
                    } else {
                        warn!("Private IP {} in X-Forwarded-For rejected", ip);
                    }
                } else {
                    warn!("Invalid IP format in X-Forwarded-For header: {}", client_ip);
                }
            }
        }

        // Try X-Real-IP header (used by nginx)
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(header_value) = real_ip.to_str() {
                if let Ok(ip) = header_value.parse::<IpAddr>() {
                    if config.allow_private_ips || !is_private_ip(ip) {
                        debug!("Extracted IP from X-Real-IP: {}", ip);
                        return validate_and_return_ip(ip, config);
                    } else {
                        warn!("Private IP {} in X-Real-IP rejected", ip);
                    }
                } else {
                    warn!("Invalid IP format in X-Real-IP header: {}", header_value);
                }
            }
        }

        // Try CF-Connecting-IP header (Cloudflare)
        if let Some(cf_ip) = headers.get("cf-connecting-ip") {
            if let Ok(header_value) = cf_ip.to_str() {
                if let Ok(ip) = header_value.parse::<IpAddr>() {
                    if config.allow_private_ips || !is_private_ip(ip) {
                        debug!("Extracted IP from CF-Connecting-IP: {}", ip);
                        return validate_and_return_ip(ip, config);
                    } else {
                        warn!("Private IP {} in CF-Connecting-IP rejected", ip);
                    }
                } else {
                    warn!("Invalid IP format in CF-Connecting-IP header: {}", header_value);
                }
            }
        }

        // Try X-Client-IP header
        if let Some(client_ip) = headers.get("x-client-ip") {
            if let Ok(header_value) = client_ip.to_str() {
                if let Ok(ip) = header_value.parse::<IpAddr>() {
                    if config.allow_private_ips || !is_private_ip(ip) {
                        debug!("Extracted IP from X-Client-IP: {}", ip);
                        return validate_and_return_ip(ip, config);
                    } else {
                        warn!("Private IP {} in X-Client-IP rejected", ip);
                    }
                } else {
                    warn!("Invalid IP format in X-Client-IP header: {}", header_value);
                }
            }
        }

        warn!("Could not extract valid client IP from proxy headers, using proxy IP");
    }

    // Fallback to direct connection IP or localhost
    if let Some(ip) = direct_ip {
        if config.allow_private_ips || !is_private_ip(ip) {
            debug!("Using direct connection IP as fallback: {}", ip);
            return ip;
        }
    }

    // Ultimate fallback
    warn!("No valid IP could be determined, using localhost fallback");
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

/// Validate IP and return it, with security logging
fn validate_and_return_ip(ip: IpAddr, config: &IpExtractionConfig) -> IpAddr {
    // Check for obviously malicious IPs
    if is_malicious_ip(ip) {
        warn!("Potentially malicious IP detected: {}", ip);
        // Could implement additional security measures here
    }
    
    // Check for private IPs in production
    if !config.allow_private_ips && is_private_ip(ip) {
        warn!("Private IP {} rejected in production mode", ip);
        return IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    }
    
    ip
}

/// Check if an IP address is in private ranges
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            // RFC 1918 private ranges
            ipv4.is_private() || 
            ipv4.is_loopback() || 
            ipv4.is_link_local() ||
            // Additional checks for special ranges
            ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 || // Link-local
            ipv4.octets()[0] == 127 // Loopback range
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() ||
            ipv6.is_unspecified() ||
            // RFC 4193 Unique Local Addresses
            (ipv6.segments()[0] & 0xfe00) == 0xfc00 ||
            // Link-local
            (ipv6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Check for obviously malicious or suspicious IP patterns
fn is_malicious_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            
            // Reserved/special ranges that shouldn't be client IPs
            octets[0] == 0 || // "This network"
            octets[0] == 224 || // Multicast
            octets[0] >= 240 || // Reserved
            ipv4.is_unspecified() ||
            ipv4.is_broadcast() ||
            ipv4.is_multicast()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_multicast() ||
            ipv6.is_unspecified() ||
            // Documentation range
            (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0db8)
        }
    }
}

/// Log suspicious IP activity for security monitoring
pub fn log_suspicious_ip_activity(ip: IpAddr, reason: &str, headers: &HeaderMap) {
    warn!("Suspicious IP activity from {}: {}", ip, reason);
    
    // Log relevant headers for forensic analysis
    debug!("Headers for suspicious IP {}:", ip);
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            debug!("  {}: {}", name, value_str);
        }
    }
    
    // TODO: Could integrate with security monitoring systems here
    // - Send to SIEM
    // - Update threat intelligence feeds
    // - Trigger automated blocking
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::hyper::header::HeaderValue;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_malicious_ip_detection() {
        assert!(is_malicious_ip("0.0.0.0".parse().unwrap()));
        assert!(is_malicious_ip("224.0.0.1".parse().unwrap()));
        assert!(is_malicious_ip("255.255.255.255".parse().unwrap()));
        assert!(!is_malicious_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_extraction_no_proxy() {
        let config = IpExtractionConfig::default();
        let headers = HeaderMap::new();
        let remote_addr = Some("203.0.113.1:12345".parse().unwrap());
        
        let result = extract_client_ip(&headers, remote_addr, &config);
        assert_eq!(result, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_ip_extraction_with_proxy() {
        let mut config = IpExtractionConfig::default();
        config.trust_proxy_headers = true;
        config.trusted_proxies = vec!["203.0.113.100".parse().unwrap()];
        
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));
        
        let remote_addr = Some("203.0.113.100:12345".parse().unwrap());
        
        let result = extract_client_ip(&headers, remote_addr, &config);
        assert_eq!(result, "203.0.113.1".parse::<IpAddr>().unwrap());
    }
}