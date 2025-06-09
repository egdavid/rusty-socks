//! Generic metrics collection and reporting system
//! 
//! This module provides a pluggable metrics interface that can work with
//! various backends like Prometheus, StatsD, or custom collectors.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::Result;

/// Metric value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram { buckets: Vec<f64>, count: u64, sum: f64 },
    Summary { quantiles: Vec<(String, f64)>, count: u64, sum: f64 },
}

/// A single metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: MetricValue,
    pub labels: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
    pub help: Option<String>,
}

/// Metric collection interface
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Record a counter increment
    async fn increment_counter(&self, name: &str, labels: HashMap<String, String>) -> Result<()>;
    
    /// Record a counter increment by a specific amount
    async fn increment_counter_by(&self, name: &str, value: u64, labels: HashMap<String, String>) -> Result<()>;
    
    /// Set a gauge value
    async fn set_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()>;
    
    /// Record a histogram observation
    async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()>;
    
    /// Record a timing measurement
    async fn record_timing(&self, name: &str, duration: Duration, labels: HashMap<String, String>) -> Result<()>;
    
    /// Get current metric values
    async fn get_metrics(&self) -> Result<Vec<Metric>>;
    
    /// Get metrics in a specific format (prometheus, json, etc.)
    async fn export_metrics(&self, format: &str) -> Result<String>;
    
    /// Reset all metrics
    async fn reset(&self) -> Result<()>;
}

/// In-memory metrics collector for development and basic use cases
pub struct InMemoryMetricsCollector {
    metrics: Arc<RwLock<HashMap<String, Metric>>>,
}

impl InMemoryMetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    fn metric_key(name: &str, labels: &HashMap<String, String>) -> String {
        let mut key = name.to_string();
        let mut sorted_labels: Vec<_> = labels.iter().collect();
        sorted_labels.sort_by_key(|(k, _)| *k);
        
        for (k, v) in sorted_labels {
            key.push_str(&format!("{}={}", k, v));
        }
        key
    }
}

#[async_trait]
impl MetricsCollector for InMemoryMetricsCollector {
    async fn increment_counter(&self, name: &str, labels: HashMap<String, String>) -> Result<()> {
        self.increment_counter_by(name, 1, labels).await
    }
    
    async fn increment_counter_by(&self, name: &str, value: u64, labels: HashMap<String, String>) -> Result<()> {
        let key = Self::metric_key(name, &labels);
        let mut metrics = self.metrics.write().await;
        
        let metric = metrics.entry(key).or_insert_with(|| Metric {
            name: name.to_string(),
            value: MetricValue::Counter(0),
            labels: labels.clone(),
            timestamp: Utc::now(),
            help: None,
        });
        
        if let MetricValue::Counter(ref mut count) = metric.value {
            *count += value;
            metric.timestamp = Utc::now();
        }
        
        Ok(())
    }
    
    async fn set_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let key = Self::metric_key(name, &labels);
        let mut metrics = self.metrics.write().await;
        
        metrics.insert(key, Metric {
            name: name.to_string(),
            value: MetricValue::Gauge(value),
            labels,
            timestamp: Utc::now(),
            help: None,
        });
        
        Ok(())
    }
    
    async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let key = Self::metric_key(name, &labels);
        let mut metrics = self.metrics.write().await;
        
        let metric = metrics.entry(key).or_insert_with(|| Metric {
            name: name.to_string(),
            value: MetricValue::Histogram {
                buckets: vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
                count: 0,
                sum: 0.0,
            },
            labels: labels.clone(),
            timestamp: Utc::now(),
            help: None,
        });
        
        if let MetricValue::Histogram { count, sum, .. } = &mut metric.value {
            *count += 1;
            *sum += value;
            metric.timestamp = Utc::now();
        }
        
        Ok(())
    }
    
    async fn record_timing(&self, name: &str, duration: Duration, labels: HashMap<String, String>) -> Result<()> {
        let seconds = duration.as_secs_f64();
        self.record_histogram(name, seconds, labels).await
    }
    
    async fn get_metrics(&self) -> Result<Vec<Metric>> {
        let metrics = self.metrics.read().await;
        Ok(metrics.values().cloned().collect())
    }
    
    async fn export_metrics(&self, format: &str) -> Result<String> {
        let metrics = self.get_metrics().await?;
        
        match format {
            "json" => {
                Ok(serde_json::to_string_pretty(&metrics)?)
            }
            "prometheus" => {
                let mut output = String::new();
                
                for metric in metrics {
                    // Format as Prometheus text format
                    output.push_str(&format!("# TYPE {} ", metric.name));
                    
                    match metric.value {
                        MetricValue::Counter(_) => output.push_str("counter\n"),
                        MetricValue::Gauge(_) => output.push_str("gauge\n"),
                        MetricValue::Histogram { .. } => output.push_str("histogram\n"),
                        MetricValue::Summary { .. } => output.push_str("summary\n"),
                    }
                    
                    let labels_str = if metric.labels.is_empty() {
                        String::new()
                    } else {
                        let mut labels_vec: Vec<_> = metric.labels.iter().collect();
                        labels_vec.sort_by_key(|(k, _)| *k);
                        let labels: Vec<String> = labels_vec
                            .iter()
                            .map(|(k, v)| format!("{}=\"{}\"", k, v))
                            .collect();
                        format!("{{{}}}", labels.join(","))
                    };
                    
                    match metric.value {
                        MetricValue::Counter(value) => {
                            output.push_str(&format!("{}{} {}\n", metric.name, labels_str, value));
                        }
                        MetricValue::Gauge(value) => {
                            output.push_str(&format!("{}{} {}\n", metric.name, labels_str, value));
                        }
                        MetricValue::Histogram { count, sum, .. } => {
                            output.push_str(&format!("{}_count{} {}\n", metric.name, labels_str, count));
                            output.push_str(&format!("{}_sum{} {}\n", metric.name, labels_str, sum));
                        }
                        MetricValue::Summary { count, sum, .. } => {
                            output.push_str(&format!("{}_count{} {}\n", metric.name, labels_str, count));
                            output.push_str(&format!("{}_sum{} {}\n", metric.name, labels_str, sum));
                        }
                    }
                    
                    output.push('\n');
                }
                
                Ok(output)
            }
            _ => Err(crate::error::RustySocksError::ValidationError(
                format!("Unsupported export format: {}", format)
            ))
        }
    }
    
    async fn reset(&self) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        metrics.clear();
        Ok(())
    }
}

/// Performance timer for measuring operation durations
pub struct Timer {
    start: Instant,
    name: String,
    labels: HashMap<String, String>,
    collector: Arc<dyn MetricsCollector>,
}

impl Timer {
    pub fn new(name: String, labels: HashMap<String, String>, collector: Arc<dyn MetricsCollector>) -> Self {
        Self {
            start: Instant::now(),
            name,
            labels,
            collector,
        }
    }
    
    pub async fn finish(self) -> Result<Duration> {
        let duration = self.start.elapsed();
        self.collector.record_timing(&self.name, duration, self.labels).await?;
        Ok(duration)
    }
}

/// Metrics middleware for automatic instrumentation
pub struct MetricsMiddleware {
    collector: Arc<dyn MetricsCollector>,
}

impl MetricsMiddleware {
    pub fn new(collector: Arc<dyn MetricsCollector>) -> Self {
        Self { collector }
    }
    
    /// Record a WebSocket connection
    pub async fn record_connection(&self, client_ip: Option<std::net::IpAddr>) -> Result<()> {
        let mut labels = HashMap::new();
        if let Some(ip) = client_ip {
            labels.insert("client_ip".to_string(), ip.to_string());
        }
        
        self.collector.increment_counter("websocket_connections_total", labels).await
    }
    
    /// Record a WebSocket disconnection
    pub async fn record_disconnection(&self, reason: &str) -> Result<()> {
        let mut labels = HashMap::new();
        labels.insert("reason".to_string(), reason.to_string());
        
        self.collector.increment_counter("websocket_disconnections_total", labels).await
    }
    
    /// Record a message sent
    pub async fn record_message_sent(&self, message_type: &str, room_id: Option<&str>) -> Result<()> {
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), message_type.to_string());
        if let Some(room) = room_id {
            labels.insert("room_id".to_string(), room.to_string());
        }
        
        self.collector.increment_counter("messages_sent_total", labels).await
    }
    
    /// Record authentication attempt
    pub async fn record_auth_attempt(&self, provider: &str, success: bool) -> Result<()> {
        let mut labels = HashMap::new();
        labels.insert("provider".to_string(), provider.to_string());
        labels.insert("success".to_string(), success.to_string());
        
        self.collector.increment_counter("auth_attempts_total", labels).await
    }
    
    /// Record room operations
    pub async fn record_room_operation(&self, operation: &str, room_id: &str) -> Result<()> {
        let mut labels = HashMap::new();
        labels.insert("operation".to_string(), operation.to_string());
        labels.insert("room_id".to_string(), room_id.to_string());
        
        self.collector.increment_counter("room_operations_total", labels).await
    }
    
    /// Update active connections gauge
    pub async fn update_active_connections(&self, count: usize) -> Result<()> {
        self.collector.set_gauge("active_connections", count as f64, HashMap::new()).await
    }
    
    /// Update active rooms gauge
    pub async fn update_active_rooms(&self, count: usize) -> Result<()> {
        self.collector.set_gauge("active_rooms", count as f64, HashMap::new()).await
    }
    
    /// Start a timer for an operation
    pub fn start_timer(&self, name: &str, labels: HashMap<String, String>) -> Timer {
        Timer::new(name.to_string(), labels, self.collector.clone())
    }
}

/// Server metrics aggregator
pub struct ServerMetrics {
    middleware: MetricsMiddleware,
    collector: Arc<dyn MetricsCollector>,
}

impl ServerMetrics {
    pub fn new(collector: Arc<dyn MetricsCollector>) -> Self {
        let middleware = MetricsMiddleware::new(collector.clone());
        Self { middleware, collector }
    }
    
    pub fn middleware(&self) -> &MetricsMiddleware {
        &self.middleware
    }
    
    pub async fn get_server_stats(&self) -> Result<ServerStats> {
        let metrics = self.collector.get_metrics().await?;
        
        let mut stats = ServerStats {
            total_connections: 0,
            active_connections: 0,
            total_messages: 0,
            total_rooms: 0,
            auth_success_rate: 0.0,
            average_response_time: 0.0,
            uptime_seconds: 0.0,
        };
        
        for metric in metrics {
            match metric.name.as_str() {
                "websocket_connections_total" => {
                    if let MetricValue::Counter(count) = metric.value {
                        stats.total_connections += count;
                    }
                }
                "active_connections" => {
                    if let MetricValue::Gauge(count) = metric.value {
                        stats.active_connections = count as u64;
                    }
                }
                "messages_sent_total" => {
                    if let MetricValue::Counter(count) = metric.value {
                        stats.total_messages += count;
                    }
                }
                "active_rooms" => {
                    if let MetricValue::Gauge(count) = metric.value {
                        stats.total_rooms = count as u64;
                    }
                }
                _ => {}
            }
        }
        
        Ok(stats)
    }
    
    pub async fn export(&self, format: &str) -> Result<String> {
        self.collector.export_metrics(format).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_messages: u64,
    pub total_rooms: u64,
    pub auth_success_rate: f64,
    pub average_response_time: f64,
    pub uptime_seconds: f64,
}

/// Create a default in-memory metrics collector
pub fn create_default_metrics() -> Arc<dyn MetricsCollector> {
    Arc::new(InMemoryMetricsCollector::new())
}