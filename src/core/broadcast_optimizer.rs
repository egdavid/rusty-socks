//! Optimized broadcasting implementation
//! 
//! This module provides an efficient broadcasting system that avoids
//! spawning tasks for each recipient and uses worker pools instead.

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use warp::ws::Message as WsMessage;

use crate::error::{Result, RustySocksError};
use crate::core::connection::Connection;

/// Broadcast task for worker processing
#[derive(Clone)]
struct BroadcastTask {
    recipient_id: String,
    message: Arc<String>, // Arc to avoid cloning the message content
    connection: Arc<Connection>,
}

/// Optimized broadcast manager with worker pools
pub struct BroadcastOptimizer {
    /// Channel for sending broadcast tasks
    task_sender: mpsc::Sender<BroadcastTask>,
}

impl BroadcastOptimizer {
    /// Create a new broadcast optimizer with specified number of workers
    pub fn new(num_workers: usize) -> Self {
        let (tx, rx) = mpsc::channel(10000); // Large buffer for burst handling
        
        // Spawn worker pool
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for worker_id in 0..num_workers {
            let worker_rx = rx.clone();
            tokio::spawn(async move {
                Self::worker_loop(worker_id, worker_rx).await;
            });
        }
        
        Self {
            task_sender: tx,
        }
    }
    
    /// Worker loop that processes broadcast tasks
    async fn worker_loop(
        worker_id: usize,
        rx: Arc<tokio::sync::Mutex<mpsc::Receiver<BroadcastTask>>>
    ) {
        loop {
            let task = {
                let mut receiver = rx.lock().await;
                receiver.recv().await
            };
            
            match task {
                Some(task) => {
                    if let Err(e) = Self::send_to_connection(&task).await {
                        log::debug!(
                            "Worker {} failed to send to {}: {}",
                            worker_id,
                            task.recipient_id,
                            e
                        );
                    }
                }
                None => {
                    log::info!("Worker {} shutting down", worker_id);
                    break;
                }
            }
        }
    }
    
    /// Send message to a single connection
    async fn send_to_connection(task: &BroadcastTask) -> Result<()> {
        task.connection
            .sender
            .send(WsMessage::text(task.message.as_str()))
            .map_err(|_| RustySocksError::ConnectionError(
                format!("Failed to send to {}", task.recipient_id)
            ))
    }
    
    /// Broadcast a message to multiple recipients efficiently
    pub async fn broadcast(
        &self,
        message: &str,
        recipients: Vec<(String, Arc<Connection>)>,
    ) -> Result<BroadcastStats> {
        let message = Arc::new(message.to_string());
        let start = std::time::Instant::now();
        let total_recipients = recipients.len();
        let mut sent_count = 0;
        
        // Queue all tasks without blocking
        for (recipient_id, connection) in recipients {
            let task = BroadcastTask {
                recipient_id,
                message: message.clone(),
                connection,
            };
            
            // Use try_send to avoid blocking
            match self.task_sender.try_send(task.clone()) {
                Ok(_) => sent_count += 1,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Channel full, fall back to blocking send
                    if self.task_sender.send(task).await.is_ok() {
                        sent_count += 1;
                    }
                }
                Err(_) => {
                    log::error!("Broadcast channel closed");
                    break;
                }
            }
        }
        
        Ok(BroadcastStats {
            total_recipients,
            sent_count,
            duration: start.elapsed(),
        })
    }
    
    /// Broadcast with batching for very large recipient lists
    pub async fn broadcast_batched(
        &self,
        message: &str,
        recipients: Vec<(String, Arc<Connection>)>,
        batch_size: usize,
    ) -> Result<BroadcastStats> {
        let mut total_stats = BroadcastStats::default();
        
        for batch in recipients.chunks(batch_size) {
            let stats = self.broadcast(message, batch.to_vec()).await?;
            total_stats.merge(stats);
            
            // Small delay between batches to prevent overwhelming
            tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
        }
        
        Ok(total_stats)
    }
}

/// Statistics for broadcast operations
#[derive(Debug, Default)]
pub struct BroadcastStats {
    pub total_recipients: usize,
    pub sent_count: usize,
    pub duration: std::time::Duration,
}

impl BroadcastStats {
    fn merge(&mut self, other: BroadcastStats) {
        self.total_recipients += other.total_recipients;
        self.sent_count += other.sent_count;
        self.duration += other.duration;
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.total_recipients == 0 {
            1.0
        } else {
            self.sent_count as f64 / self.total_recipients as f64
        }
    }
    
    pub fn messages_per_second(&self) -> f64 {
        if self.duration.as_secs_f64() == 0.0 {
            0.0
        } else {
            self.sent_count as f64 / self.duration.as_secs_f64()
        }
    }
}

/// Serialization cache to avoid repeated JSON encoding
pub struct SerializationCache<T: serde::Serialize> {
    cache: Arc<RwLock<lru::LruCache<String, Arc<String>>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: serde::Serialize> SerializationCache<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap()
            ))),
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Get or compute serialized value
    pub async fn get_or_serialize(&self, key: &str, value: &T) -> Result<Arc<String>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(key) {
                return Ok(cached.clone());
            }
        }
        
        // Serialize if not in cache
        let serialized = serde_json::to_string(value)
            .map_err(|e| RustySocksError::MessageParseError(e.to_string()))?;
        let serialized = Arc::new(serialized);
        
        // Store in cache
        {
            let mut cache = self.cache.write().await;
            cache.put(key.to_string(), serialized.clone());
        }
        
        Ok(serialized)
    }
    
    /// Clear the cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_broadcast_optimizer() {
        let optimizer = BroadcastOptimizer::new(4);
        
        // Create mock connections
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        
        let conn1 = Arc::new(Connection {
            id: "user1".to_string(),
            sender: tx1,
            connected_at: std::time::Instant::now(),
            last_ping: std::time::Instant::now(),
            user: None,
            client_ip: "192.168.1.1".parse().unwrap(),
        });
        
        let conn2 = Arc::new(Connection {
            id: "user2".to_string(),
            sender: tx2,
            connected_at: std::time::Instant::now(),
            last_ping: std::time::Instant::now(),
            user: None,
            client_ip: "192.168.1.2".parse().unwrap(),
        });
        
        let recipients = vec![
            ("user1".to_string(), conn1),
            ("user2".to_string(), conn2),
        ];
        
        let stats = optimizer.broadcast("test message", recipients).await.unwrap();
        assert_eq!(stats.total_recipients, 2);
        assert_eq!(stats.sent_count, 2);
    }
    
    #[tokio::test]
    async fn test_serialization_cache() {
        let cache = SerializationCache::<String>::new(10);
        
        let value = "test value".to_string();
        let key = "test_key";
        
        // First call should serialize
        let result1 = cache.get_or_serialize(key, &value).await.unwrap();
        
        // Second call should hit cache
        let result2 = cache.get_or_serialize(key, &value).await.unwrap();
        
        // Should be the same Arc
        assert!(Arc::ptr_eq(&result1, &result2));
    }
}