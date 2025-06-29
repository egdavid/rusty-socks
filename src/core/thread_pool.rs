//! Thread pool management for the WebSocket server
//!
//! This module provides a configurable thread pool to efficiently manage
//! concurrent client connections and message processing tasks.

use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

use crate::config::ServerConfig;
use crate::error::{Result, RustySocksError};

/// Represents a thread pool for executing WebSocket related tasks with DoS protection
pub struct ThreadPool {
    /// Runtime instance managing the thread pool
    runtime: Arc<Runtime>,
    /// Number of worker threads in the pool
    worker_count: usize,
    /// Maximum number of tasks that can be queued
    max_queued_tasks: usize,
    /// Current number of active tasks
    active_tasks: Arc<Mutex<usize>>,
    /// Rate limiter for task submissions (per-second)
    task_rate_limiter: Arc<Mutex<Vec<Instant>>>,
    /// Maximum tasks per second to prevent DoS
    max_tasks_per_second: usize,
}

impl ThreadPool {
    /// Create a new thread pool with the specified number of worker threads and DoS protection
    ///
    /// # Arguments
    /// * `worker_count` - Number of worker threads to create
    /// * `max_queued_tasks` - Maximum number of tasks that can be queued
    ///
    /// # Returns
    /// A `Result` containing the `ThreadPool` or an error
    pub fn new(worker_count: usize, max_queued_tasks: usize) -> Result<Self> {
        // Set a minimum number of threads to avoid performance issues
        let actual_workers = worker_count.max(2);
        
        // Calculate reasonable task rate limit based on thread count
        let max_tasks_per_second = (actual_workers * 100).min(1000); // Max 1000 tasks/sec

        let runtime = match Builder::new_multi_thread()
            .worker_threads(actual_workers)
            .enable_io()
            .enable_time()
            .thread_name("rusty-socks-worker")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return Err(RustySocksError::SystemError(format!(
                    "Failed to build thread pool runtime: {}",
                    e
                )))
            }
        };

        info!(
            "Created thread pool with {} worker threads and {} max queued tasks",
            actual_workers, max_queued_tasks
        );

        Ok(Self {
            runtime: Arc::new(runtime),
            worker_count: actual_workers,
            max_queued_tasks,
            active_tasks: Arc::new(Mutex::new(0)),
            task_rate_limiter: Arc::new(Mutex::new(Vec::new())),
            max_tasks_per_second,
        })
    }

    /// Create a thread pool from server configuration
    ///
    /// # Arguments
    /// * `config` - Server configuration containing thread pool parameters
    ///
    /// # Returns
    /// A `Result` containing the `ThreadPool` or an error
    pub fn from_config(config: &ServerConfig) -> Result<Self> {
        Self::new(config.thread_pool_size, config.max_queued_tasks)
    }

    /// Execute a future on the thread pool with DoS protection
    ///
    /// # Arguments
    /// * `future` - Task to be executed
    ///
    /// # Returns
    /// An `Option<JoinHandle<T>>` that can be used to await the task's result,
    /// or `None` if the thread pool is at capacity or rate limited
    pub fn execute<F>(&self, future: F) -> Option<JoinHandle<F::Output>>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Check rate limiting first
        if !self.check_task_rate_limit() {
            warn!("Task submission rate limit exceeded, rejecting task");
            return None;
        }

        // Check if we can accept more tasks
        let mut active_count = match self.active_tasks.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Thread pool mutex poisoned: {}", e);
                return None;
            }
        };

        if *active_count >= self.max_queued_tasks {
            warn!(
                "Thread pool at capacity ({} active tasks), rejecting new task",
                *active_count
            );
            return None;
        }

        // Increment active task count
        *active_count += 1;
        let active_tasks_clone = Arc::clone(&self.active_tasks);

        // Spawn the task, wrapping it to track completion
        let handle = self.runtime.spawn(async move {
            let result = future.await;

            // Decrement the active task count when done
            if let Ok(mut count) = active_tasks_clone.lock() {
                *count = count.saturating_sub(1);
            }

            result
        });

        Some(handle)
    }
    
    /// Check if task submission rate is within limits
    fn check_task_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut rate_limiter = match self.task_rate_limiter.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Rate limiter mutex poisoned: {}", e);
                return false;
            }
        };
        
        // Remove entries older than 1 second
        rate_limiter.retain(|&time| now.duration_since(time) < Duration::from_secs(1));
        
        // Check if we're under the rate limit
        if rate_limiter.len() >= self.max_tasks_per_second {
            return false;
        }
        
        // Add current timestamp
        rate_limiter.push(now);
        true
    }

    /// Get the current number of active tasks
    pub fn active_task_count(&self) -> Result<usize> {
        let count = self.active_tasks.lock().map_err(|e| {
            RustySocksError::SystemError(format!("Failed to access active tasks counter: {}", e))
        })?;

        Ok(*count)
    }

    /// Get the number of worker threads in the pool
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        info!(
            "Shutting down thread pool with {} worker threads",
            self.worker_count
        );
    }
}

/// Shared thread pool that can be accessed by multiple components
pub type SharedThreadPool = Arc<ThreadPool>;

/// Create a new shared thread pool
///
/// # Arguments
/// * `config` - Server configuration containing thread pool parameters
///
/// # Returns
/// A `Result` containing the shared thread pool or an error
pub fn create_thread_pool(config: &ServerConfig) -> Result<SharedThreadPool> {
    let pool = ThreadPool::from_config(config)?;
    Ok(Arc::new(pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_thread_pool_creation() {
        let pool = ThreadPool::new(4, 100).expect("Failed to create thread pool");
        assert_eq!(pool.worker_count(), 4);
    }

    #[test]
    fn test_execute_task() {
        let pool = ThreadPool::new(2, 10).expect("Failed to create thread pool");

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let handle = pool
                .execute(async {
                    sleep(Duration::from_millis(100)).await;
                    42
                })
                .expect("Failed to execute task");

            let result = handle.await.expect("Task failed");
            assert_eq!(result, 42);

            let active = pool
                .active_task_count()
                .expect("Failed to get active count");
            assert_eq!(active, 0);
        });
    }
}
