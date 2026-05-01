//! Rate limiting implementation for token requests
//!
//! This module provides functionality for rate limiting token requests
//! to prevent abuse.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::error::{BaffaoError, BaffaoResult};

/// Default rate limit window in seconds
const DEFAULT_WINDOW_SECONDS: u64 = 60;
/// Default maximum requests per window
const DEFAULT_MAX_REQUESTS: u32 = 10;

/// A record of rate-limited requests
#[derive(Debug, Clone)]
struct RequestRecord {
    /// The time of the first request in the current window
    window_start: Instant,
    /// Count of requests in the current window
    count: u32,
}

/// Rate limiter configuration
#[derive(Debug, Clone, Copy)]
pub struct RateLimiterConfig {
    /// Window size in seconds
    pub window_seconds: u64,
    /// Maximum requests per window
    pub max_requests: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_WINDOW_SECONDS,
            max_requests: DEFAULT_MAX_REQUESTS,
        }
    }
}

/// Rate limiter for controlling request frequency
pub struct RateLimiter {
    /// Rate limiter configuration
    config: RateLimiterConfig,
    /// Map of identifiers to request records
    records: Arc<Mutex<HashMap<String, RequestRecord>>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Creates a new rate limiter with default configuration
    pub fn default() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Checks if a request is allowed and updates the rate limit record
    pub async fn check(&self, identifier: &str) -> BaffaoResult<()> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_seconds);

        let mut records = self.records.lock().await;

        // Get or create record for this identifier
        let record = records.entry(identifier.to_string()).or_insert_with(|| RequestRecord {
            window_start: now,
            count: 0,
        });

        // Check if window has expired and reset if needed
        if now.duration_since(record.window_start) > window_duration {
            record.window_start = now;
            record.count = 0;
        }

        // Check if rate limit exceeded
        if record.count >= self.config.max_requests {
            let time_remaining = window_duration
                .checked_sub(now.duration_since(record.window_start))
                .unwrap_or_default();

            return Err(BaffaoError::RateLimitExceeded(format!(
                "Rate limit exceeded. Try again in {} seconds",
                time_remaining.as_secs()
            )));
        }

        // Increment count
        record.count += 1;

        // Periodically clean up stale records (with a small probability to avoid doing this too often)
        if rand::random::<u8>() < 5 {
            self.cleanup(&mut records, now, window_duration);
        }

        Ok(())
    }

    /// Cleans up stale records
    fn cleanup(
        &self,
        records: &mut HashMap<String, RequestRecord>,
        now: Instant,
        window_duration: Duration,
    ) {
        records.retain(|_, record| now.duration_since(record.window_start) <= window_duration);
    }

    /// Resets rate limit for a specific identifier
    pub async fn reset(&self, identifier: &str) -> BaffaoResult<()> {
        let mut records = self.records.lock().await;
        records.remove(identifier);
        Ok(())
    }

    /// Gets the current rate limit status for an identifier
    pub async fn get_status(&self, identifier: &str) -> BaffaoResult<RateLimitStatus> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_seconds);

        let records = self.records.lock().await;
        
        if let Some(record) = records.get(identifier) {
            // Check if window has expired
            if now.duration_since(record.window_start) > window_duration {
                Ok(RateLimitStatus {
                    remaining: self.config.max_requests,
                    reset_after: 0,
                    limit: self.config.max_requests,
                })
            } else {
                let remaining = self.config.max_requests.saturating_sub(record.count);
                let reset_after = window_duration
                    .checked_sub(now.duration_since(record.window_start))
                    .unwrap_or_default()
                    .as_secs();
                
                Ok(RateLimitStatus {
                    remaining,
                    reset_after,
                    limit: self.config.max_requests,
                })
            }
        } else {
            // No record means no requests yet
            Ok(RateLimitStatus {
                remaining: self.config.max_requests,
                reset_after: 0,
                limit: self.config.max_requests,
            })
        }
    }
}

/// Rate limit status for a specific identifier
#[derive(Debug, Clone, Copy)]
pub struct RateLimitStatus {
    /// Remaining requests in the current window
    pub remaining: u32,
    /// Seconds until the window resets
    pub reset_after: u64,
    /// Total request limit
    pub limit: u32,
}

/// Rate-limited token manager decorator
pub struct RateLimitedTokenManager<T> {
    /// Inner token manager
    inner: Arc<T>,
    /// Rate limiter for get_access_token
    get_limiter: RateLimiter,
    /// Rate limiter for refresh_token
    refresh_limiter: RateLimiter,
}

impl<T> RateLimitedTokenManager<T> {
    /// Creates a new rate-limited token manager
    pub fn new(
        inner: T,
        get_config: Option<RateLimiterConfig>,
        refresh_config: Option<RateLimiterConfig>,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            get_limiter: RateLimiter::new(get_config.unwrap_or_default()),
            refresh_limiter: RateLimiter::new(refresh_config.unwrap_or_else(|| RateLimiterConfig {
                window_seconds: 300, // 5 minutes
                max_requests: 5,     // 5 requests per 5 minutes
            })),
        }
    }
    
    /// Creates a new rate-limited token manager with default configuration
    pub fn default(inner: T) -> Self {
        Self::new(inner, None, None)
    }
}

#[async_trait::async_trait]
impl<T: crate::token::TokenManager + Sync + Send> crate::token::TokenManager for RateLimitedTokenManager<T> {
    async fn store_access_token(&self, user_id: &str, token: crate::token::AccessToken) -> BaffaoResult<()> {
        self.inner.store_access_token(user_id, token).await
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<crate::token::AccessToken>> {
        // Apply rate limiting
        self.get_limiter.check(user_id).await?;
        
        // Forward to inner implementation
        self.inner.get_access_token(user_id).await
    }

    async fn store_refresh_token(&self, user_id: &str, token: crate::token::RefreshToken) -> BaffaoResult<()> {
        self.inner.store_refresh_token(user_id, token).await
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<crate::token::RefreshToken>> {
        // Apply rate limiting
        self.refresh_limiter.check(user_id).await?;
        
        // Forward to inner implementation
        self.inner.get_refresh_token(user_id).await
    }
    
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        // Reset rate limits for this user
        self.get_limiter.reset(user_id).await?;
        self.refresh_limiter.reset(user_id).await?;
        
        // Forward to inner implementation
        self.inner.revoke_tokens(user_id).await
    }
    
    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<crate::token::AccessToken>> {
        // Apply rate limiting
        self.get_limiter.check(user_id).await?;
        
        // Forward to inner implementation
        self.inner.get_access_token_for_scope(user_id, required_scopes).await
    }
}