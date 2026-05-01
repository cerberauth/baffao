//! Key patterns for Redis storage.

/// Builds a session key for Redis.
pub fn session_key(session_id: &str) -> String {
    format!("baffao:session:{}", session_id)
}

/// Builds a user sessions index key for Redis.
pub fn user_sessions_key(user_id: &str) -> String {
    format!("baffao:user:{}:sessions", user_id)
}

/// Builds an access token key for Redis.
pub fn access_token_key(user_id: &str) -> String {
    format!("baffao:access_token:{}", user_id)
}

/// Builds a refresh token key for Redis.
pub fn refresh_token_key(user_id: &str) -> String {
    format!("baffao:refresh_token:{}", user_id)
}

/// Builds a token search index key for Redis.
pub fn token_search_index_key(token: &str) -> String {
    format!("baffao:token_index:{}", token)
}

/// Builds an expiry key for Redis.
pub fn expiry_key(key: &str) -> String {
    format!("{}:expiry", key)
}
