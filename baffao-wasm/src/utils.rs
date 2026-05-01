use js_sys::Math;
use wasm_bindgen::prelude::*;

use crate::storage;

const CSRF_TOKEN_KEY: &str = "baffao_csrf_token";

/// Generates a random string of the specified length
pub fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let charset_len = CHARSET.len() as u32;

    (0..length)
        .map(|_| {
            let idx = (Math::random() * charset_len as f64) as usize;
            CHARSET[idx % CHARSET.len()] as char
        })
        .collect()
}

/// Gets the CSRF token, generating a new one if it doesn't exist
pub fn get_csrf_token() -> Option<String> {
    if let Some(token) = storage::get_session(CSRF_TOKEN_KEY) {
        Some(token)
    } else {
        // Generate a new token
        let token = generate_random_string(32);
        let _ = storage::store_session(CSRF_TOKEN_KEY, &token);
        Some(token)
    }
}

/// Gets the URL parameters as a key-value map
pub fn get_url_params() -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    if let Some(window) = web_sys::window() {
        let location = window.location();
        if let Ok(search) = location.search() {
            if !search.is_empty() {
                let search = search.trim_start_matches('?');
                for pair in search.split('&') {
                    let mut items = pair.split('=');
                    if let Some(key) = items.next() {
                        let value = items.next().unwrap_or("");
                        params.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }
    }

    params
}
