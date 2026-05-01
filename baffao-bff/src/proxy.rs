use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Method, Uri},
    response::Response,
};
use baffao_core::error::{BaffaoError, BaffaoResult};
use baffao_core::token::AccessToken;
use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;
use http::StatusCode;
use reqwest::Client;
use url::Url;

use crate::state::BffState;

/// Represents a destination URL for proxying requests
struct ProxyDestination {
    /// The URL of the destination
    pub url: String,
    /// Whether to strip the path prefix
    pub strip_prefix: bool,
    /// Allowed HTTP methods for this destination
    pub allowed_methods: Option<HashSet<Method>>,
    /// Required scopes for this destination
    pub required_scopes: Option<Vec<String>>,
}

/// Proxy a request to a backend service
pub async fn proxy_request<S, T>(
    state: &Arc<BffState<S, T>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    access_token: &AccessToken,
) -> BaffaoResult<Response<axum::body::Body>>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Extract the path from the URI
    let path = uri.path();
    let query = uri.query();
    
    // Determine the destination URL
    let destination = determine_destination(state, path)?;
    
    // Check if the method is allowed for this destination
    if let Some(allowed_methods) = &destination.allowed_methods {
        if !allowed_methods.contains(&method) {
            return Err(BaffaoError::Proxy(format!(
                "Method {} not allowed for path {}", method, path
            )));
        }
    }
    
    // Check if the access token has the required scopes
    if let Some(required_scopes) = &destination.required_scopes {
        if !access_token.has_scopes(required_scopes) {
            return Err(BaffaoError::Forbidden);
        }
    }
    
    // Build the destination URL
    let destination_url = build_destination_url(&destination, path)?;
    
    // If there's a query string, add it to the destination URL
    let full_destination_url = if let Some(q) = query {
        format!("{}?{}", destination_url, q)
    } else {
        destination_url
    };
    
    // Validate the destination URL
    validate_destination_url(&full_destination_url)?;
    
    // Create a reqwest client with default configuration
    // This includes default timeouts and security settings
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
        .build()
        .map_err(|e| BaffaoError::Proxy(format!("Failed to create HTTP client: {}", e)))?;
    
    // Build the request
    let mut req_builder = client
        .request(method.clone(), full_destination_url)
        .header("Authorization", format!("Bearer {}", access_token.token));
    
    // Add security headers
    req_builder = req_builder.header("X-Forwarded-For", "Baffao BFF");
    
    // Copy allowed headers
    let allowed_headers = [
        "accept", 
        "accept-language",
        "content-type", 
        "content-length",
        "user-agent",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    ];
    
    for (name, value) in headers {
        // Skip excluded headers
        if name.as_ref() == "cookie" ||
           name.as_ref() == "host" ||
           name.as_ref() == "authorization" ||
           name.as_ref() == "connection" ||
           name.as_ref() == "proxy-authorization" ||
           name.as_ref() == "www-authenticate" {
            continue;
        }
        
        // Only allow specified headers
        if let Some(name_str) = name.as_ref().to_str().ok() {
            if allowed_headers.contains(&name_str.to_lowercase().as_str()) {
                if let Some(header_name) = name {
                    req_builder = req_builder.header(header_name.clone(), value);
                }
            }
        }
    }
    
    // Add the body
    req_builder = req_builder.body(body);
    
    // Send the request
    let response = req_builder
        .send()
        .await
        .map_err(|e| BaffaoError::Proxy(e.to_string()))?;
    
    // Convert the response to an axum response
    let status = response.status();
    let mut response_headers = HeaderMap::new();
    
    // Only copy allowed response headers
    let allowed_response_headers = [
        "content-type",
        "content-length",
        "cache-control",
        "etag",
        "last-modified",
        "location",
    ];
    
    for (name, value) in response.headers() {
        if let Ok(name_str) = name.as_str().to_lowercase().parse::<String>() {
            if allowed_response_headers.contains(&name_str.as_str()) {
                response_headers.insert(name.clone(), value.clone());
            }
        }
    }
    
    // Extract the body
    let bytes = response
        .bytes()
        .await
        .map_err(|e| BaffaoError::Proxy(e.to_string()))?;
    
    // Build the response
    let mut axum_response = Response::builder()
        .status(status);
    
    // Add security headers
    axum_response = axum_response
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("X-XSS-Protection", "1; mode=block");
    
    // Add the rest of the headers
    for (name, value) in response_headers {
        axum_response = axum_response.header(name, value);
    }
    
    // Build and return the response
    axum_response
        .body(axum::body::Body::from(bytes))
        .map_err(|e| BaffaoError::Proxy(e.to_string()))
}

/// Validates a destination URL for security concerns
fn validate_destination_url(url_str: &str) -> BaffaoResult<()> {
    // Parse the URL
    let url = Url::parse(url_str)
        .map_err(|_| BaffaoError::InvalidUrl(url_str.to_string()))?;
    
    // Check for dangerous schemes
    match url.scheme() {
        "http" | "https" => {}, // These are allowed
        scheme => return Err(BaffaoError::Proxy(format!(
            "Scheme {} not allowed for proxy destination", scheme
        ))),
    }
    
    // Ensure there's a host
    if url.host_str().is_none() {
        return Err(BaffaoError::Proxy(
            "Missing host in destination URL".to_string()
        ));
    }
    
    // Disallow localhost and private networks in production
    // This can be commented out for development
    if let Some(host) = url.host_str() {
        if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" ||
           host.starts_with("192.168.") || host.starts_with("10.") || 
           host.starts_with("172.16.") || host.starts_with("172.17.") || 
           host.starts_with("172.18.") || host.starts_with("172.19.") || 
           host.starts_with("172.20.") || host.starts_with("172.21.") || 
           host.starts_with("172.22.") || host.starts_with("172.23.") || 
           host.starts_with("172.24.") || host.starts_with("172.25.") || 
           host.starts_with("172.26.") || host.starts_with("172.27.") || 
           host.starts_with("172.28.") || host.starts_with("172.29.") || 
           host.starts_with("172.30.") || host.starts_with("172.31.") {
            
            // Enable this in production:
            // return Err(BaffaoError::Proxy(
            //     "Private/localhost addresses not allowed in proxy".to_string()
            // ));
        }
    }
    
    // Check the port
    if let Some(port) = url.port() {
        // Disallow dangerous ports
        match port {
            80 | 443 | 8080 | 8443 => {}, // Common HTTP/HTTPS ports allowed
            _ if port > 1023 => {},       // Non-privileged ports allowed
            _ => return Err(BaffaoError::Proxy(format!(
                "Port {} not allowed for proxy destination", port
            ))),
        }
    }
    
    Ok(())
}

/// Determines the destination for a proxy request based on the path
fn determine_destination<S, T>(
    state: &Arc<BffState<S, T>>,
    path: &str,
) -> BaffaoResult<ProxyDestination>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // API path prefix
    const API_PATH_PREFIX: &str = "/api/";
    
    // Check if this is an API request
    if path.starts_with(API_PATH_PREFIX) {
        // Extract the API name from the path
        let api_path = &path[API_PATH_PREFIX.len()..];
        let api_name = api_path.split('/').next().unwrap_or("");
        
        // Try to find the destination in the allowed destinations
        for dest in &state.config.allowed_proxy_destinations {
            if dest.ends_with(&format!("/{}", api_name)) {
                // Define default allowed methods for common API patterns
                let allowed_methods = if path.contains("/admin/") || path.contains("/private/") {
                    // Restrict admin paths to safer methods
                    let mut methods = HashSet::new();
                    methods.insert(Method::GET);
                    methods.insert(Method::POST);
                    Some(methods)
                } else {
                    // Allow common methods for regular APIs
                    let mut methods = HashSet::new();
                    methods.insert(Method::GET);
                    methods.insert(Method::POST);
                    methods.insert(Method::PUT);
                    methods.insert(Method::DELETE);
                    methods.insert(Method::PATCH);
                    Some(methods)
                };
                
                // Define required scopes based on path patterns
                let required_scopes = if path.contains("/admin/") {
                    // Admin paths require admin scope
                    Some(vec!["admin".to_string()])
                } else if path.contains("/users/") || path.contains("/user/") {
                    // User paths require user scope
                    Some(vec!["user".to_string()])
                } else {
                    // No specific scopes required for general paths
                    None
                };
                
                return Ok(ProxyDestination {
                    url: dest.clone(),
                    strip_prefix: true,
                    allowed_methods,
                    required_scopes,
                });
            }
        }
    }
    
    // Check exact matches in allowed destinations
    for dest in &state.config.allowed_proxy_destinations {
        if path == dest {
            return Ok(ProxyDestination {
                url: dest.clone(),
                strip_prefix: false,
                allowed_methods: None, // Allow all methods for exact matches
                required_scopes: None, // No specific scopes required
            });
        }
    }
    
    Err(BaffaoError::Proxy(format!("No proxy destination found for path: {}", path)))
}

/// Builds the destination URL for a proxy request
fn build_destination_url(
    destination: &ProxyDestination,
    path: &str,
) -> BaffaoResult<String> {
    if destination.strip_prefix {
        // API path prefix
        const API_PATH_PREFIX: &str = "/api/";
        
        // Remove the API prefix and the API name
        let api_path = &path[API_PATH_PREFIX.len()..];
        let api_parts: Vec<&str> = api_path.splitn(2, '/').collect();
        
        if api_parts.len() > 1 {
            return Ok(format!("{}/{}", destination.url, api_parts[1]));
        } else {
            return Ok(destination.url.clone());
        }
    } else {
        Ok(destination.url.clone())
    }
}