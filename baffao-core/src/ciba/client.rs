//! CIBA (Client Initiated Backchannel Authentication) client implementation.
//!
//! This module provides a client for initiating and polling for CIBA requests.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

use crate::ciba::models::{AuthenticationRequest, AuthenticationResponse, AuthStatus, TokenResponse};
use crate::ciba::error::{CibaError, CibaResult};
use base64::Engine;

/// Client for interacting with a CIBA-compliant authorization server.
pub struct CibaClient {
    client: Client,
    client_id: String,
    client_secret: Option<String>,
    backchannel_auth_endpoint: String,
    token_endpoint: String,
    default_interval: u64,
}

impl CibaClient {
    /// Create a new CIBA client.
    pub fn new(
        client_id: String,
        client_secret: Option<String>,
        backchannel_auth_endpoint: String,
        token_endpoint: String,
    ) -> Self {
        Self {
            client: Client::new(),
            client_id,
            client_secret,
            backchannel_auth_endpoint,
            token_endpoint,
            default_interval: 5,
        }
    }

    /// Initiate an authentication request.
    pub async fn initiate_auth(
        &self,
        login_hint: Option<String>,
        id_token_hint: Option<String>,
        binding_message: Option<String>,
        scope: Option<Vec<String>>,
        user_code: Option<String>,
        requested_expiry: Option<u32>,
    ) -> CibaResult<AuthenticationResponse> {
        let mut body = HashMap::new();
        body.insert("client_id".to_string(), self.client_id.clone());
        
        if let Some(hint) = login_hint {
            body.insert("login_hint".to_string(), hint);
        }
        
        if let Some(hint) = id_token_hint {
            body.insert("id_token_hint".to_string(), hint);
        }
        
        if let Some(msg) = binding_message {
            body.insert("binding_message".to_string(), msg);
        }
        
        if let Some(s) = scope {
            body.insert("scope".to_string(), s.join(" "));
        }
        
        if let Some(code) = user_code {
            body.insert("user_code".to_string(), code);
        }
        
        if let Some(expiry) = requested_expiry {
            body.insert("requested_expiry".to_string(), expiry.to_string());
        }
        
        let mut headers = header::HeaderMap::new();
        if let Some(secret) = &self.client_secret {
            let auth_value = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.client_id, secret));
            headers.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Basic {}", auth_value))
                    .map_err(|e| CibaError::ConfigurationError(e.to_string()))?,
            );
        }
        
        let response = self.client.post(&self.backchannel_auth_endpoint)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| CibaError::NetworkError(e.to_string()))?;
            
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .map_err(|e| CibaError::NetworkError(format!("Failed to read error response: {}", e)))?;
                
            return Err(CibaError::AuthorizationFailed(format!(
                "Authorization server returned error: {} - {}", 
                status, 
                error_text
            )));
        }
        
        let auth_response = response.json::<AuthenticationResponse>().await
            .map_err(|e| CibaError::AuthorizationFailed(format!("Failed to parse response: {}", e)))?;
            
        Ok(auth_response)
    }
    
    pub async fn poll_and_get_tokens(&self, auth_req_id: &str, max_attempts: Option<u32>) -> CibaResult<TokenResponse> {
        let max_attempts = max_attempts.unwrap_or(60);
        let mut attempts = 0;
        
        while attempts < max_attempts {
            tokio::time::sleep(Duration::from_secs(self.default_interval)).await;
            
            let mut body = HashMap::new();
            body.insert("grant_type".to_string(), "urn:ietf:params:oauth:grant-type:ciba".to_string());
            body.insert("auth_req_id".to_string(), auth_req_id.to_string());
            
            let mut headers = header::HeaderMap::new();
            if let Some(secret) = &self.client_secret {
                let auth_value = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.client_id, secret));
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!("Basic {}", auth_value))
                        .map_err(|e| CibaError::ConfigurationError(e.to_string()))?,
                );
            }
            
            let response = self.client.post(&self.token_endpoint)
                .headers(headers)
                .form(&body)
                .send()
                .await
                .map_err(|e| CibaError::NetworkError(e.to_string()))?;
                
            if response.status().is_success() {
                let token_response = response.json::<TokenResponse>().await
                    .map_err(|e| CibaError::TokenRequestFailed(format!("Failed to parse token response: {}", e)))?;
                
                return Ok(token_response);
            } else {
                let status = response.status();
                let error_body = response.json::<serde_json::Value>().await
                    .map_err(|e| CibaError::NetworkError(format!("Failed to read error response: {}", e)))?;
                
                if let Some(error) = error_body.get("error").and_then(|e| e.as_str()) {
                    match error {
                        "authorization_pending" => {
                            attempts += 1;
                            continue;
                        },
                        "slow_down" => {
                            tokio::time::sleep(Duration::from_secs(self.default_interval * 2)).await;
                            attempts += 1;
                            continue;
                        },
                        "expired_token" => {
                            return Err(CibaError::ExpiredRequest("Authentication request has expired".to_string()));
                        },
                        "access_denied" => {
                            return Err(CibaError::UserCancelled("User denied the authentication request".to_string()));
                        },
                        _ => {
                            return Err(CibaError::TokenRequestFailed(format!("Token request failed: {}", error)));
                        }
                    }
                } else {
                    return Err(CibaError::TokenRequestFailed(format!(
                        "Token request failed: {} - {:?}", 
                        status,
                        error_body
                    )));
                }
            }
        }
        
        Err(CibaError::ExpiredRequest("Maximum polling attempts reached".to_string()))
    }
}
