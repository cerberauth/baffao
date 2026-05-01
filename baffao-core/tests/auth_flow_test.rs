//! Integration test for OAuth authorization flow.

use std::time::Duration;

use baffao_core::auth::{OAuthClient, OAuthClientConfig};
use baffao_core::dpop::{DPoPKeyPair, DPoPVerifier};
use baffao_core::dpop::extensions::DPoPClientExt;
use baffao_core::error::{BaffaoError, BaffaoResult};
use baffao_core::pkce::{CodeChallenge, CodeChallengeMethod, PkceStore};
use oauth2::{AuthUrl, TokenUrl};
use tokio::sync::Mutex;
use oauth2::basic::BasicTokenResponse;

use std::sync::Arc;

// Mock OAuth server for testing
struct MockOAuthServer {
    authorization_code: String,
    access_token: String,
    refresh_token: String,
    dpop_verifier: DPoPVerifier,
    pkce_store: PkceStore,
}

impl MockOAuthServer {
    fn new() -> Self {
        Self {
            authorization_code: "mock_auth_code".to_string(),
            access_token: "mock_access_token".to_string(),
            refresh_token: "mock_refresh_token".to_string(),
            dpop_verifier: DPoPVerifier::new(),
            pkce_store: PkceStore::new(),
        }
    }
    
    async fn handle_authorization_request(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
        code_challenge_method: &str,
    ) -> BaffaoResult<String> {
        // Validate client ID (in a real server, this would check against a database)
        if client_id != "test_client" {
            return Err(BaffaoError::OAuth("Invalid client ID".to_string()));
        }
        
        // Validate redirect URI
        if redirect_uri != "https://client.example.com/callback" {
            return Err(BaffaoError::OAuth("Invalid redirect URI".to_string()));
        }
        
        // Store the PKCE challenge
        let method = match code_challenge_method {
            "S256" => CodeChallengeMethod::S256,
            "plain" => CodeChallengeMethod::Plain,
            _ => return Err(BaffaoError::OAuth("Invalid code_challenge_method".to_string())),
        };
        
        // In a real server, we would generate a new code challenge and store it
        // For the mock, we'll create one with the provided challenge
        let challenge = CodeChallenge {
            verifier: "placeholder".to_string(), // Will be verified through our mock
            challenge: code_challenge.to_string(),
            method,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.pkce_store.store_challenge(state, challenge).await?;
        
        // Return a redirect URI with the authorization code
        Ok(format!(
            "{}?code={}&state={}",
            redirect_uri, self.authorization_code, state
        ))
    }
    
    async fn handle_token_request(
        &self,
        grant_type: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: Option<&str>,
        refresh_token: Option<&str>,
        dpop_proof: Option<&str>,
    ) -> BaffaoResult<BasicTokenResponse> {
        // Validate request based on grant type
        match grant_type {
            "authorization_code" => {
                // Validate code
                if code != self.authorization_code {
                    return Err(BaffaoError::OAuth("Invalid authorization code".to_string()));
                }
                
                // Validate client ID
                if client_id != "test_client" {
                    return Err(BaffaoError::OAuth("Invalid client ID".to_string()));
                }
                
                // Validate redirect URI
                if redirect_uri != "https://client.example.com/callback" {
                    return Err(BaffaoError::OAuth("Invalid redirect URI".to_string()));
                }
                
                // Validate code verifier (PKCE)
                if let Some(verifier) = code_verifier {
                    // In a real server, we'd verify the code_verifier against the stored challenge
                    // For the mock, we'll simulate successful verification for a specific value
                    if verifier != "test_code_verifier" {
                        return Err(BaffaoError::PkceVerificationError("Invalid code verifier".to_string()));
                    }
                } else {
                    return Err(BaffaoError::OAuth("Missing code verifier".to_string()));
                }
            }
            "refresh_token" => {
                // Validate refresh token
                if let Some(token) = refresh_token {
                    if token != self.refresh_token {
                        return Err(BaffaoError::OAuth("Invalid refresh token".to_string()));
                    }
                } else {
                    return Err(BaffaoError::OAuth("Missing refresh token".to_string()));
                }
            }
            _ => return Err(BaffaoError::OAuth("Invalid grant type".to_string())),
        }
        
        // Validate DPoP proof if provided
        if let Some(proof) = dpop_proof {
            // In a real server, we'd validate the DPoP proof
            // For the mock, we'll simulate a basic check
            self.dpop_verifier.verify_without_nonce(
                proof, 
                "POST", 
                "https://auth.example.com/token"
            )?;
        }
        
        // Create a token response
        let mut token_response = oauth2::basic::BasicTokenResponse::new(
            oauth2::AccessToken::new(self.access_token.clone()),
            oauth2::StandardTokenType::Bearer,
            Some(Duration::from_secs(3600)),
        );
        
        // Add refresh token
        token_response = token_response.set_refresh_token(Some(oauth2::RefreshToken::new(
            self.refresh_token.clone(),
        )));
        
        // Add scopes
        let scopes = vec![
            oauth2::Scope::new("read".to_string()),
            oauth2::Scope::new("write".to_string()),
        ];
        token_response = token_response.set_scopes(Some(scopes));
        
        Ok(token_response)
    }
}

// Create a mock OAuth client for testing
async fn create_test_oauth_client() -> (OAuthClient, Arc<Mutex<MockOAuthServer>>) {
    let config = OAuthClientConfig {
        client_id: "test_client".to_string(),
        client_secret: Some("test_secret".to_string()),
        auth_url: AuthUrl::new("https://auth.example.com/authorize".to_string()).unwrap(),
        token_url: TokenUrl::new("https://auth.example.com/token".to_string()).unwrap(),
        redirect_url: "https://client.example.com/callback".to_string(),
        default_scopes: Some(vec![
            "read".to_string(),
            "write".to_string(),
        ]),
        state_expiry: Some(Duration::from_secs(600)),
        issuer: None,
    };
    
    let oauth_client = OAuthClient::new(config).unwrap();
    let mock_server = Arc::new(Mutex::new(MockOAuthServer::new()));
    
    (oauth_client, mock_server)
}

#[tokio::test]
async fn test_authorization_flow_with_pkce_and_dpop() -> BaffaoResult<()> {
    // Create a test OAuth client and mock server
    let (oauth_client, mock_server) = create_test_oauth_client().await;
    
    // Generate a state value
    let state = "test_state";
    
    // Create a PKCE challenge
    let code_challenge = CodeChallenge::new(CodeChallengeMethod::S256);
    
    // Generate the authorization URL
    let (auth_url, _csrf_token) = oauth_client.build_authorization_url(
        Some(state.to_string()),
        Some(code_challenge.challenge.clone()),
        Some(code_challenge.method.as_str().to_string()),
    )?;
    
    // Parse the authorization URL
    let auth_url_str = auth_url.to_string();
    let url = url::Url::parse(&auth_url_str).unwrap();
    let query_params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    
    // Mock the authorization request
    let server = mock_server.lock().await;
    let redirect_url = server
        .handle_authorization_request(
            &query_params["client_id"],
            &query_params["redirect_uri"],
            &query_params["state"],
            &query_params["code_challenge"],
            &query_params["code_challenge_method"],
        )
        .await?;
    drop(server);
    
    // Parse the redirect URL to get the authorization code
    let redirect_url = url::Url::parse(&redirect_url).unwrap();
    let query_params: std::collections::HashMap<_, _> = redirect_url.query_pairs().into_owned().collect();
    let code = query_params["code"].clone();
    let response_state = query_params["state"].clone();
    
    // Verify the state
    assert_eq!(response_state, state, "State parameter should match");
    
    // Generate a DPoP key pair
    let dpop_key_pair = DPoPKeyPair::new_p256()?;
    
    // Exchange the authorization code for tokens using DPoP
    let token_response = oauth_client
        .exchange_code_with_dpop(code, "test_code_verifier".to_string(), &dpop_key_pair)
        .await?;
    
    // Verify the token response
    assert_eq!(
        token_response.access_token().secret(),
        "mock_access_token",
        "Access token should match"
    );
    assert!(token_response.refresh_token().is_some(), "Refresh token should be present");
    assert_eq!(
        token_response.refresh_token().unwrap().secret(),
        "mock_refresh_token",
        "Refresh token should match"
    );
    
    // Refresh the token using DPoP
    let refresh_token_str = token_response.refresh_token().unwrap().secret();
    let refreshed_token_response = oauth_client
        .refresh_token_with_dpop(refresh_token_str, &dpop_key_pair)
        .await?;
    
    // Verify the refreshed token response
    assert_eq!(
        refreshed_token_response.access_token().secret(),
        "mock_access_token",
        "Refreshed access token should match"
    );
    
    Ok(())
}