use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use baffao_core::auth::AuthorizationFlow;
use baffao_core::error::{BaffaoError, BaffaoResult};
use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;
use baffao_core::utils;

use crate::proxy::proxy_request;
use crate::state::BffState;

/// Session status response
#[derive(Serialize)]
pub struct SessionStatus {
    /// Whether the user is authenticated
    pub authenticated: bool,
    /// User ID if authenticated
    pub user_id: Option<String>,
    /// Session data if authenticated
    pub session_data: Option<serde_json::Value>,
}

/// Authorization query parameters
#[derive(Deserialize)]
pub struct AuthorizationParams {
    /// Authorization code
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
}

/// Handles the check session endpoint
pub async fn check_session<S, T>(
    State(state): State<Arc<BffState<S, T>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Extract the session cookie
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Ok(Json(SessionStatus {
            authenticated: false,
            user_id: None,
            session_data: None,
        })),
    };
    
    // Get the session
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Ok(Json(SessionStatus {
            authenticated: false,
            user_id: None,
            session_data: None,
        })),
    };
    
    // Check if the session is valid
    if session.is_expired() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            user_id: None,
            session_data: None,
        }));
    }
    
    Ok(Json(SessionStatus {
        authenticated: true,
        user_id: Some(session.user_id.clone()),
        session_data: session.data.clone(),
    }))
}

/// Handles the login endpoint
pub async fn login<S, T>(
    State(state): State<Arc<BffState<S, T>>>,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Start the authorization flow
    let flow = state.oauth_client.start_authorization_flow(None)?;
    
    // Store the PKCE verifier and CSRF token in the session
    let session = state.session_manager.create_session(
        &utils::generate_secure_random_string(32),
        None,
    ).await?;
    
    let data = serde_json::json!({
        "pkce_verifier": flow.pkce_verifier,
        "csrf_token": flow.csrf_token,
        "flow_type": "authorization_code",
    });
    
    let mut session = session.with_data(data);
    
    // Update the session
    state.session_manager.update_session(&session).await?;
    
    // Set the session cookie
    let cookie = state.session_manager.create_cookie(&session, &state.cookie_config);
    
    // Redirect to the authorization server
    let mut response = Redirect::to(flow.auth_url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    Ok(response)
}

/// Handles the authorization callback
pub async fn callback<S, T>(
    State(state): State<Arc<BffState<S, T>>>,
    Query(params): Query<AuthorizationParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Extract the session cookie
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Err(BaffaoErrorResponse(BaffaoError::InvalidSession)),
    };
    
    // Get the session
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Err(BaffaoErrorResponse(BaffaoError::InvalidSession)),
    };
    
    // Check if the session is valid
    if session.is_expired() {
        return Err(BaffaoErrorResponse(BaffaoError::SessionExpired));
    }
    
    // Extract the PKCE verifier and CSRF token
    let session_data = session.data.as_ref()
        .ok_or_else(|| BaffaoError::InvalidSession)?;
    
    let pkce_verifier = session_data["pkce_verifier"].as_str()
        .ok_or_else(|| BaffaoError::InvalidSession)?;
    
    let csrf_token = session_data["csrf_token"].as_str()
        .ok_or_else(|| BaffaoError::InvalidSession)?;
    
    // Verify the CSRF token
    if params.state != csrf_token {
        return Err(BaffaoErrorResponse(BaffaoError::InvalidCsrfToken));
    }
    
    // Exchange the authorization code for tokens
    let auth_response = state.oauth_client
        .exchange_code(params.code, pkce_verifier.to_string())
        .await?;
    
    // Store the tokens
    state.token_manager
        .store_access_token(&session.user_id, auth_response.access_token.clone())
        .await?;
    
    if let Some(refresh_token) = &auth_response.refresh_token {
        state.token_manager
            .store_refresh_token(&session.user_id, refresh_token.clone())
            .await?;
    }
    
    // Update the session data
    let data = serde_json::json!({
        "authenticated": true,
        "login_time": utils::current_timestamp(),
    });
    
    let mut updated_session = session.clone();
    updated_session.data = Some(data);
    
    state.session_manager.update_session(&updated_session).await?;
    
    // Set the session cookie and redirect to the frontend
    let cookie = state.session_manager.create_cookie(&updated_session, &state.cookie_config);
    
    let redirect_to = state.config.base_path.clone() + "/";
    let mut response = Redirect::to(&redirect_to).into_response();
    
    response.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    Ok(response)
}

/// Handles the logout endpoint
pub async fn logout<S, T>(
    State(state): State<Arc<BffState<S, T>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Extract the session cookie
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Ok(StatusCode::OK),
    };
    
    // Get the session
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Ok(StatusCode::OK),
    };
    
    // Revoke the tokens
    state.token_manager.revoke_tokens(&session.user_id).await?;
    
    // Delete the session
    state.session_manager.delete_session(&session_id).await?;
    
    // Set an expired cookie to clear the session
    let mut cookie = state.session_manager.create_cookie(&session, &state.cookie_config);
    cookie.set_max_age(time::Duration::seconds(-1));
    
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    Ok(response)
}

/// Handles the API proxy
pub async fn proxy<S, T>(
    State(state): State<Arc<BffState<S, T>>>,
    headers: HeaderMap,
    method: http::Method,
    uri: http::Uri,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    // Extract the session cookie
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    // Get the session
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    // Check if the session is valid
    if session.is_expired() {
        return Err(BaffaoErrorResponse(BaffaoError::SessionExpired));
    }
    
    // Get the access token
    let access_token = match state.token_manager.get_access_token(&session.user_id).await? {
        Some(token) => {
            if token.is_expired() {
                // Try to refresh the token
                let refresh_token = match state.token_manager.get_refresh_token(&session.user_id).await? {
                    Some(token) => token,
                    None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
                };
                
                let auth_response = state.oauth_client
                    .refresh_token(&refresh_token.token)
                    .await?;
                
                // Store the new tokens
                state.token_manager
                    .store_access_token(&session.user_id, auth_response.access_token.clone())
                    .await?;
                
                if let Some(refresh_token) = &auth_response.refresh_token {
                    state.token_manager
                        .store_refresh_token(&session.user_id, refresh_token.clone())
                        .await?;
                }
                
                auth_response.access_token
            } else {
                token
            }
        },
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    // Proxy the request
    let response = proxy_request(
        &state,
        method,
        uri,
        headers,
        body,
        &access_token,
    ).await?;
    
    Ok(response)
}

/// Converts a BaffaoError into an HTTP response
pub struct BaffaoErrorResponse(pub BaffaoError);

impl IntoResponse for BaffaoErrorResponse {
    fn into_response(self) -> Response {
        let status = self.0.status_code();
        let message = self.0.to_string();
        
        let body = Json(serde_json::json!({
            "error": message,
        }));
        
        (status, body).into_response()
    }
}

impl<E> From<E> for BaffaoErrorResponse
where
    E: Into<BaffaoError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}