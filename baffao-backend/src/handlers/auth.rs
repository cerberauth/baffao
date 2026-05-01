use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use baffao_core::error::{BaffaoError, BaffaoResult};
use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;
use baffao_core::utils;

use crate::config::BackendType;
use crate::state::BackendState;

/// Session status response
#[derive(Serialize)]
pub struct SessionStatus {
    /// Whether the user is authenticated
    pub authenticated: bool,
    /// User ID if authenticated
    pub user_id: Option<String>,
    /// Session data if authenticated
    pub session_data: Option<serde_json::Value>,
    /// Access token (only for TMI mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Token expiration time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// Authorization query parameters
#[derive(Deserialize)]
pub struct AuthorizationParams {
    /// Authorization code
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
}

/// Token request parameters
#[derive(Deserialize)]
pub struct TokenRequest {
    /// Requested scopes
    pub scopes: Option<Vec<String>>,
}

/// Handles the check session endpoint
pub async fn check_session<S, T>(
    State(state): State<Arc<BackendState<S, T>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
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
            access_token: None,
            expires_in: None,
        })),
    };
    
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Ok(Json(SessionStatus {
            authenticated: false,
            user_id: None,
            session_data: None,
            access_token: None,
            expires_in: None,
        })),
    };
    
    if session.is_expired() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            user_id: None,
            session_data: None,
            access_token: None,
            expires_in: None,
        }));
    }
    
    if state.config.backend_type == BackendType::TMI {
        let access_token = match state.token_manager.get_access_token(&session.user_id).await? {
            Some(token) => {
                if token.is_expired() {
                    let refresh_token = match state.token_manager.get_refresh_token(&session.user_id).await? {
                        Some(token) => token,
                        None => return Ok(Json(SessionStatus {
                            authenticated: true,
                            user_id: Some(session.user_id.clone()),
                            session_data: session.data.clone(),
                            access_token: None,
                            expires_in: None,
                        })),
                    };
                    
                    let auth_response = state.oauth_client
                        .refresh_token(&refresh_token.token)
                        .await?;
                    
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
            None => return Ok(Json(SessionStatus {
                authenticated: true,
                user_id: Some(session.user_id.clone()),
                session_data: session.data.clone(),
                access_token: None,
                expires_in: None,
            })),
        };
        
        let expires_in = access_token.time_until_expiry().map(|d| d.as_secs());
        
        Ok(Json(SessionStatus {
            authenticated: true,
            user_id: Some(session.user_id.clone()),
            session_data: session.data.clone(),
            access_token: Some(access_token.token),
            expires_in,
        }))
    } else {
        Ok(Json(SessionStatus {
            authenticated: true,
            user_id: Some(session.user_id.clone()),
            session_data: session.data.clone(),
            access_token: None,
            expires_in: None,
        }))
    }
}

/// Handles the login endpoint
pub async fn login<S, T>(
    State(state): State<Arc<BackendState<S, T>>>,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let flow = state.oauth_client
        .start_authorization_flow(None, None)
        .await?;
    
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
    
    state.session_manager.update_session(&session).await?;
    
    let cookie = state.session_manager.create_cookie(&session, &state.cookie_config);
    
    let mut response = Redirect::to(flow.auth_url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    Ok(response)
}

/// Handles the authorization callback
pub async fn callback<S, T>(
    State(state): State<Arc<BackendState<S, T>>>,
    Query(params): Query<AuthorizationParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Err(BaffaoErrorResponse(BaffaoError::InvalidSession)),
    };
    
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Err(BaffaoErrorResponse(BaffaoError::InvalidSession)),
    };
    
    if session.is_expired() {
        return Err(BaffaoErrorResponse(BaffaoError::SessionExpired));
    }
    
    let session_data = session.data.as_ref()
        .ok_or_else(|| BaffaoError::InvalidSession)?;
    
    let auth_response = state.oauth_client
        .exchange_code(params.code, params.state)
        .await?;
    
    state.token_manager
        .store_access_token(&session.user_id, auth_response.access_token.clone())
        .await?;
    
    if let Some(refresh_token) = &auth_response.refresh_token {
        state.token_manager
            .store_refresh_token(&session.user_id, refresh_token.clone())
            .await?;
    }
    
    let data = serde_json::json!({
        "authenticated": true,
        "login_time": utils::current_timestamp(),
    });
    
    let mut updated_session = session.clone();
    updated_session.data = Some(data);
    
    state.session_manager.update_session(&updated_session).await?;
    
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
    State(state): State<Arc<BackendState<S, T>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Ok(StatusCode::OK.into_response()),
    };
    
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Ok(StatusCode::OK.into_response()),
    };
    
    state.token_manager.revoke_tokens(&session.user_id).await?;
    
    state.session_manager.delete_session(&session_id).await?;
    
    let mut cookie = state.session_manager.create_cookie(&session, &state.cookie_config);
    cookie.set_max_age(time::Duration::seconds(-1));
    
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    Ok(response)
}

/// Handles token requests (TMI mode only)
pub async fn get_token<S, T>(
    State(state): State<Arc<BackendState<S, T>>>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    if state.config.backend_type != BackendType::TMI {
        return Err(BaffaoErrorResponse(BaffaoError::Configuration(
            "Token endpoint is only available in TMI mode".to_string()
        )));
    }

    let cookie_header = headers.get(header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    if session.is_expired() {
        return Err(BaffaoErrorResponse(BaffaoError::SessionExpired));
    }
    
    let scopes = request.scopes.unwrap_or_else(Vec::new);
    
    if let Some(token) = state.token_manager.get_access_token_for_scope(&session.user_id, &scopes).await? {
        let expires_in = token.time_until_expiry().map(|d| d.as_secs());
        
        return Ok(Json(serde_json::json!({
            "access_token": token.token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": token.scopes
        })));
    }
    
    let refresh_token = match state.token_manager.get_refresh_token(&session.user_id).await? {
        Some(token) => token,
        None => return Err(BaffaoErrorResponse(BaffaoError::Unauthorized)),
    };
    
    let auth_response = state.oauth_client
        .refresh_token(&refresh_token.token)
        .await?;
    
    state.token_manager
        .store_access_token(&session.user_id, auth_response.access_token.clone())
        .await?;
    
    if let Some(refresh_token) = &auth_response.refresh_token {
        state.token_manager
            .store_refresh_token(&session.user_id, refresh_token.clone())
            .await?;
    }
    
    let expires_in = auth_response.access_token.time_until_expiry().map(|d| d.as_secs());
    
    Ok(Json(serde_json::json!({
        "access_token": auth_response.access_token.token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": auth_response.access_token.scopes
    })))
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