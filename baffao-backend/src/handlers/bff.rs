use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Response},
};

use baffao_core::error::BaffaoResult;
use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;

use crate::config::BackendType;
use crate::proxy::proxy_request;
use crate::state::BackendState;
use crate::handlers::auth::BaffaoErrorResponse;

/// Handles API proxy requests (BFF mode only)
pub async fn proxy<S, T>(
    State(state): State<Arc<BackendState<S, T>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, BaffaoErrorResponse>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    if state.config.backend_type != BackendType::BFF {
        return Err(BaffaoErrorResponse(
            baffao_core::error::BaffaoError::Configuration(
                "Proxy endpoint is only available in BFF mode".to_string()
            )
        ));
    }

    let cookie_header = headers.get(http::header::COOKIE);
    let cookie_value = cookie_header.map(|h| h.to_str().unwrap_or_default());
    
    let session_id = match baffao_core::utils::extract_session_id_from_cookie(
        cookie_value, 
        &state.cookie_config.name
    ) {
        Some(id) => state.session_manager.session_id_from_cookie(&id)?,
        None => return Err(BaffaoErrorResponse(
            baffao_core::error::BaffaoError::Unauthorized
        )),
    };
    
    let session = match state.session_manager.get_session(&session_id).await? {
        Some(session) => session,
        None => return Err(BaffaoErrorResponse(
            baffao_core::error::BaffaoError::Unauthorized
        )),
    };
    
    if session.is_expired() {
        return Err(BaffaoErrorResponse(
            baffao_core::error::BaffaoError::SessionExpired
        ));
    }
    
    let access_token = match state.token_manager.get_access_token(&session.user_id).await? {
        Some(token) => {
            if token.is_expired() {
                let refresh_token = match state.token_manager.get_refresh_token(&session.user_id).await? {
                    Some(token) => token,
                    None => return Err(BaffaoErrorResponse(
                        baffao_core::error::BaffaoError::Unauthorized
                    )),
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
        None => return Err(BaffaoErrorResponse(
            baffao_core::error::BaffaoError::Unauthorized
        )),
    };
    
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