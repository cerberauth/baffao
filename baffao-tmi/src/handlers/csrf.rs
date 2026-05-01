use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};

use baffao_core::csrf::CsrfToken;
use baffao_core::error::BaffaoResult;
use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;

use crate::state::TmiState;

/// CSRF token response
#[derive(Serialize)]
pub struct CsrfTokenResponse {
    /// CSRF token
    pub token: String,
}

/// Generates a new CSRF token for the client
pub async fn generate_csrf_token<S, T>(
    State(state): State<Arc<TmiState<S, T>>>,
) -> Result<impl IntoResponse, StatusCode>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let token = state.csrf_manager.generate_token(None, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CsrfTokenResponse {
        token: token.token,
    }))
}