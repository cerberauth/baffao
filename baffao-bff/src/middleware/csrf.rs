use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode},
};
use baffao_core::csrf::CsrfManager;
use tower::{Layer, Service};
use futures::future::BoxFuture;
use futures::FutureExt;

/// CSRF protection middleware
#[derive(Clone)]
pub struct CsrfProtection {
    csrf_manager: Arc<CsrfManager>,
}

impl CsrfProtection {
    /// Creates a new CSRF protection middleware
    pub fn new(csrf_manager: Arc<CsrfManager>) -> Self {
        Self { csrf_manager }
    }
}

impl<S> Layer<S> for CsrfProtection {
    type Service = CsrfProtectionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfProtectionMiddleware {
            inner,
            csrf_manager: self.csrf_manager.clone(),
        }
    }
}

/// CSRF protection middleware
#[derive(Clone)]
pub struct CsrfProtectionMiddleware<S> {
    inner: S,
    csrf_manager: Arc<CsrfManager>,
}

impl<S> Service<Request<Body>> for CsrfProtectionMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Skip CSRF check for safe methods (GET, HEAD, OPTIONS)
        let method = req.method().clone();
        if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
            return self.inner.call(req).boxed();
        }

        // Get the CSRF manager
        let csrf_manager = self.csrf_manager.clone();

        // Check for the CSRF token in the headers
        let headers = req.headers().clone();
        
        // Create a clone of the service
        let mut inner = self.inner.clone();

        async move {
            // Check for CSRF token in both standard and custom header locations
            let headers_to_check = ["X-CSRF-Token", "csrf-token", "x-csrf"];
            let mut token_found = false;
            
            for header_name in headers_to_check {
                if let Some(token_header) = headers.get(header_name) {
                    if let Ok(token) = token_header.to_str() {
                        match csrf_manager.validate_stored_token(token, None).await {
                            Ok(_) => {
                                token_found = true;
                                break;
                            }
                            Err(_) => continue, // Try the next header
                        }
                    }
                }
            }
            
            // If no valid CSRF token found, reject the request
            if !token_found {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"error":"CSRF token missing or invalid"}"#))
                    .unwrap());
            }

            // Call the inner service
            inner.call(req).await
        }.boxed()
    }
}