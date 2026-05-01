/*!
# Baffao WebAssembly Bindings

This crate provides WebAssembly bindings for Baffao, allowing you to use it in JavaScript
applications or edge workers.

## Features

- OAuth 2.0 flows for TMI pattern
- Token management for browser applications
- Utilities for secure token storage
*/

use wasm_bindgen::prelude::*;
use js_sys::{Array, Promise};
use web_sys::{Request, RequestInit, RequestMode, Response};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

mod token;
mod storage;
mod utils;

use token::TokenRequest;

/// The Baffao WASM client
#[wasm_bindgen]
pub struct BaffaoClient {
    base_url: String,
}

/// Options for creating a Baffao client
#[wasm_bindgen]
pub struct BaffaoOptions {
    base_url: String,
}

#[wasm_bindgen]
impl BaffaoOptions {
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: String) -> BaffaoOptions {
        BaffaoOptions { base_url }
    }

    #[wasm_bindgen(getter)]
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }
}

#[wasm_bindgen]
impl BaffaoClient {
    /// Creates a new Baffao client
    #[wasm_bindgen(constructor)]
    pub fn new(options: BaffaoOptions) -> BaffaoClient {
        console_error_panic_hook::set_once();
        
        BaffaoClient {
            base_url: options.base_url,
        }
    }
    
    /// Checks if the user is authenticated
    #[wasm_bindgen]
    pub fn check_session(&self) -> Promise {
        let base_url = self.base_url.clone();
        
        future_to_promise(async move {
            let url = format!("{}/auth/check", base_url);
            
            let mut opts = RequestInit::new();
            opts.method("GET");
            opts.mode(RequestMode::Cors);
            opts.credentials(web_sys::RequestCredentials::Include);
            
            let request = Request::new_with_str_and_init(&url, &opts)
                .map_err(|err| JsValue::from_str(&format!("Failed to create request: {:?}", err)))?;
                
            request.headers().set("Accept", "application/json")
                .map_err(|err| JsValue::from_str(&format!("Failed to set Accept header: {:?}", err)))?;
                
            let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
            
            let resp: Response = resp_value.dyn_into()
                .map_err(|_| JsValue::from_str("Failed to cast response"))?;
                
            if !resp.ok() {
                return Err(JsValue::from_str(&format!("Request failed with status: {}", resp.status())));
            }
            
            let json = JsFuture::from(resp.json()?)
                .await
                .map_err(|err| JsValue::from_str(&format!("Failed to parse JSON: {:?}", err)))?;
                
            Ok(json)
        })
    }
    
    /// Gets an access token with the specified scopes
    #[wasm_bindgen]
    pub fn get_token(&self, scopes: Option<Array>) -> Promise {
        let base_url = self.base_url.clone();
        
        let scopes_vec = if let Some(scopes_array) = scopes {
            let mut result = Vec::new();
            for i in 0..scopes_array.length() {
                if let Some(scope) = scopes_array.get(i).as_string() {
                    result.push(scope);
                }
            }
            Some(result)
        } else {
            None
        };
        
        future_to_promise(async move {
            let url = format!("{}/auth/token", base_url);
            
            let token_request = TokenRequest {
                scopes: scopes_vec,
            };
            
            let token_request_json = JsValue::from_str(&serde_json::to_string(&token_request)
                .map_err(|err| JsValue::from_str(&format!("Failed to serialize token request: {:?}", err)))?);
            
            let mut opts = RequestInit::new();
            opts.method("POST");
            opts.mode(RequestMode::Cors);
            opts.credentials(web_sys::RequestCredentials::Include);
            opts.body(Some(&token_request_json));
            
            let request = Request::new_with_str_and_init(&url, &opts)
                .map_err(|err| JsValue::from_str(&format!("Failed to create request: {:?}", err)))?;
                
            request.headers().set("Content-Type", "application/json")
                .map_err(|err| JsValue::from_str(&format!("Failed to set Content-Type header: {:?}", err)))?;
                
            request.headers().set("Accept", "application/json")
                .map_err(|err| JsValue::from_str(&format!("Failed to set Accept header: {:?}", err)))?;
                
            // Add CSRF token if available
            if let Some(csrf_token) = utils::get_csrf_token() {
                request.headers().set("X-CSRF-Token", &csrf_token)
                    .map_err(|err| JsValue::from_str(&format!("Failed to set CSRF header: {:?}", err)))?;
            }
                
            let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
            
            let resp: Response = resp_value.dyn_into()
                .map_err(|_| JsValue::from_str("Failed to cast response"))?;
                
            if !resp.ok() {
                return Err(JsValue::from_str(&format!("Request failed with status: {}", resp.status())));
            }
            
            let json = JsFuture::from(resp.json()?)
                .await
                .map_err(|err| JsValue::from_str(&format!("Failed to parse JSON: {:?}", err)))?;
                
            Ok(json)
        })
    }
    
    /// Redirects the user to the login page
    #[wasm_bindgen]
    pub fn login(&self) {
        let login_url = format!("{}/auth/login", self.base_url);
        
        if let Some(window) = web_sys::window() {
            let location = window.location();
            let _ = location.set_href(&login_url);
        }
    }
    
    /// Logs the user out
    #[wasm_bindgen]
    pub fn logout(&self) -> Promise {
        let base_url = self.base_url.clone();
        
        future_to_promise(async move {
            let url = format!("{}/auth/logout", base_url);
            
            let mut opts = RequestInit::new();
            opts.method("GET");
            opts.mode(RequestMode::Cors);
            opts.credentials(web_sys::RequestCredentials::Include);
            
            let request = Request::new_with_str_and_init(&url, &opts)
                .map_err(|err| JsValue::from_str(&format!("Failed to create request: {:?}", err)))?;
                
            let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
            
            let resp: Response = resp_value.dyn_into()
                .map_err(|_| JsValue::from_str("Failed to cast response"))?;
                
            if !resp.ok() {
                return Err(JsValue::from_str(&format!("Request failed with status: {}", resp.status())));
            }
            
            // Redirect to home page
            let location = window.location();
            let _ = location.set_href("/");
            
            Ok(JsValue::from_bool(true))
        })
    }
}

use wasm_bindgen_futures::JsFuture;
