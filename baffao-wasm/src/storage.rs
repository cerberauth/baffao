use wasm_bindgen::prelude::*;
use web_sys::{Storage, Window};

/// Gets the local storage
fn get_local_storage() -> Option<Storage> {
    web_sys::window()
        .and_then(|window| window.local_storage().ok())
        .flatten()
}

/// Gets the session storage
fn get_session_storage() -> Option<Storage> {
    web_sys::window()
        .and_then(|window| window.session_storage().ok())
        .flatten()
}

/// Stores a value in local storage
pub fn store_local(key: &str, value: &str) -> Result<(), JsValue> {
    if let Some(storage) = get_local_storage() {
        storage.set_item(key, value)
    } else {
        Err(JsValue::from_str("Local storage not available"))
    }
}

/// Gets a value from local storage
pub fn get_local(key: &str) -> Option<String> {
    get_local_storage()
        .and_then(|storage| storage.get_item(key).ok())
        .flatten()
}

/// Removes a value from local storage
pub fn remove_local(key: &str) -> Result<(), JsValue> {
    if let Some(storage) = get_local_storage() {
        storage.remove_item(key)
    } else {
        Err(JsValue::from_str("Local storage not available"))
    }
}

/// Stores a value in session storage
pub fn store_session(key: &str, value: &str) -> Result<(), JsValue> {
    if let Some(storage) = get_session_storage() {
        storage.set_item(key, value)
    } else {
        Err(JsValue::from_str("Session storage not available"))
    }
}

/// Gets a value from session storage
pub fn get_session(key: &str) -> Option<String> {
    get_session_storage()
        .and_then(|storage| storage.get_item(key).ok())
        .flatten()
}

/// Removes a value from session storage
pub fn remove_session(key: &str) -> Result<(), JsValue> {
    if let Some(storage) = get_session_storage() {
        storage.remove_item(key)
    } else {
        Err(JsValue::from_str("Session storage not available"))
    }
}
