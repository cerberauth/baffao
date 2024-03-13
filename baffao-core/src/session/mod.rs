use anyhow::Error;
pub use extract_session::extract_session;
pub use update_session::update_session;

mod extract_session;
mod update_session;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    id: String,
    iat: DateTime<Utc>,
    exp: Option<DateTime<Utc>>,
}

impl Session {
    pub fn new(id: Option<String>, iat: Option<DateTime<Utc>>, exp: Option<DateTime<Utc>>) -> Self {
        Self {
            id: id.unwrap_or_else(generate_session_id),
            iat: iat.unwrap_or_else(Utc::now),
            exp,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }

    pub fn expire(&self) -> Option<DateTime<Utc>> {
        self.exp
    }

    pub fn is_expired(&self) -> bool {
        match self.exp {
            Some(exp) => exp < Utc::now(),
            None => false,
        }
    }

    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn decode(encoded: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(encoded)
    }

    pub fn encode_cookie(&self) -> String {
        STANDARD.encode(self.encode().as_bytes())
    }

    pub fn decode_cookie(encoded: String) -> Result<Self, Error> {
        let decoded_cookie = STANDARD.decode(encoded)?;
        let session_str = String::from_utf8(decoded_cookie)?;

        let decoded = Self::decode(&session_str)?;
        Ok(decoded)
    }
}

pub fn generate_session_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut session_id = [0u8; 32];
    rng.fill(&mut session_id).unwrap();

    // Convert the session_id byte array to a hex string
    hex::encode(session_id)
}
