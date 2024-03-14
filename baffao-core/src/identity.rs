use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub subject: String,
    pub name: String,
    pub email: String,
}
