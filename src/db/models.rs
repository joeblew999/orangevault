use serde::{Deserialize, Deserializer, Serialize};

/// D1/SQLite stores booleans as INTEGER 0/1, but serde_wasm_bindgen
/// receives them as f64. This deserializer handles bool, integer, and float.
fn de_bool_from_int<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrNum {
        Bool(bool),
        Float(f64),
        Int(i64),
    }
    match BoolOrNum::deserialize(deserializer)? {
        BoolOrNum::Bool(b) => Ok(b),
        BoolOrNum::Float(f) => Ok(f != 0.0),
        BoolOrNum::Int(i) => Ok(i != 0),
    }
}

/// Database representation of a user (matches `users` table in migration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub salt: String,
    pub password_iterations: u32,
    pub akey: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub security_stamp: String,
    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
    pub client_kdf_memory: Option<i32>,
    pub client_kdf_parallelism: Option<i32>,
    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    /// Stored as INTEGER 0/1 in SQLite. D1 returns this as a number.
    #[serde(deserialize_with = "de_bool_from_int")]
    pub email_verified: bool,
    pub totp_recover: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Database representation of a device (matches `devices` table in migration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub uuid: String,
    pub user_uuid: String,
    pub name: String,
    pub atype: i32,
    pub push_uuid: Option<String>,
    pub push_token: Option<String>,
    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
