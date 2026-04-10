use serde::{Deserialize, Serialize};

/// Database representation of a user (matches `users` table in migration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
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
