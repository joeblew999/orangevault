use serde::{Deserialize, Serialize};

/// API response for user profile.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileResponse {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub premium: bool,
    pub master_password_hint: Option<String>,
    pub culture: String,
    pub two_factor_enabled: bool,
    pub key: String,
    pub private_key: Option<String>,
    pub security_stamp: String,
    pub organizations: Vec<serde_json::Value>,
    pub providers: Vec<serde_json::Value>,
    pub force_password_reset: bool,
    pub avatar_color: Option<String>,
    pub object: String,
}

/// Prelogin response (KDF parameters).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<i32>,
}
