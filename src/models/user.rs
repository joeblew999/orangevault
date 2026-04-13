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

/// Prelogin request.
#[derive(Debug, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
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

/// Registration request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    pub master_password_hash: String,
    #[allow(dead_code)]
    pub master_password_hint: Option<String>,
    pub key: Option<String>,
    pub kdf: Option<i32>,
    pub kdf_iterations: Option<i32>,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    pub keys: Option<KeysRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeysRequest {
    pub public_key: String,
    pub encrypted_private_key: String,
}

/// Token request (form-urlencoded from /identity/connect/token).
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[allow(dead_code)]
    pub scope: Option<String>,
    #[allow(dead_code)]
    pub client_id: Option<String>,
    #[serde(rename = "deviceType")]
    pub device_type: Option<i32>,
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: Option<String>,
    #[serde(rename = "deviceName")]
    pub device_name: Option<String>,
    pub refresh_token: Option<String>,
    #[serde(rename = "twoFactorToken")]
    pub two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    pub two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    pub two_factor_remember: Option<i32>,
}

/// Login/refresh token response.
/// OAuth fields use snake_case, Bitwarden fields use PascalCase.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub refresh_token: String,
    #[serde(rename = "Key")]
    pub key: Option<String>,
    #[serde(rename = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(rename = "Kdf")]
    pub kdf: i32,
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: i32,
    #[serde(rename = "KdfMemory", skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "KdfParallelism", skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<i32>,
    #[serde(rename = "unofficialServer")]
    pub unofficial_server: bool,
    #[serde(rename = "UserDecryptionOptions")]
    pub user_decryption_options: UserDecryptionOptions,
    #[serde(rename = "TwoFactorToken", skip_serializing_if = "Option::is_none")]
    pub two_factor_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserDecryptionOptions {
    #[serde(rename = "HasMasterPassword")]
    pub has_master_password: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    #[allow(dead_code)]
    pub master_password_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    #[allow(dead_code)]
    pub master_password_hint: Option<String>,
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub key: String,
    pub kdf: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKeysRequest {
    pub master_password_hash: String,
    pub key: String,
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPasswordRequest {
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStampRequest {
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRequest {
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountRequest {
    pub master_password_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApiKeyResponse {
    pub api_key: String,
    pub object: String,
}
