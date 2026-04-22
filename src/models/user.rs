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

/// Shared by the legacy `/register` endpoint (`key`/`keys`) and the newer
/// `/register/finish` endpoint (`userSymmetricKey`/`userAsymmetricKeys`);
/// both spellings are accepted via serde aliases.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    pub master_password_hash: String,
    #[allow(dead_code)]
    pub master_password_hint: Option<String>,
    #[serde(alias = "userSymmetricKey")]
    pub key: Option<String>,
    pub kdf: Option<i32>,
    pub kdf_iterations: Option<i32>,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    #[serde(alias = "userAsymmetricKeys")]
    pub keys: Option<KeysRequest>,
    /// Present only on requests to `/identity/accounts/register/finish`.
    pub email_verification_token: Option<String>,
}

/// Body of `/identity/accounts/register/send-verification-email`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerificationRequest {
    pub email: String,
    pub name: Option<String>,
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
    /// Set only when `user.private_key` is present; newer clients reject the
    /// login as "legacy encryption" when the account has no asymmetric keys.
    #[serde(rename = "AccountKeys")]
    pub account_keys: Option<AccountKeys>,
    #[serde(rename = "TwoFactorToken", skip_serializing_if = "Option::is_none")]
    pub two_factor_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserDecryptionOptions {
    #[serde(rename = "HasMasterPassword")]
    pub has_master_password: bool,
    #[serde(rename = "MasterPasswordUnlock")]
    pub master_password_unlock: Option<MasterPasswordUnlock>,
    #[serde(rename = "Object")]
    pub object: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MasterPasswordUnlock {
    #[serde(rename = "Kdf")]
    pub kdf: MasterPasswordUnlockKdf,
    /// Legacy name kept for older clients; duplicated into the "Wrapped"
    /// field below for the newer naming convention.
    #[serde(rename = "MasterKeyEncryptedUserKey")]
    pub master_key_encrypted_user_key: String,
    #[serde(rename = "MasterKeyWrappedUserKey")]
    pub master_key_wrapped_user_key: String,
    /// Bitwarden derives the master key with the email as the PBKDF2 salt.
    #[serde(rename = "Salt")]
    pub salt: String,
}

#[derive(Debug, Serialize)]
pub struct MasterPasswordUnlockKdf {
    #[serde(rename = "KdfType")]
    pub kdf_type: i32,
    #[serde(rename = "Iterations")]
    pub iterations: i32,
    #[serde(rename = "Memory")]
    pub memory: Option<i32>,
    #[serde(rename = "Parallelism")]
    pub parallelism: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct AccountKeys {
    #[serde(rename = "publicKeyEncryptionKeyPair")]
    pub public_key_encryption_key_pair: PublicKeyEncryptionKeyPair,
    #[serde(rename = "Object")]
    pub object: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyEncryptionKeyPair {
    #[serde(rename = "wrappedPrivateKey")]
    pub wrapped_private_key: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "Object")]
    pub object: &'static str,
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
