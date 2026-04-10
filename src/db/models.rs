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

/// Database representation of a cipher (matches `ciphers` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub uuid: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub atype: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    #[serde(rename = "akey")]
    pub key: Option<String>,
    pub password_history: Option<String>,
    pub reprompt: Option<i32>,
    pub deleted_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Database representation of a folder (matches `folders` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub uuid: String,
    pub user_uuid: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Row from `favorites` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Favorite {
    pub user_uuid: String,
    pub cipher_uuid: String,
}

/// Row from `folders_ciphers` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderCipher {
    pub cipher_uuid: String,
    pub folder_uuid: String,
}

/// Database representation of an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

/// Database representation of an org membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,
    pub akey: Option<String>,
    pub atype: i32,
    pub status: i32,
    #[serde(deserialize_with = "de_bool_from_int", default)]
    pub access_all: bool,
    pub external_id: Option<String>,
    pub reset_password_key: Option<String>,
}

/// Database representation of a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
    pub external_id: Option<String>,
}

/// Row from `users_collections`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCollection {
    pub user_uuid: String,
    pub collection_uuid: String,
    #[serde(deserialize_with = "de_bool_from_int", default)]
    pub read_only: bool,
    #[serde(deserialize_with = "de_bool_from_int", default)]
    pub hide_passwords: bool,
    #[serde(deserialize_with = "de_bool_from_int", default)]
    pub manage: bool,
}

/// Row from `ciphers_collections`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherCollection {
    pub cipher_uuid: String,
    pub collection_uuid: String,
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
