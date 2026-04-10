use serde::{Deserialize, Serialize};

/// API response for a cipher.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CipherResponse {
    pub id: String,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<serde_json::Value>,
    pub login: Option<serde_json::Value>,
    pub card: Option<serde_json::Value>,
    pub identity: Option<serde_json::Value>,
    pub secure_note: Option<serde_json::Value>,
    pub favorite: bool,
    pub reprompt: i32,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub view_password: bool,
    pub revision_date: String,
    pub attachments: Option<Vec<serde_json::Value>>,
    pub password_history: Option<Vec<serde_json::Value>>,
    pub collection_ids: Vec<String>,
    pub creation_date: String,
    pub deleted_date: Option<String>,
    pub object: String,
}
