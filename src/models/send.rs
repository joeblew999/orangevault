use serde::{Deserialize, Serialize};

/// API response for a Send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendResponse {
    pub id: String,
    pub access_id: String,
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub file: Option<serde_json::Value>,
    pub text: Option<serde_json::Value>,
    pub key: String,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub password: Option<String>,
    pub disabled: bool,
    pub revision_date: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub hide_email: bool,
    pub object: String,
}
