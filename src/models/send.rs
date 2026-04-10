use serde::{Deserialize, Serialize};

use crate::db::models::Send as DbSend;
use crate::util::base64url_encode;

/// Send type constants.
pub const SEND_TYPE_TEXT: i32 = 0;
pub const SEND_TYPE_FILE: i32 = 1;

/// Parse send data JSON into (text, file) based on send type.
fn parse_send_data(
    atype: i32,
    data: &str,
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    match atype {
        SEND_TYPE_TEXT => {
            let text_val: Option<serde_json::Value> = serde_json::from_str(data).ok();
            (text_val, None)
        }
        SEND_TYPE_FILE => {
            let file_val: Option<serde_json::Value> = serde_json::from_str(data).ok();
            (None, file_val)
        }
        _ => (None, None),
    }
}

/// API response for a Send (authenticated owner view).
#[derive(Debug, Serialize)]
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
    pub hide_email: bool,
    pub revision_date: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub object: String,
}

impl SendResponse {
    pub fn from_db(s: &DbSend) -> Self {
        let access_id = base64url_encode(s.uuid.as_bytes());
        let (text, file) = parse_send_data(s.atype, &s.data);

        // Clients use presence/absence of this field to know if password-protected.
        // Clients use presence/absence of this field to know if password-protected.
        let password = s
            .password_hash
            .as_ref()
            .map(|h| base64url_encode(h.as_bytes()));

        SendResponse {
            id: s.uuid.clone(),
            access_id,
            r#type: s.atype,
            name: s.name.clone(),
            notes: s.notes.clone(),
            file,
            text,
            key: s.akey.clone(),
            max_access_count: s.max_access_count,
            access_count: s.access_count,
            password,
            disabled: s.disabled,
            hide_email: s.hide_email,
            revision_date: s.updated_at.clone(),
            expiration_date: s.expiration_date.clone(),
            deletion_date: s.deletion_date.clone(),
            object: "send".into(),
        }
    }
}

/// API response for anonymous send access.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendAccessResponse {
    pub id: String,
    pub r#type: i32,
    pub name: String,
    pub text: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub expiration_date: Option<String>,
    pub creator_identifier: Option<String>,
    pub object: String,
}

impl SendAccessResponse {
    pub fn from_db(s: &DbSend, creator_email: Option<&str>) -> Self {
        let (text, file) = parse_send_data(s.atype, &s.data);

        let creator_identifier = if s.hide_email {
            None
        } else {
            creator_email.map(|e| e.to_string())
        };

        SendAccessResponse {
            id: s.uuid.clone(),
            r#type: s.atype,
            name: s.name.clone(),
            text,
            file,
            expiration_date: s.expiration_date.clone(),
            creator_identifier,
            object: "send-access".into(),
        }
    }
}

/// File upload response for v2 file sends.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendFileUploadResponse {
    pub file_upload_type: i32,
    pub object: String,
    pub url: String,
    pub send_response: SendResponse,
}

/// File download response for anonymous file access.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendFileDownloadResponse {
    pub id: String,
    pub url: String,
    pub object: String,
}

/// Request body for creating/updating a send.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub r#type: i32,
    pub key: String,
    pub name: String,
    pub notes: Option<String>,
    pub text: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub file_length: Option<i64>,
    pub password: Option<String>,
    pub max_access_count: Option<i32>,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: Option<bool>,
    pub hide_email: Option<bool>,
}

/// Request body for anonymous send access.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessRequest {
    pub password: Option<String>,
}
