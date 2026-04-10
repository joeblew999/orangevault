use serde::{Deserialize, Serialize};

use crate::db::models::{Cipher, Favorite, FolderCipher};

/// API response for a cipher.
#[derive(Debug, Serialize)]
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
    #[serde(rename = "Key")]
    pub key: Option<String>,
    pub revision_date: String,
    pub attachments: Option<Vec<serde_json::Value>>,
    pub password_history: Option<serde_json::Value>,
    pub collection_ids: Vec<String>,
    pub creation_date: String,
    pub deleted_date: Option<String>,
    pub object: String,
}

impl CipherResponse {
    /// Build a CipherResponse from a DB Cipher row, resolving favorite/folder from lists.
    pub fn from_cipher(
        c: &Cipher,
        user_uuid: &str,
        favorites: &[Favorite],
        folder_ciphers: &[FolderCipher],
    ) -> Self {
        let is_fav = favorites
            .iter()
            .any(|f| f.cipher_uuid == c.uuid && f.user_uuid == user_uuid);
        let folder_id = folder_ciphers
            .iter()
            .find(|fc| fc.cipher_uuid == c.uuid)
            .map(|fc| fc.folder_uuid.clone());
        Self::from_cipher_resolved(c, is_fav, folder_id)
    }

    /// Build a CipherResponse when favorite/folder status is already known.
    pub fn from_cipher_resolved(c: &Cipher, is_favorite: bool, folder_id: Option<String>) -> Self {
        let data: serde_json::Value =
            serde_json::from_str(&c.data).unwrap_or(serde_json::Value::Null);
        let (login, card, identity, secure_note) = match c.atype {
            1 => (Some(data), None, None, None),
            2 => (None, None, None, Some(serde_json::json!({"Type": 0}))),
            3 => (None, Some(data), None, None),
            4 => (None, None, Some(data), None),
            _ => (None, None, None, None),
        };

        CipherResponse {
            id: c.uuid.clone(),
            organization_id: c.organization_uuid.clone(),
            folder_id,
            r#type: c.atype,
            name: c.name.clone(),
            notes: c.notes.clone(),
            fields: c.fields.as_ref().and_then(|f| serde_json::from_str(f).ok()),
            login,
            card,
            identity,
            secure_note,
            favorite: is_favorite,
            reprompt: c.reprompt.unwrap_or(0),
            organization_use_totp: false,
            edit: true,
            view_password: true,
            key: c.key.clone(),
            revision_date: c.updated_at.clone(),
            attachments: None,
            password_history: c
                .password_history
                .as_ref()
                .and_then(|p| serde_json::from_str(p).ok()),
            collection_ids: vec![],
            creation_date: c.created_at.clone(),
            deleted_date: c.deleted_at.clone(),
            object: "cipherDetails".into(),
        }
    }
}

/// Cipher create/update request from client.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<serde_json::Value>,
    pub login: Option<serde_json::Value>,
    pub card: Option<serde_json::Value>,
    pub identity: Option<serde_json::Value>,
    pub secure_note: Option<serde_json::Value>,
    pub folder_id: Option<String>,
    pub favorite: Option<bool>,
    pub reprompt: Option<i32>,
    pub key: Option<String>,
    pub password_history: Option<serde_json::Value>,
    #[serde(default)]
    pub last_known_revision_date: Option<String>,
}

impl CipherRequest {
    /// Extract the type-specific data blob to store in the `data` column.
    pub fn data_json(&self) -> String {
        let val = match self.r#type {
            1 => self.login.as_ref(),
            3 => self.card.as_ref(),
            4 => self.identity.as_ref(),
            _ => None,
        };
        val.map(|v| v.to_string()).unwrap_or_else(|| "{}".into())
    }
}
