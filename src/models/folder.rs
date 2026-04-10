use serde::{Deserialize, Serialize};

/// API response for a folder.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FolderResponse {
    pub id: String,
    pub name: String,
    pub revision_date: String,
    pub object: String,
}

impl FolderResponse {
    pub fn from_db(f: &crate::db::models::Folder) -> Self {
        FolderResponse {
            id: f.uuid.clone(),
            name: f.name.clone(),
            revision_date: f.updated_at.clone(),
            object: "folder".into(),
        }
    }
}

/// Folder create/update request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderRequest {
    pub name: String,
}
