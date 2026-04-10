use serde::Serialize;

use super::cipher::CipherResponse;
use super::folder::FolderResponse;
use super::user::ProfileResponse;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncResponse {
    pub profile: ProfileResponse,
    pub ciphers: Vec<CipherResponse>,
    pub folders: Vec<FolderResponse>,
    pub collections: Vec<serde_json::Value>,
    pub policies: Vec<serde_json::Value>,
    pub sends: Vec<serde_json::Value>,
    pub domains: DomainsResponse,
    pub object: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DomainsResponse {
    pub equivalent_domains: Vec<serde_json::Value>,
    pub global_equivalent_domains: Vec<GlobalDomain>,
    pub object: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GlobalDomain {
    pub r#type: i32,
    pub domains: Vec<String>,
    pub excluded: bool,
}
