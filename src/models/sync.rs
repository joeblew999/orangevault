use serde::Serialize;

use super::cipher::CipherResponse;
use super::folder::FolderResponse;
use super::organization::CollectionDetailsResponse;
use super::send::SendResponse;
use super::user::ProfileResponse;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncResponse {
    pub profile: ProfileResponse,
    pub ciphers: Vec<CipherResponse>,
    pub folders: Vec<FolderResponse>,
    pub collections: Vec<CollectionDetailsResponse>,
    pub policies: Vec<serde_json::Value>,
    pub sends: Vec<SendResponse>,
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

pub fn default_global_domains() -> Vec<GlobalDomain> {
    vec![
        GlobalDomain {
            r#type: 0,
            domains: ["google.com", "youtube.com", "gmail.com", "googlemail.com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 1,
            domains: ["apple.com", "icloud.com", "me.com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 2,
            domains: [
                "live.com",
                "microsoft.com",
                "microsoftonline.com",
                "outlook.com",
                "hotmail.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 3,
            domains: [
                "amazon.com",
                "amazon.co.uk",
                "amazon.ca",
                "amazon.de",
                "amazon.in",
                "amazon.co.jp",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            excluded: false,
        },
    ]
}
