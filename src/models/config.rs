use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub version: String,
    pub git_hash: String,
    pub server: ServerInfo,
    pub environment: EnvironmentUrls,
    pub feature_states: serde_json::Value,
    pub object: String,
}

#[derive(Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct EnvironmentUrls {
    pub api: String,
    pub identity: String,
    pub notifications: String,
    pub sso: String,
}
