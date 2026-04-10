use serde::{Deserialize, Serialize};

/// API response for an organization.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub use_policies: bool,
    pub use_sso: bool,
    pub use_groups: bool,
    pub use_directory: bool,
    pub use_events: bool,
    pub use_totp: bool,
    pub seats: Option<i32>,
    pub max_collections: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub self_host: bool,
    pub has_public_and_private_keys: bool,
    pub plan_product_type: i32,
    pub object: String,
}
