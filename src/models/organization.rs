use serde::{Deserialize, Serialize};

use crate::db::models::{Collection, Membership, Organization};

/// API response for an organization.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub billing_email: String,
    pub plan_type: i32,
    pub seats: Option<i32>,
    pub max_collections: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub use_policies: bool,
    pub use_sso: bool,
    pub use_groups: bool,
    pub use_directory: bool,
    pub use_events: bool,
    pub use_totp: bool,
    pub self_host: bool,
    pub has_public_and_private_keys: bool,
    pub use_reset_password: bool,
    pub use_password_manager: bool,
    pub use_secrets_manager: bool,
    pub users_get_premium: bool,
    pub use_custom_permissions: bool,
    pub allow_admin_access_to_all_collection_items: bool,
    pub limit_collection_creation: bool,
    pub limit_collection_deletion: bool,
    pub object: String,
}

impl OrganizationResponse {
    pub fn from_db(org: &Organization) -> Self {
        OrganizationResponse {
            id: org.uuid.clone(),
            name: org.name.clone(),
            billing_email: org.billing_email.clone(),
            plan_type: 6, // Enterprise (self-hosted)
            seats: None,
            max_collections: None,
            max_storage_gb: Some(32767),
            use_policies: true,
            use_sso: false,
            use_groups: false,
            use_directory: false,
            use_events: false,
            use_totp: true,
            self_host: true,
            has_public_and_private_keys: org.public_key.is_some() && org.private_key.is_some(),
            use_reset_password: false,
            use_password_manager: true,
            use_secrets_manager: false,
            users_get_premium: true,
            use_custom_permissions: false,
            allow_admin_access_to_all_collection_items: true,
            limit_collection_creation: false,
            limit_collection_deletion: false,
            object: "organization".into(),
        }
    }
}

/// Profile organization response (included in sync).
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileOrganizationResponse {
    pub id: String,
    pub name: String,
    pub use_policies: bool,
    pub use_sso: bool,
    pub use_groups: bool,
    pub use_directory: bool,
    pub use_events: bool,
    pub use_totp: bool,
    pub self_host: bool,
    pub seats: Option<i32>,
    pub max_collections: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub has_public_and_private_keys: bool,
    pub use_password_manager: bool,
    pub use_secrets_manager: bool,
    pub users_get_premium: bool,
    pub use_reset_password: bool,
    pub use_custom_permissions: bool,
    pub plan_type: i32,
    pub organization_user_id: String,
    pub user_id: String,
    pub key: Option<String>,
    pub status: i32,
    pub r#type: i32,
    pub enabled: bool,
    pub permissions: OrgPermissions,
    pub allow_admin_access_to_all_collection_items: bool,
    pub limit_collection_creation: bool,
    pub limit_collection_deletion: bool,
    pub product_tier_type: i32,
    pub object: String,
}

impl ProfileOrganizationResponse {
    pub fn from_membership(org: &Organization, m: &Membership) -> Self {
        let is_admin_or_owner = m.atype <= 1;
        ProfileOrganizationResponse {
            id: org.uuid.clone(),
            name: org.name.clone(),
            use_policies: true,
            use_sso: false,
            use_groups: false,
            use_directory: false,
            use_events: false,
            use_totp: true,
            self_host: true,
            seats: None,
            max_collections: None,
            max_storage_gb: Some(32767),
            has_public_and_private_keys: org.public_key.is_some() && org.private_key.is_some(),
            use_password_manager: true,
            use_secrets_manager: false,
            users_get_premium: true,
            use_reset_password: false,
            use_custom_permissions: false,
            plan_type: 6,
            organization_user_id: m.uuid.clone(),
            user_id: m.user_uuid.clone(),
            key: m.akey.clone(),
            status: m.status,
            r#type: m.atype,
            enabled: true,
            permissions: OrgPermissions {
                create_new_collections: is_admin_or_owner,
                edit_any_collection: is_admin_or_owner,
                delete_any_collection: is_admin_or_owner,
                manage_users: is_admin_or_owner,
                manage_groups: false,
                manage_policies: is_admin_or_owner,
                manage_sso: false,
                manage_reset_password: false,
                access_event_logs: false,
                access_import_export: is_admin_or_owner,
                access_reports: false,
                manage_scim: false,
            },
            allow_admin_access_to_all_collection_items: true,
            limit_collection_creation: false,
            limit_collection_deletion: false,
            product_tier_type: 3,
            object: "profileOrganization".into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgPermissions {
    pub create_new_collections: bool,
    pub edit_any_collection: bool,
    pub delete_any_collection: bool,
    pub manage_users: bool,
    pub manage_groups: bool,
    pub manage_policies: bool,
    pub manage_sso: bool,
    pub manage_reset_password: bool,
    pub access_event_logs: bool,
    pub access_import_export: bool,
    pub access_reports: bool,
    pub manage_scim: bool,
}

/// Request body for creating an organization.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgCreateRequest {
    pub name: String,
    pub billing_email: String,
    pub collection_name: Option<String>,
    pub key: String,
    pub keys: Option<OrgKeysRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeysRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
}

/// Collection API response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub object: String,
}

impl CollectionResponse {
    pub fn from_db(c: &Collection) -> Self {
        CollectionResponse {
            id: c.uuid.clone(),
            organization_id: c.org_uuid.clone(),
            name: c.name.clone(),
            external_id: c.external_id.clone(),
            object: "collection".into(),
        }
    }
}

/// Sync-specific collection details response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionDetailsResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    pub object: String,
}

/// Request body for creating a collection.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionCreateRequest {
    pub name: String,
    pub external_id: Option<String>,
}

/// Request body for sharing a cipher to an organization.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareCipherRequest {
    pub cipher: crate::models::cipher::CipherRequest,
    pub collection_ids: Vec<String>,
}

/// Member response for listing org users.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MemberResponse {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub r#type: i32,
    pub status: i32,
    pub access_all: bool,
    pub object: String,
}
