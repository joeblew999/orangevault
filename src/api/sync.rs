use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::queries;
use crate::error;
use crate::models::cipher::CipherResponse;
use crate::models::folder::FolderResponse;
use crate::models::organization::{CollectionDetailsResponse, ProfileOrganizationResponse};
use crate::models::send::SendResponse;
use crate::models::sync::{DomainsResponse, GlobalDomain, SyncResponse};
use crate::models::user::ProfileResponse;

pub async fn sync(req: Request, ctx: RouteContext<RequestContext>) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;

            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(crate::error::AppError::NotFound("User not found".into()))?;

            // Personal ciphers, folders, favorites, folder-cipher links
            let mut ciphers = queries::find_ciphers_by_user(&db, &user.uuid).await?;
            let folders = queries::find_folders_by_user(&db, &user.uuid).await?;
            let favorites = queries::find_favorites_by_user(&db, &user.uuid).await?;
            let folder_ciphers = queries::find_folder_ciphers_by_user(&db, &user.uuid).await?;

            let memberships = queries::find_memberships_by_user(&db, &user.uuid).await?;
            let confirmed: Vec<_> = memberships.iter().filter(|m| m.status == 2).collect();
            let user_collections = queries::find_user_collections_by_user(&db, &user.uuid).await?;

            let mut profile_orgs = Vec::new();
            let mut collections_resp = Vec::new();
            let mut all_cipher_collections = Vec::new();

            for m in &confirmed {
                if let Some(org) = queries::find_organization_by_uuid(&db, &m.org_uuid).await? {
                    profile_orgs.push(ProfileOrganizationResponse::from_membership(&org, m));

                    let org_ciphers = queries::find_org_ciphers(&db, &m.org_uuid).await?;
                    ciphers.extend(org_ciphers);

                    let org_cipher_collections =
                        queries::find_cipher_collections_by_org(&db, &m.org_uuid).await?;
                    all_cipher_collections.extend(org_cipher_collections);

                    let org_collections =
                        queries::find_collections_by_org(&db, &m.org_uuid).await?;

                    for col in &org_collections {
                        let uc = user_collections
                            .iter()
                            .find(|uc| uc.collection_uuid == col.uuid);
                        if m.access_all || uc.is_some() {
                            collections_resp.push(CollectionDetailsResponse {
                                id: col.uuid.clone(),
                                organization_id: col.org_uuid.clone(),
                                name: col.name.clone(),
                                external_id: col.external_id.clone(),
                                read_only: uc.map(|u| u.read_only).unwrap_or(false),
                                hide_passwords: uc.map(|u| u.hide_passwords).unwrap_or(false),
                                manage: uc.map(|u| u.manage).unwrap_or(m.access_all),
                                object: "collectionDetails".into(),
                            });
                        }
                    }
                }
            }

            let profile_orgs_json: Vec<serde_json::Value> = profile_orgs
                .iter()
                .map(|o| serde_json::to_value(o).unwrap_or_default())
                .collect();

            let profile = ProfileResponse {
                id: db_user.uuid.clone(),
                name: db_user.name.clone(),
                email: db_user.email.clone(),
                email_verified: db_user.email_verified,
                premium: user.premium,
                master_password_hint: None,
                culture: "en-US".into(),
                two_factor_enabled: false,
                key: db_user.akey.clone().unwrap_or_default(),
                private_key: db_user.private_key.clone(),
                security_stamp: db_user.security_stamp.clone(),
                organizations: profile_orgs_json,
                providers: vec![],
                force_password_reset: false,
                avatar_color: db_user.avatar_color.clone(),
                object: "profile".into(),
            };

            let cipher_responses: Vec<CipherResponse> = ciphers
                .iter()
                .map(|c| {
                    CipherResponse::from_cipher(
                        c,
                        &user.uuid,
                        &favorites,
                        &folder_ciphers,
                        &all_cipher_collections,
                    )
                })
                .collect();

            let folder_responses: Vec<FolderResponse> =
                folders.iter().map(FolderResponse::from_db).collect();

            // Sends
            let sends = queries::find_sends_by_user(&db, &user.uuid).await?;
            let send_responses: Vec<SendResponse> =
                sends.iter().map(SendResponse::from_db).collect();

            let domains = DomainsResponse {
                equivalent_domains: vec![],
                global_equivalent_domains: default_global_domains(),
                object: "domains".into(),
            };

            let sync_resp = SyncResponse {
                profile,
                ciphers: cipher_responses,
                folders: folder_responses,
                collections: collections_resp,
                policies: vec![],
                sends: send_responses,
                domains,
                object: "sync".into(),
            };

            Ok(Response::from_json(&sync_resp)?)
        }
        .await,
    )
}

fn default_global_domains() -> Vec<GlobalDomain> {
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
