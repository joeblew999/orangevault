use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::queries;
use crate::error;
use crate::models::cipher::CipherResponse;
use crate::models::folder::FolderResponse;
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

            let ciphers = queries::find_ciphers_by_user(&db, &user.uuid).await?;
            let folders = queries::find_folders_by_user(&db, &user.uuid).await?;
            let favorites = queries::find_favorites_by_user(&db, &user.uuid).await?;
            let folder_ciphers = queries::find_folder_ciphers_by_user(&db, &user.uuid).await?;

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
                organizations: vec![],
                providers: vec![],
                force_password_reset: false,
                avatar_color: db_user.avatar_color.clone(),
                object: "profile".into(),
            };

            let cipher_responses: Vec<CipherResponse> = ciphers
                .iter()
                .map(|c| CipherResponse::from_cipher(c, &user.uuid, &favorites, &folder_ciphers))
                .collect();

            let folder_responses: Vec<FolderResponse> =
                folders.iter().map(FolderResponse::from_db).collect();

            let domains = DomainsResponse {
                equivalent_domains: vec![],
                global_equivalent_domains: default_global_domains(),
                object: "domains".into(),
            };

            let sync_resp = SyncResponse {
                profile,
                ciphers: cipher_responses,
                folders: folder_responses,
                collections: vec![],
                policies: vec![],
                sends: vec![],
                domains,
                object: "sync".into(),
            };

            Ok(Response::from_json(&sync_resp)?)
        }
        .await,
    )
}

/// Default global equivalent domain groups (subset from Bitwarden).
fn default_global_domains() -> Vec<GlobalDomain> {
    vec![
        GlobalDomain {
            r#type: 0,
            domains: vec!["google.com", "youtube.com", "gmail.com", "googlemail.com"]
                .into_iter()
                .map(String::from)
                .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 1,
            domains: vec!["apple.com", "icloud.com", "me.com"]
                .into_iter()
                .map(String::from)
                .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 2,
            domains: vec![
                "live.com",
                "microsoft.com",
                "microsoftonline.com",
                "outlook.com",
                "hotmail.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            excluded: false,
        },
        GlobalDomain {
            r#type: 3,
            domains: vec![
                "amazon.com",
                "amazon.co.uk",
                "amazon.ca",
                "amazon.de",
                "amazon.in",
                "amazon.co.jp",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            excluded: false,
        },
    ]
}
