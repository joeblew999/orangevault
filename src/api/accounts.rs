use worker::{Request, Response, RouteContext};

use crate::auth::guards::{auth_from_request, verify_master_password};
use crate::config::RequestContext;
use crate::crypto::pbkdf2::SERVER_PASSWORD_ITERATIONS;
use crate::crypto::{pbkdf2, random};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::config::{ConfigResponse, EnvironmentUrls, ServerInfo};
use crate::models::organization::ProfileOrganizationResponse;
use crate::models::user::ProfileResponse;
use crate::models::user::{
    ApiKeyRequest, ApiKeyResponse, ChangeKdfRequest, ChangePasswordRequest, DeleteAccountRequest,
    PreloginRequest, PreloginResponse, SecurityStampRequest, UpdateKeysRequest,
    UpdateProfileRequest, VerifyPasswordRequest,
};
use crate::notifications::{self, UpdateType};
use crate::util::{base64_encode, generate_uuid, hex_encode, now_utc};

pub async fn get_config(
    _req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let domain = ctx.data.domain()?;
            let config = ConfigResponse {
                version: "2024.1.0".into(),
                git_hash: "".into(),
                server: ServerInfo {
                    name: "orangevault".into(),
                    url: "".into(),
                },
                environment: EnvironmentUrls {
                    api: format!("{domain}/api"),
                    identity: format!("{domain}/identity"),
                    notifications: format!("{domain}/notifications"),
                    sso: "".into(),
                },
                feature_states: serde_json::json!({}),
                object: "config".into(),
            };
            Ok(Response::from_json(&config)?)
        }
        .await,
    )
}

pub async fn prelogin(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let body: PreloginRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let email = body.email.trim().to_lowercase();
            let db = ctx.data.db()?;
            let user = queries::find_user_by_email(&db, &email).await?;

            let response = match user {
                Some(u) => PreloginResponse {
                    kdf: u.client_kdf_type,
                    kdf_iterations: u.client_kdf_iter,
                    kdf_memory: u.client_kdf_memory,
                    kdf_parallelism: u.client_kdf_parallelism,
                },
                None => PreloginResponse {
                    kdf: 0,
                    kdf_iterations: 600000,
                    kdf_memory: None,
                    kdf_parallelism: None,
                },
            };
            Ok(Response::from_json(&response)?)
        }
        .await,
    )
}

async fn build_profile(
    ctx: &RouteContext<RequestContext>,
    user_uuid: &str,
) -> crate::error::Result<ProfileResponse> {
    let db = ctx.data.db()?;
    let db_user = queries::find_user_by_uuid(&db, user_uuid)
        .await?
        .ok_or(AppError::NotFound("User not found".into()))?;
    build_profile_from_user(ctx, &db_user).await
}

async fn build_profile_from_user(
    ctx: &RouteContext<RequestContext>,
    db_user: &crate::db::models::User,
) -> crate::error::Result<ProfileResponse> {
    let db = ctx.data.db()?;
    let memberships = queries::find_memberships_by_user(&db, &db_user.uuid).await?;
    let confirmed: Vec<_> = memberships.iter().filter(|m| m.status == 2).collect();

    let mut profile_orgs = Vec::new();
    for m in &confirmed {
        if let Some(org) = queries::find_organization_by_uuid(&db, &m.org_uuid).await? {
            profile_orgs.push(ProfileOrganizationResponse::from_membership(&org, m));
        }
    }

    let two_factors = queries::find_two_factors_by_user(&db, &db_user.uuid).await?;

    let profile_orgs_json: Vec<serde_json::Value> = profile_orgs
        .iter()
        .map(|o| serde_json::to_value(o).unwrap_or_default())
        .collect();

    Ok(ProfileResponse {
        id: db_user.uuid.clone(),
        name: db_user.name.clone(),
        email: db_user.email.clone(),
        email_verified: db_user.email_verified,
        premium: true,
        master_password_hint: None,
        culture: "en-US".into(),
        two_factor_enabled: !two_factors.is_empty(),
        key: db_user.akey.clone().unwrap_or_default(),
        private_key: db_user.private_key.clone(),
        security_stamp: db_user.security_stamp.clone(),
        organizations: profile_orgs_json,
        providers: vec![],
        force_password_reset: false,
        avatar_color: db_user.avatar_color.clone(),
        object: "profile".into(),
    })
}

pub async fn get_profile(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let profile = build_profile(&ctx, &user.uuid).await?;
            Ok(Response::from_json(&profile)?)
        }
        .await,
    )
}

pub async fn put_profile(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: UpdateProfileRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            let name = body.name.unwrap_or(db_user.name.clone());
            let now = now_utc();
            queries::update_user_profile(&db, &user.uuid, &name, &db_user.avatar_color, &now)
                .await?;

            // Re-read the updated user rather than calling build_profile which re-fetches
            let mut updated_user = db_user;
            updated_user.name = name;
            updated_user.updated_at = now;
            let profile = build_profile_from_user(&ctx, &updated_user).await?;
            Ok(Response::from_json(&profile)?)
        }
        .await,
    )
}

pub async fn post_password(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: ChangePasswordRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let salt = random::random_bytes(64)?;
            let password_hash = pbkdf2::pbkdf2_sha256(
                body.new_master_password_hash.as_bytes(),
                &salt,
                SERVER_PASSWORD_ITERATIONS,
                32,
            )
            .await?;

            let new_stamp = generate_uuid();
            let now = now_utc();
            queries::update_user_password(
                &db,
                &user.uuid,
                &base64_encode(&password_hash),
                &base64_encode(&salt),
                SERVER_PASSWORD_ITERATIONS,
                &body.key,
                &new_stamp,
                &now,
            )
            .await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::LogOut,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn put_kdf(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: ChangeKdfRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let salt = random::random_bytes(64)?;
            let password_hash = pbkdf2::pbkdf2_sha256(
                body.new_master_password_hash.as_bytes(),
                &salt,
                SERVER_PASSWORD_ITERATIONS,
                32,
            )
            .await?;

            let new_stamp = generate_uuid();
            let now = now_utc();
            queries::update_user_kdf(
                &db,
                &user.uuid,
                &base64_encode(&password_hash),
                &base64_encode(&salt),
                SERVER_PASSWORD_ITERATIONS,
                &body.key,
                &new_stamp,
                body.kdf,
                body.kdf_iterations,
                body.kdf_memory,
                body.kdf_parallelism,
                &now,
            )
            .await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::LogOut,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn put_keys(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: UpdateKeysRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let new_stamp = generate_uuid();
            let now = now_utc();
            queries::update_user_keys(
                &db,
                &user.uuid,
                &body.key,
                &body.private_key,
                &new_stamp,
                &now,
            )
            .await?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn verify_password(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: VerifyPasswordRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn post_security_stamp(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: SecurityStampRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let new_stamp = generate_uuid();
            queries::update_user_security_stamp(&db, &user.uuid, &new_stamp, &now_utc()).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::LogOut,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn post_api_key(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: ApiKeyRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let api_key = match db_user.api_key {
                Some(key) => key,
                None => {
                    let key = hex_encode(&random::random_bytes(30)?);
                    queries::update_user_api_key(&db, &user.uuid, &key, &now_utc()).await?;
                    key
                }
            };

            Ok(Response::from_json(&ApiKeyResponse {
                api_key,
                object: "apiKey".into(),
            })?)
        }
        .await,
    )
}

pub async fn rotate_api_key(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: ApiKeyRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            let key = hex_encode(&random::random_bytes(30)?);
            queries::update_user_api_key(&db, &user.uuid, &key, &now_utc()).await?;

            Ok(Response::from_json(&ApiKeyResponse {
                api_key: key,
                object: "apiKey".into(),
            })?)
        }
        .await,
    )
}

pub async fn delete_account(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: DeleteAccountRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::BadRequest("Invalid master password".into()));
            }

            if let Ok(r2) = ctx.data.r2() {
                let file_sends = queries::find_file_send_data_by_user(&db, &user.uuid).await?;
                for send in &file_sends {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&send.data)
                        && let Some(file_id) =
                            data.get("Id").or(data.get("id")).and_then(|v| v.as_str())
                    {
                        let key = format!("sends/{}/{}", send.uuid, file_id);
                        let _ = r2.delete(&key).await;
                    }
                }
            }

            queries::delete_user_cascade(&db, &user.uuid).await?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn get_revision_date(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            // Bitwarden clients expect a bare quoted date string
            Ok(Response::from_json(&db_user.updated_at)?)
        }
        .await,
    )
}

pub async fn get_domains(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let resp = build_domains_response(&db, &user.uuid).await?;
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn post_domains(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: DomainsRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let existing = queries::find_equivalent_domains_by_user(&db, &user.uuid).await?;
            let uuid = existing.map(|e| e.uuid).unwrap_or_else(generate_uuid);

            let global_equiv_str = serde_json::to_string(&body.excluded_global_equivalent_domains)
                .unwrap_or_else(|_| "[]".into());
            let custom_equiv_str =
                serde_json::to_string(&body.equivalent_domains).unwrap_or_else(|_| "[]".into());

            let ed = crate::db::models::EquivalentDomain {
                uuid,
                user_uuid: user.uuid.clone(),
                global_equiv_domains: Some(global_equiv_str),
                custom_equiv_domains: Some(custom_equiv_str),
            };
            queries::upsert_equivalent_domains(&db, &ed).await?;

            // Build response from the data we already have instead of re-querying
            let resp = build_domains_response_from_data(
                &body.excluded_global_equivalent_domains,
                &body.equivalent_domains,
            );
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

async fn build_domains_response(
    db: &worker::D1Database,
    user_uuid: &str,
) -> crate::error::Result<crate::models::sync::DomainsResponse> {
    let user_domains = queries::find_equivalent_domains_by_user(db, user_uuid).await?;

    let excluded_globals: Vec<i32> = user_domains
        .as_ref()
        .and_then(|ed| ed.global_equiv_domains.as_ref())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let custom_domains: Vec<Vec<String>> = user_domains
        .as_ref()
        .and_then(|ed| ed.custom_equiv_domains.as_ref())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Ok(build_domains_response_from_data(
        &excluded_globals,
        &custom_domains,
    ))
}

fn build_domains_response_from_data(
    excluded_globals: &[i32],
    custom_domains: &[Vec<String>],
) -> crate::models::sync::DomainsResponse {
    use crate::models::sync::{DomainsResponse, GlobalDomain};

    let custom_json: Vec<serde_json::Value> = custom_domains
        .iter()
        .map(|d| serde_json::to_value(d).unwrap_or_default())
        .collect();

    let globals: Vec<GlobalDomain> = crate::models::sync::default_global_domains()
        .into_iter()
        .map(|mut g| {
            g.excluded = excluded_globals.contains(&g.r#type);
            g
        })
        .collect();

    DomainsResponse {
        equivalent_domains: custom_json,
        global_equivalent_domains: globals,
        object: "domains".into(),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainsRequest {
    #[serde(default)]
    equivalent_domains: Vec<Vec<String>>,
    #[serde(default)]
    excluded_global_equivalent_domains: Vec<i32>,
}
