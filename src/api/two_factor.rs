use serde::{Deserialize, Serialize};
use worker::{Request, Response, RouteContext};

use crate::auth::guards::{auth_from_request, verify_master_password};
use crate::config::RequestContext;
use crate::crypto::totp::{
    base32_decode, generate_recovery_code, generate_totp_secret, validate_totp,
};
use crate::db::models::TwoFactor;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::util::generate_uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordOrOtp {
    master_password_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableAuthenticatorRequest {
    master_password_hash: Option<String>,
    key: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AuthenticatorResponse {
    enabled: bool,
    key: String,
    object: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RecoverResponse {
    code: Option<String>,
    object: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct TwoFactorProviderResponse {
    enabled: bool,
    r#type: i32,
    object: String,
}

async fn verify_password_and_get_user(
    db: &worker::D1Database,
    user_uuid: &str,
    master_password_hash: Option<&str>,
) -> crate::error::Result<crate::db::models::User> {
    let hash =
        master_password_hash.ok_or(AppError::Unauthorized("Master password required".into()))?;
    let user = queries::find_user_by_uuid(db, user_uuid)
        .await?
        .ok_or(AppError::NotFound("User not found".into()))?;
    if !verify_master_password(&user, hash).await? {
        return Err(AppError::Unauthorized("Invalid master password".into()));
    }
    Ok(user)
}

/// GET /two-factor — list enabled 2FA providers.
pub async fn get_two_factor(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let factors = queries::find_two_factors_by_user(&db, &user.uuid).await?;

            let data: Vec<TwoFactorProviderResponse> = factors
                .iter()
                .map(|tf| TwoFactorProviderResponse {
                    enabled: tf.enabled,
                    r#type: tf.atype,
                    object: "twoFactorProvider".into(),
                })
                .collect();

            Ok(Response::from_json(&serde_json::json!({
                "Data": data,
                "Object": "list",
                "ContinuationToken": null,
            }))?)
        }
        .await,
    )
}

/// POST /two-factor/get-authenticator — get or generate TOTP secret.
pub async fn get_authenticator(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: PasswordOrOtp = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            verify_password_and_get_user(&db, &user.uuid, body.master_password_hash.as_deref())
                .await?;

            let existing = queries::find_two_factor_by_user_and_type(&db, &user.uuid, 0).await?;

            let (enabled, key) = match existing {
                Some(tf) => (tf.enabled, tf.data),
                None => {
                    let secret = generate_totp_secret()?;
                    (false, secret)
                }
            };

            Ok(Response::from_json(&AuthenticatorResponse {
                enabled,
                key,
                object: "twoFactorAuthenticator".into(),
            })?)
        }
        .await,
    )
}

/// POST /two-factor/authenticator — enable TOTP 2FA.
pub async fn post_authenticator(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: EnableAuthenticatorRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user =
                verify_password_and_get_user(&db, &user.uuid, body.master_password_hash.as_deref())
                    .await?;

            let secret_bytes = base32_decode(&body.key)?;
            let now = crate::util::now_epoch_secs() as u64;
            let step = validate_totp(&secret_bytes, &body.token, now)
                .await?
                .ok_or(AppError::BadRequest("Invalid TOTP code".into()))?;

            // Upsert the TOTP two-factor record. Anchor `last_used` to the step
            // the user just proved possession of, so the same code cannot be
            // replayed against /identity/connect/token within the window.
            let existing = queries::find_two_factor_by_user_and_type(&db, &user.uuid, 0).await?;
            if let Some(ref e) = existing
                && step <= e.last_used.unwrap_or(0)
            {
                return Err(AppError::BadRequest("TOTP code already used".into()));
            }
            let tf = TwoFactor {
                uuid: existing.map(|e| e.uuid).unwrap_or_else(generate_uuid),
                user_uuid: user.uuid.clone(),
                atype: 0, // Authenticator
                enabled: true,
                data: body.key.clone(),
                last_used: Some(step),
            };
            queries::upsert_two_factor(&db, &tf).await?;

            if db_user.totp_recover.is_none() {
                let recovery = generate_recovery_code()?;
                queries::update_user_totp_recover(&db, &user.uuid, Some(&recovery)).await?;
            }

            Ok(Response::from_json(&AuthenticatorResponse {
                enabled: true,
                key: body.key,
                object: "twoFactorAuthenticator".into(),
            })?)
        }
        .await,
    )
}

/// POST /two-factor/get-recover — get recovery code.
pub async fn get_recover(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: PasswordOrOtp = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user =
                verify_password_and_get_user(&db, &user.uuid, body.master_password_hash.as_deref())
                    .await?;

            Ok(Response::from_json(&RecoverResponse {
                code: db_user.totp_recover,
                object: "twoFactorRecover".into(),
            })?)
        }
        .await,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableTwoFactorRequest {
    master_password_hash: Option<String>,
    r#type: i32,
}

/// PUT /two-factor/disable — disable a specific 2FA provider.
pub async fn disable_two_factor(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: DisableTwoFactorRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            verify_password_and_get_user(&db, &user.uuid, body.master_password_hash.as_deref())
                .await?;

            let tf = queries::find_two_factor_by_user_and_type(&db, &user.uuid, body.r#type)
                .await?
                .ok_or(AppError::NotFound("2FA provider not found".into()))?;

            queries::disable_two_factor(&db, &tf.uuid).await?;

            // If no enabled 2FA remains, clear recovery code
            let remaining = queries::find_two_factors_by_user(&db, &user.uuid).await?;
            let any_enabled = remaining.iter().any(|t| t.enabled && t.uuid != tf.uuid);
            if !any_enabled {
                queries::update_user_totp_recover(&db, &user.uuid, None).await?;
            }

            Ok(Response::from_json(&TwoFactorProviderResponse {
                enabled: false,
                r#type: body.r#type,
                object: "twoFactorProvider".into(),
            })?)
        }
        .await,
    )
}

/// POST /two-factor/recover — regenerate recovery code.
pub async fn post_recover(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: PasswordOrOtp = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            verify_password_and_get_user(&db, &user.uuid, body.master_password_hash.as_deref())
                .await?;

            let recovery = generate_recovery_code()?;
            queries::update_user_totp_recover(&db, &user.uuid, Some(&recovery)).await?;

            Ok(Response::from_json(&RecoverResponse {
                code: Some(recovery),
                object: "twoFactorRecover".into(),
            })?)
        }
        .await,
    )
}
