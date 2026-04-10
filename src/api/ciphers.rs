use worker::{Request, Response, RouteContext};

use crate::auth::guards::{auth_from_request, verify_master_password};
use crate::config::RequestContext;
use crate::db::models::Cipher;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::cipher::{CipherRequest, CipherResponse};
use crate::util::{generate_uuid, now_utc};

/// Fetch a cipher by route param "id" and verify the user has access.
/// Access is granted if the cipher belongs to the user directly, or if the
/// cipher belongs to an org the user is a confirmed member of.
async fn fetch_accessible_cipher(
    ctx: &RouteContext<RequestContext>,
    user_uuid: &str,
) -> crate::error::Result<Cipher> {
    let cipher_id = ctx
        .param("id")
        .ok_or(AppError::BadRequest("Missing cipher id".into()))?
        .clone();
    let db = ctx.data.db()?;
    let cipher = queries::find_cipher_by_uuid(&db, &cipher_id)
        .await?
        .ok_or(AppError::NotFound("Cipher not found".into()))?;

    if cipher.user_uuid.as_deref() == Some(user_uuid) {
        return Ok(cipher);
    }

    if let Some(ref org_uuid) = cipher.organization_uuid
        && let Some(m) = queries::find_membership(&db, user_uuid, org_uuid).await?
        && m.status == 2
    {
        return Ok(cipher);
    }

    Err(AppError::Forbidden("Not your cipher".into()))
}

pub async fn get_ciphers(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let ciphers = queries::find_ciphers_by_user(&db, &user.uuid).await?;
            let favorites = queries::find_favorites_by_user(&db, &user.uuid).await?;
            let folder_ciphers = queries::find_folder_ciphers_by_user(&db, &user.uuid).await?;

            let data: Vec<CipherResponse> = ciphers
                .iter()
                .map(|c| {
                    CipherResponse::from_cipher(c, &user.uuid, &favorites, &folder_ciphers, &[])
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

pub async fn get_cipher(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_accessible_cipher(&ctx, &user.uuid).await?;
            let db = ctx.data.db()?;
            let favorites = queries::find_favorites_by_user(&db, &user.uuid).await?;
            let folder_ciphers = queries::find_folder_ciphers_by_user(&db, &user.uuid).await?;
            let cipher_collections = queries::find_cipher_collections(&db, &cipher.uuid).await?;
            let resp = CipherResponse::from_cipher(
                &cipher,
                &user.uuid,
                &favorites,
                &folder_ciphers,
                &cipher_collections,
            );
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn post_cipher(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: CipherRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let now = now_utc();
            let cipher_uuid = generate_uuid();

            let cipher = Cipher {
                uuid: cipher_uuid.clone(),
                user_uuid: Some(user.uuid.clone()),
                organization_uuid: None,
                atype: body.r#type,
                name: body.name.clone(),
                notes: body.notes.clone(),
                fields: body.fields.as_ref().map(|v| v.to_string()),
                data: body.data_json(),
                key: body.key.clone(),
                password_history: body.password_history.as_ref().map(|v| v.to_string()),
                reprompt: body.reprompt,
                deleted_at: None,
                created_at: now.clone(),
                updated_at: now,
            };

            let db = ctx.data.db()?;
            queries::insert_cipher(&db, &cipher).await?;

            if let Some(ref folder_id) = body.folder_id {
                queries::set_folder_cipher(&db, &cipher.uuid, folder_id).await?;
            }

            let is_fav = body.favorite.unwrap_or(false);
            if is_fav {
                queries::set_favorite(&db, &user.uuid, &cipher.uuid).await?;
            }

            let resp = CipherResponse::from_cipher_resolved(
                &cipher,
                is_fav,
                body.folder_id.clone(),
                vec![],
            );
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn put_cipher(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let mut cipher = fetch_accessible_cipher(&ctx, &user.uuid).await?;
            let body: CipherRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            cipher.name = body.name.clone();
            cipher.notes = body.notes.clone();
            cipher.fields = body.fields.as_ref().map(|v| v.to_string());
            cipher.data = body.data_json();
            cipher.key = body.key.clone();
            cipher.password_history = body.password_history.as_ref().map(|v| v.to_string());
            cipher.reprompt = body.reprompt;
            cipher.updated_at = now_utc();

            let db = ctx.data.db()?;
            queries::update_cipher(&db, &cipher).await?;

            queries::clear_folder_for_cipher(&db, &cipher.uuid).await?;
            if let Some(ref folder_id) = body.folder_id {
                queries::set_folder_cipher(&db, &cipher.uuid, folder_id).await?;
            }

            let is_fav = body.favorite.unwrap_or(false);
            if is_fav {
                queries::set_favorite(&db, &user.uuid, &cipher.uuid).await?;
            } else {
                queries::unset_favorite(&db, &user.uuid, &cipher.uuid).await?;
            }

            let cipher_collections = queries::find_cipher_collections(&db, &cipher.uuid).await?;
            let col_ids: Vec<String> = cipher_collections
                .into_iter()
                .map(|cc| cc.collection_uuid)
                .collect();
            let resp = CipherResponse::from_cipher_resolved(
                &cipher,
                is_fav,
                body.folder_id.clone(),
                col_ids,
            );
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn delete_cipher(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_accessible_cipher(&ctx, &user.uuid).await?;
            let db = ctx.data.db()?;
            queries::hard_delete_cipher(&db, &cipher.uuid).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn soft_delete_cipher(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_accessible_cipher(&ctx, &user.uuid).await?;
            let db = ctx.data.db()?;
            queries::soft_delete_cipher(&db, &cipher.uuid, &now_utc()).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn restore_cipher(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_accessible_cipher(&ctx, &user.uuid).await?;
            let db = ctx.data.db()?;
            queries::restore_cipher(&db, &cipher.uuid, &now_utc()).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn purge_ciphers(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;

            #[derive(serde::Deserialize)]
            struct PurgeBody {
                #[serde(rename = "masterPasswordHash")]
                master_password_hash: String,
            }
            let body: PurgeBody = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let db_user = queries::find_user_by_uuid(&db, &user.uuid)
                .await?
                .ok_or(AppError::NotFound("User not found".into()))?;

            if !verify_master_password(&db_user, &body.master_password_hash).await? {
                return Err(AppError::Unauthorized("Invalid master password".into()));
            }

            queries::purge_ciphers_for_user(&db, &user.uuid).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}
