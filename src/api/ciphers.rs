use worker::{Request, Response, RouteContext};

use crate::auth::guards::{auth_from_request, verify_master_password};
use crate::config::RequestContext;
use crate::db::models::{Attachment, Cipher, Folder};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::cipher::{
    AttachmentRequestV2, AttachmentResponse, AttachmentUploadResponse, BulkIdsRequest,
    BulkMoveRequest, CipherCollectionsRequest, CipherRequest, CipherResponse, ImportCiphersRequest,
    format_size,
};
use crate::notifications::{self, UpdateType};
use crate::util::{generate_uuid, now_utc};

/// Whether a caller needs read-only access or the ability to mutate a cipher.
/// `Write` additionally excludes members whose only collection grants are
/// `read_only = 1`.
#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

/// Return whether `user_uuid` has the requested `Access` to `cipher`.
///
/// Precedence (matches the vaultwarden semantics we ported from):
/// 1. Personal cipher (`user_uuid` matches) → full access.
/// 2. Org cipher + confirmed membership with Owner/Admin role or
///    `access_all = 1` → full access.
/// 3. Otherwise, at least one `users_collections` row linking the user to a
///    collection that contains the cipher, and for `Write` access at least
///    one of those rows must have `read_only = 0`.
async fn has_cipher_access(
    db: &worker::D1Database,
    user_uuid: &str,
    cipher: &Cipher,
    access: Access,
) -> crate::error::Result<bool> {
    if cipher.user_uuid.as_deref() == Some(user_uuid) {
        return Ok(true);
    }
    let Some(ref org_uuid) = cipher.organization_uuid else {
        return Ok(false);
    };
    let Some(m) = queries::find_membership(db, user_uuid, org_uuid).await? else {
        return Ok(false);
    };
    if m.status != 2 {
        return Ok(false);
    }
    if m.atype <= 1 || m.access_all {
        return Ok(true);
    }
    let rows = queries::find_user_cipher_collection_access(db, user_uuid, &cipher.uuid).await?;
    if rows.is_empty() {
        return Ok(false);
    }
    Ok(match access {
        Access::Read => true,
        Access::Write => rows.iter().any(|uc| !uc.read_only),
    })
}

/// Fetch a cipher by route param "id" and enforce `access`.
async fn fetch_cipher_with_access(
    ctx: &RouteContext<RequestContext>,
    user_uuid: &str,
    access: Access,
) -> crate::error::Result<Cipher> {
    let cipher_id = ctx
        .param("id")
        .ok_or(AppError::BadRequest("Missing cipher id".into()))?
        .clone();
    let db = ctx.data.db()?;
    let cipher = queries::find_cipher_by_uuid(&db, &cipher_id)
        .await?
        .ok_or(AppError::NotFound("Cipher not found".into()))?;

    if has_cipher_access(&db, user_uuid, &cipher, access).await? {
        Ok(cipher)
    } else {
        Err(AppError::Forbidden("Not your cipher".into()))
    }
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
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Read).await?;
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

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherCreate,
                &cipher.uuid,
                serde_json::json!({"Id": cipher.uuid, "RevisionDate": cipher.updated_at}),
            )
            .await;

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
            let mut cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
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

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherUpdate,
                &cipher.uuid,
                serde_json::json!({"Id": cipher.uuid, "RevisionDate": cipher.updated_at}),
            )
            .await;

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
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let db = ctx.data.db()?;
            let cipher_uuid = cipher.uuid.clone();
            queries::hard_delete_cipher(&db, &cipher.uuid).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherDelete,
                &cipher_uuid,
                serde_json::json!({"Id": cipher_uuid}),
            )
            .await;

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
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let db = ctx.data.db()?;
            queries::soft_delete_cipher(&db, &cipher.uuid, &now_utc()).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherUpdate,
                &cipher.uuid,
                serde_json::json!({"Id": cipher.uuid}),
            )
            .await;

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
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let db = ctx.data.db()?;
            queries::restore_cipher(&db, &cipher.uuid, &now_utc()).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherUpdate,
                &cipher.uuid,
                serde_json::json!({"Id": cipher.uuid}),
            )
            .await;

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

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncVault,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn bulk_move(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: BulkMoveRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            for cipher_id in &body.ids {
                if let Some(cipher) = queries::find_cipher_by_uuid(&db, cipher_id).await? {
                    if cipher.user_uuid.as_deref() != Some(&user.uuid) {
                        continue;
                    }
                    queries::clear_folder_for_cipher(&db, cipher_id).await?;
                    if let Some(ref folder_id) = body.folder_id {
                        queries::set_folder_cipher(&db, cipher_id, folder_id).await?;
                    }
                }
            }

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncVault,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn bulk_soft_delete(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: BulkIdsRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let now = now_utc();
            for cipher_id in &body.ids {
                if let Some(cipher) = queries::find_cipher_by_uuid(&db, cipher_id).await?
                    && has_cipher_access(&db, &user.uuid, &cipher, Access::Write).await?
                {
                    queries::soft_delete_cipher(&db, cipher_id, &now).await?;
                }
            }

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncVault,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn bulk_restore(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: BulkIdsRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let now = now_utc();
            for cipher_id in &body.ids {
                if let Some(cipher) = queries::find_cipher_by_uuid(&db, cipher_id).await?
                    && has_cipher_access(&db, &user.uuid, &cipher, Access::Write).await?
                {
                    queries::restore_cipher(&db, cipher_id, &now).await?;
                }
            }

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncVault,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn import_ciphers(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: ImportCiphersRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let now = now_utc();

            let mut folder_uuids = Vec::new();
            for folder_req in &body.folders {
                let folder = Folder {
                    uuid: generate_uuid(),
                    user_uuid: user.uuid.clone(),
                    name: folder_req.name.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };
                queries::insert_folder(&db, &folder).await?;
                folder_uuids.push(folder.uuid);
            }

            let mut cipher_uuids = Vec::new();
            for cipher_req in &body.ciphers {
                let cipher = Cipher {
                    uuid: generate_uuid(),
                    user_uuid: Some(user.uuid.clone()),
                    organization_uuid: None,
                    atype: cipher_req.r#type,
                    name: cipher_req.name.clone(),
                    notes: cipher_req.notes.clone(),
                    fields: cipher_req.fields.as_ref().map(|v| v.to_string()),
                    data: cipher_req.data_json(),
                    key: cipher_req.key.clone(),
                    password_history: cipher_req.password_history.as_ref().map(|v| v.to_string()),
                    reprompt: cipher_req.reprompt,
                    deleted_at: None,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };
                queries::insert_cipher(&db, &cipher).await?;
                cipher_uuids.push(cipher.uuid);
            }

            for rel in &body.folder_relationships {
                if rel.key < cipher_uuids.len() && rel.value < folder_uuids.len() {
                    queries::set_folder_cipher(
                        &db,
                        &cipher_uuids[rel.key],
                        &folder_uuids[rel.value],
                    )
                    .await?;
                }
            }

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncVault,
                &user.uuid,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn post_cipher_collections(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let body: CipherCollectionsRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            queries::clear_cipher_collections(&db, &cipher.uuid).await?;
            for col_id in &body.collection_ids {
                queries::set_cipher_collection(&db, &cipher.uuid, col_id).await?;
            }

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncCipherUpdate,
                &cipher.uuid,
                serde_json::json!({"Id": cipher.uuid, "RevisionDate": cipher.updated_at}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn post_cipher_collections_admin(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    post_cipher_collections(req, ctx).await
}

// --- Attachments ---

pub async fn post_attachment_v2(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let body: AttachmentRequestV2 = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let att_id = generate_uuid();

            let attachment = Attachment {
                id: att_id.clone(),
                cipher_uuid: cipher.uuid.clone(),
                file_name: Some(body.file_name),
                file_size: Some(body.file_size),
                akey: body.key,
            };
            queries::insert_attachment(&db, &attachment).await?;

            let domain = ctx.data.domain()?;
            let url = format!("{domain}/api/ciphers/{}/attachment/{att_id}", cipher.uuid);

            let resp = AttachmentUploadResponse {
                attachment_id: att_id,
                url,
                file_upload_type: 0,
                cipher_id: cipher.uuid,
                cipher_mini_response: None,
                object: "attachment-upload".into(),
            };

            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn upload_attachment(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let att_id = ctx
                .param("att_id")
                .ok_or(AppError::BadRequest("Missing attachment id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let attachment = queries::find_attachment_by_id(&db, &att_id)
                .await?
                .ok_or(AppError::NotFound("Attachment not found".into()))?;
            if attachment.cipher_uuid != cipher.uuid {
                return Err(AppError::Forbidden(
                    "Attachment does not belong to this cipher".into(),
                ));
            }

            let bytes = req
                .bytes()
                .await
                .map_err(|e| AppError::BadRequest(format!("Failed to read body: {e}")))?;

            let r2 = ctx.data.r2()?;
            let key = format!("attachments/{}/{}", cipher.uuid, att_id);
            r2.put(&key, bytes)
                .execute()
                .await
                .map_err(|e| AppError::Internal(format!("R2 put failed: {e}")))?;

            queries::update_cipher_date(&db, &cipher.uuid, &now_utc()).await?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn get_attachment(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Read).await?;
            let att_id = ctx
                .param("att_id")
                .ok_or(AppError::BadRequest("Missing attachment id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let attachment = queries::find_attachment_by_id(&db, &att_id)
                .await?
                .ok_or(AppError::NotFound("Attachment not found".into()))?;

            if attachment.cipher_uuid != cipher.uuid {
                return Err(AppError::Forbidden(
                    "Attachment does not belong to this cipher".into(),
                ));
            }

            let domain = ctx.data.domain()?;
            let url = format!(
                "{domain}/api/ciphers/{}/attachment/{att_id}/download",
                cipher.uuid
            );

            Ok(Response::from_json(&AttachmentResponse {
                id: attachment.id,
                file_name: attachment.file_name,
                size: attachment.file_size,
                size_name: format_size(attachment.file_size.unwrap_or(0)),
                key: attachment.akey,
                url,
                object: "attachment".into(),
            })?)
        }
        .await,
    )
}

pub async fn delete_attachment(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher = fetch_cipher_with_access(&ctx, &user.uuid, Access::Write).await?;
            let att_id = ctx
                .param("att_id")
                .ok_or(AppError::BadRequest("Missing attachment id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let attachment = queries::find_attachment_by_id(&db, &att_id)
                .await?
                .ok_or(AppError::NotFound("Attachment not found".into()))?;

            if attachment.cipher_uuid != cipher.uuid {
                return Err(AppError::Forbidden(
                    "Attachment does not belong to this cipher".into(),
                ));
            }

            if let Ok(r2) = ctx.data.r2() {
                let key = format!("attachments/{}/{}", cipher.uuid, att_id);
                let _ = r2.delete(&key).await;
            }

            queries::delete_attachment(&db, &att_id).await?;
            queries::update_cipher_date(&db, &cipher.uuid, &now_utc()).await?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}
