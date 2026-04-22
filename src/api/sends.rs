use worker::{Request, Response, RouteContext};

use crate::auth::claims::SendAccessClaims;
use crate::auth::guards::auth_from_request;
use crate::auth::jwt;
use crate::config::RequestContext;
use crate::crypto::{pbkdf2, random};
use crate::db::models::Send as DbSend;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::send::{
    SEND_TYPE_FILE, SEND_TYPE_TEXT, SendAccessRequest, SendAccessResponse,
    SendFileDownloadResponse, SendFileUploadResponse, SendRequest, SendResponse,
};
use crate::notifications::{self, UpdateType};
use crate::util::{base64_encode, base64url_decode, generate_uuid, now_utc};

const SEND_PASSWORD_ITERATIONS: u32 = 100_000;

/// Fetch a send by route param and verify the authenticated user owns it.
async fn fetch_owned_send(
    ctx: &RouteContext<RequestContext>,
    user_uuid: &str,
    param_name: &str,
) -> crate::error::Result<DbSend> {
    let send_id = ctx
        .param(param_name)
        .ok_or(AppError::BadRequest(format!("Missing {param_name}")))?
        .clone();
    let db = ctx.data.db()?;
    let send = queries::find_send_by_uuid(&db, &send_id)
        .await?
        .ok_or(AppError::NotFound("Send not found".into()))?;

    if send.user_uuid.as_deref() != Some(user_uuid) {
        return Err(AppError::Forbidden("Not your send".into()));
    }

    Ok(send)
}

/// Build a new `DbSend` from a request body and computed data field.
fn new_send_from_request(
    user_uuid: String,
    body: SendRequest,
    atype: i32,
    data: String,
    pw_hash: Option<String>,
    pw_salt: Option<String>,
    pw_iter: Option<i32>,
) -> DbSend {
    let now = now_utc();
    DbSend {
        uuid: generate_uuid(),
        user_uuid: Some(user_uuid),
        organization_uuid: None,
        atype,
        name: body.name,
        notes: body.notes,
        data,
        akey: body.key,
        password_hash: pw_hash,
        password_salt: pw_salt,
        password_iter: pw_iter,
        max_access_count: body.max_access_count,
        access_count: 0,
        disabled: body.disabled.unwrap_or(false),
        hide_email: body.hide_email.unwrap_or(false),
        expiration_date: body.expiration_date,
        deletion_date: body.deletion_date,
        created_at: now.clone(),
        updated_at: now,
    }
}

/// GET /api/sends — list all sends for the authenticated user.
pub async fn get_sends(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let sends = queries::find_sends_by_user(&db, &user.uuid).await?;
            let data: Vec<SendResponse> = sends.iter().map(SendResponse::from_db).collect();
            Ok(Response::from_json(&serde_json::json!({
                "Data": data,
                "Object": "list",
                "ContinuationToken": null,
            }))?)
        }
        .await,
    )
}

/// GET /api/sends/:id — get a single send.
pub async fn get_send(req: Request, ctx: RouteContext<RequestContext>) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let send = fetch_owned_send(&ctx, &user.uuid, "id").await?;
            Ok(Response::from_json(&SendResponse::from_db(&send))?)
        }
        .await,
    )
}

/// POST /api/sends — create a new text send.
pub async fn post_send(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: SendRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            if body.r#type == SEND_TYPE_FILE {
                return Err(AppError::BadRequest(
                    "Use /sends/file/v2 for file sends".into(),
                ));
            }

            let (pw_hash, pw_salt, pw_iter) = hash_send_password(body.password.as_deref()).await?;
            let data =
                serde_json::to_string(&body.text.as_ref().unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let user_uuid = user.uuid.clone();
            let send = new_send_from_request(
                user.uuid,
                body,
                SEND_TYPE_TEXT,
                data,
                pw_hash,
                pw_salt,
                pw_iter,
            );

            let db = ctx.data.db()?;
            queries::insert_send(&db, &send).await?;

            notifications::send_notification(
                &ctx.env,
                &user_uuid,
                UpdateType::SyncSendCreate,
                &send.uuid,
                serde_json::json!({"Id": send.uuid, "RevisionDate": send.updated_at}),
            )
            .await;

            Ok(Response::from_json(&SendResponse::from_db(&send))?)
        }
        .await,
    )
}

/// POST /api/sends/file/v2 — initialize a file send (v2 protocol).
pub async fn post_send_file_v2(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: SendRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            if body.r#type != SEND_TYPE_FILE {
                return Err(AppError::BadRequest("Expected file send type".into()));
            }

            let file_data = body.file.as_ref().ok_or(AppError::BadRequest(
                "Missing file data for file send".into(),
            ))?;

            let file_id = generate_uuid();
            let mut file_obj = file_data.clone();
            if let Some(obj) = file_obj.as_object_mut() {
                obj.insert("id".to_string(), serde_json::Value::String(file_id.clone()));
                if let Some(size) = body.file_length {
                    obj.insert(
                        "size".to_string(),
                        serde_json::Value::String(size.to_string()),
                    );
                    obj.insert(
                        "sizeName".to_string(),
                        serde_json::Value::String(format_size(size)),
                    );
                }
            }
            let data = serde_json::to_string(&file_obj).unwrap_or_default();

            let (pw_hash, pw_salt, pw_iter) = hash_send_password(body.password.as_deref()).await?;
            let user_uuid = user.uuid.clone();
            let send = new_send_from_request(
                user.uuid,
                body,
                SEND_TYPE_FILE,
                data,
                pw_hash,
                pw_salt,
                pw_iter,
            );

            let db = ctx.data.db()?;
            queries::insert_send(&db, &send).await?;

            notifications::send_notification(
                &ctx.env,
                &user_uuid,
                UpdateType::SyncSendCreate,
                &send.uuid,
                serde_json::json!({"Id": send.uuid, "RevisionDate": send.updated_at}),
            )
            .await;

            let domain = ctx.data.domain()?;
            let url = format!("{domain}/api/sends/{}/file/{}", send.uuid, file_id);

            let resp = SendFileUploadResponse {
                file_upload_type: 0,
                object: "send-fileUpload".into(),
                url,
                send_response: SendResponse::from_db(&send),
            };
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

/// POST /api/sends/:send_id/file/:file_id — upload file data for a v2 file send.
pub async fn post_send_file(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let send = fetch_owned_send(&ctx, &user.uuid, "send_id").await?;
            let file_id = ctx
                .param("file_id")
                .ok_or(AppError::BadRequest("Missing file_id".into()))?
                .clone();

            if send.atype != SEND_TYPE_FILE {
                return Err(AppError::BadRequest("Send is not a file send".into()));
            }

            // Validate that the URL file_id matches the one stored in send data
            let expected_file_id = extract_file_id(&send.data)?;
            if file_id != expected_file_id {
                return Err(AppError::BadRequest("File ID mismatch".into()));
            }

            let bytes = req
                .bytes()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to read body: {e}")))?;

            let r2 = ctx.data.r2()?;
            let r2_key = format!("sends/{}/{file_id}", send.uuid);
            r2.put(&r2_key, bytes)
                .execute()
                .await
                .map_err(|e| AppError::Internal(format!("R2 put failed: {e}")))?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

/// PUT /api/sends/:id — update an existing send.
pub async fn put_send(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let mut send = fetch_owned_send(&ctx, &user.uuid, "id").await?;
            let body: SendRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            send.name = body.name;
            send.notes = body.notes;
            send.akey = body.key;
            send.max_access_count = body.max_access_count;
            send.expiration_date = body.expiration_date;
            send.deletion_date = body.deletion_date;
            send.disabled = body.disabled.unwrap_or(send.disabled);
            send.hide_email = body.hide_email.unwrap_or(send.hide_email);

            // For text sends, update data; for file sends, data is immutable
            if send.atype == SEND_TYPE_TEXT
                && let Some(text) = &body.text
            {
                send.data = serde_json::to_string(text).unwrap_or_default();
            }

            if let Some(pw) = &body.password
                && !pw.is_empty()
            {
                let (pw_hash, pw_salt, pw_iter) = hash_send_password(Some(pw)).await?;
                send.password_hash = pw_hash;
                send.password_salt = pw_salt;
                send.password_iter = pw_iter;
            }

            send.updated_at = now_utc();
            let db = ctx.data.db()?;
            queries::update_send(&db, &send).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncSendUpdate,
                &send.uuid,
                serde_json::json!({"Id": send.uuid, "RevisionDate": send.updated_at}),
            )
            .await;

            Ok(Response::from_json(&SendResponse::from_db(&send))?)
        }
        .await,
    )
}

/// PUT /api/sends/:id/remove-password — remove password from a send.
pub async fn put_send_remove_password(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let mut send = fetch_owned_send(&ctx, &user.uuid, "id").await?;

            send.password_hash = None;
            send.password_salt = None;
            send.password_iter = None;
            send.updated_at = now_utc();
            let db = ctx.data.db()?;
            queries::update_send(&db, &send).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncSendUpdate,
                &send.uuid,
                serde_json::json!({"Id": send.uuid, "RevisionDate": send.updated_at}),
            )
            .await;

            Ok(Response::from_json(&SendResponse::from_db(&send))?)
        }
        .await,
    )
}

/// DELETE /api/sends/:id — delete a send.
pub async fn delete_send(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let send = fetch_owned_send(&ctx, &user.uuid, "id").await?;

            if send.atype == SEND_TYPE_FILE
                && let Ok(file_id) = extract_file_id(&send.data)
            {
                let r2 = ctx.data.r2()?;
                let r2_key = format!("sends/{}/{file_id}", send.uuid);
                let _ = r2.delete(&r2_key).await;
            }

            let send_uuid = send.uuid.clone();
            let db = ctx.data.db()?;
            queries::delete_send(&db, &send.uuid).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncSendDelete,
                &send_uuid,
                serde_json::json!({"Id": send_uuid}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

/// POST /api/sends/access/:access_id — anonymous access to a send.
pub async fn post_access(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let access_id = ctx
                .param("access_id")
                .ok_or(AppError::BadRequest("Missing access_id".into()))?
                .clone();

            let uuid_bytes = base64url_decode(&access_id)
                .map_err(|_| AppError::NotFound("Send not found".into()))?;
            let send_uuid = String::from_utf8(uuid_bytes)
                .map_err(|_| AppError::NotFound("Send not found".into()))?;

            let db = ctx.data.db()?;
            let send =
                queries::find_send_by_uuid(&db, &send_uuid)
                    .await?
                    .ok_or(AppError::NotFound(
                        "Send does not exist or is no longer available".into(),
                    ))?;

            let now = now_utc();
            check_send_available(&send, &now)?;

            if send.password_hash.is_some() {
                let body: SendAccessRequest = req
                    .json()
                    .await
                    .map_err(|_| AppError::Unauthorized("Password not provided".into()))?;

                let password = body
                    .password
                    .ok_or(AppError::Unauthorized("Password not provided".into()))?;

                if !verify_send_password(&send, &password).await? {
                    return Err(AppError::Unauthorized("Invalid password".into()));
                }
            }

            if send.atype == SEND_TYPE_TEXT {
                queries::increment_send_access_count(&db, &send.uuid, &now).await?;
            }

            let creator_email = if !send.hide_email {
                if let Some(user_uuid) = &send.user_uuid {
                    queries::find_user_by_uuid(&db, user_uuid)
                        .await?
                        .map(|u| u.email)
                } else {
                    None
                }
            } else {
                None
            };

            let resp = SendAccessResponse::from_db(&send, creator_email.as_deref());
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

/// POST /api/sends/:send_id/access/file/:file_id — anonymous file download.
pub async fn post_access_file(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let send_id = ctx
                .param("send_id")
                .ok_or(AppError::BadRequest("Missing send_id".into()))?
                .clone();
            let file_id = ctx
                .param("file_id")
                .ok_or(AppError::BadRequest("Missing file_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let send =
                queries::find_send_by_uuid(&db, &send_id)
                    .await?
                    .ok_or(AppError::NotFound(
                        "Send does not exist or is no longer available".into(),
                    ))?;

            let now = now_utc();
            check_send_available(&send, &now)?;

            if send.atype != SEND_TYPE_FILE {
                return Err(AppError::BadRequest("Send is not a file send".into()));
            }

            if send.password_hash.is_some() {
                let body: SendAccessRequest = req
                    .json()
                    .await
                    .map_err(|_| AppError::Unauthorized("Password not provided".into()))?;

                let password = body
                    .password
                    .ok_or(AppError::Unauthorized("Password not provided".into()))?;

                if !verify_send_password(&send, &password).await? {
                    return Err(AppError::Unauthorized("Invalid password".into()));
                }
            }

            queries::increment_send_access_count(&db, &send.uuid, &now).await?;

            let kv = ctx.data.kv()?;
            let signing_key = jwt::load_or_create_signing_key(&kv).await?;
            let token = jwt::create_send_access_token(&send_id, &file_id, &signing_key).await?;

            let domain = ctx.data.domain()?;
            let url = format!("{domain}/api/sends/{send_id}/{file_id}?t={token}");

            let resp = SendFileDownloadResponse {
                id: file_id,
                url,
                object: "send-fileDownload".into(),
            };
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

/// GET /api/sends/:send_id/:file_id?t=<jwt> — download a send file.
///
/// The `?t=` capability gates this endpoint because without it anyone who
/// knew (or guessed) the path could stream the R2 object, bypassing the
/// password / expiration / access-count checks done at mint time.
pub async fn get_send_file(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let send_id = ctx
                .param("send_id")
                .ok_or(AppError::BadRequest("Missing send_id".into()))?
                .clone();
            let file_id = ctx
                .param("file_id")
                .ok_or(AppError::BadRequest("Missing file_id".into()))?
                .clone();

            let url = req
                .url()
                .map_err(|e| AppError::Internal(format!("url parse: {e}")))?;
            let token = url
                .query_pairs()
                .find(|(k, _)| k == "t")
                .map(|(_, v)| v.to_string())
                .ok_or_else(|| AppError::Unauthorized("Missing download token".into()))?;

            let kv = ctx.data.kv()?;
            let public_key = jwt::load_public_key(&kv).await?;
            let claims: SendAccessClaims =
                jwt::verify_and_decode_jwt(&token, &public_key, jwt::TYPE_SEND_ACCESS)
                    .await
                    .map_err(|_| AppError::Unauthorized("Invalid download token".into()))?;
            if claims.sub != jwt::send_access_subject(&send_id, &file_id) {
                return Err(AppError::Unauthorized("Download token mismatch".into()));
            }

            let r2 = ctx.data.r2()?;
            let r2_key = format!("sends/{send_id}/{file_id}");
            let object = r2
                .get(&r2_key)
                .execute()
                .await
                .map_err(|e| AppError::Internal(format!("R2 get failed: {e}")))?
                .ok_or(AppError::NotFound("File not found".into()))?;

            let body = object
                .body()
                .ok_or(AppError::Internal("R2 object has no body".into()))?;

            let bytes = body
                .bytes()
                .await
                .map_err(|e| AppError::Internal(format!("R2 read failed: {e}")))?;

            let headers = worker::Headers::new();
            headers
                .set("Content-Type", "application/octet-stream")
                .map_err(|e| AppError::Internal(format!("Header error: {e}")))?;
            headers
                .set("Cache-Control", "no-store")
                .map_err(|e| AppError::Internal(format!("Header error: {e}")))?;

            Ok(Response::from_bytes(bytes)?.with_headers(headers))
        }
        .await,
    )
}

// --- Helpers ---

/// Check if a send is currently available (not expired, not deleted, not disabled, not over limit).
fn check_send_available(send: &DbSend, now: &str) -> crate::error::Result<()> {
    if send.disabled {
        return Err(AppError::NotFound(
            "Send does not exist or is no longer available".into(),
        ));
    }

    if let Some(exp) = &send.expiration_date
        && exp.as_str() <= now
    {
        return Err(AppError::NotFound(
            "Send does not exist or is no longer available".into(),
        ));
    }

    if send.deletion_date.as_str() <= now {
        return Err(AppError::NotFound(
            "Send does not exist or is no longer available".into(),
        ));
    }

    if let Some(max) = send.max_access_count
        && send.access_count >= max
    {
        return Err(AppError::NotFound(
            "Send does not exist or is no longer available".into(),
        ));
    }

    Ok(())
}

/// Hash a send password using PBKDF2, returning (hash, salt, iterations).
async fn hash_send_password(
    password: Option<&str>,
) -> crate::error::Result<(Option<String>, Option<String>, Option<i32>)> {
    match password {
        Some(pw) if !pw.is_empty() => {
            let salt = random::random_bytes(64)?;
            let hash =
                pbkdf2::pbkdf2_sha256(pw.as_bytes(), &salt, SEND_PASSWORD_ITERATIONS, 32).await?;
            Ok((
                Some(base64_encode(&hash)),
                Some(base64_encode(&salt)),
                Some(SEND_PASSWORD_ITERATIONS as i32),
            ))
        }
        _ => Ok((None, None, None)),
    }
}

/// Verify a password against a send's stored hash.
async fn verify_send_password(send: &DbSend, password: &str) -> crate::error::Result<bool> {
    let stored_hash = match &send.password_hash {
        Some(h) => crate::util::base64_decode(h)?,
        None => return Ok(true),
    };
    let salt = match &send.password_salt {
        Some(s) => crate::util::base64_decode(s)?,
        None => return Ok(false),
    };
    let iterations = send
        .password_iter
        .unwrap_or(SEND_PASSWORD_ITERATIONS as i32) as u32;

    let computed = pbkdf2::pbkdf2_sha256(password.as_bytes(), &salt, iterations, 32).await?;
    Ok(computed == stored_hash)
}

/// Extract the file ID from the send data JSON.
fn extract_file_id(data: &str) -> crate::error::Result<String> {
    let val: serde_json::Value = serde_json::from_str(data)
        .map_err(|e| AppError::Internal(format!("Invalid send data: {e}")))?;
    val.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or(AppError::Internal("Missing file id in send data".into()))
}

/// Format a byte size into a human-readable string.
fn format_size(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} Bytes")
    }
}
