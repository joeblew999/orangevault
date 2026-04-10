use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::models::Folder;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::folder::{FolderRequest, FolderResponse};
use crate::notifications::{self, UpdateType};
use crate::util::{generate_uuid, now_utc};

pub async fn get_folders(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let db = ctx.data.db()?;
            let folders = queries::find_folders_by_user(&db, &user.uuid).await?;
            let data: Vec<FolderResponse> = folders.iter().map(FolderResponse::from_db).collect();
            Ok(Response::from_json(&serde_json::json!({
                "Data": data,
                "Object": "list",
                "ContinuationToken": null,
            }))?)
        }
        .await,
    )
}

pub async fn post_folder(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: FolderRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let now = now_utc();
            let folder = Folder {
                uuid: generate_uuid(),
                user_uuid: user.uuid,
                name: body.name,
                created_at: now.clone(),
                updated_at: now,
            };

            let db = ctx.data.db()?;
            queries::insert_folder(&db, &folder).await?;

            notifications::send_notification(
                &ctx.env,
                &folder.user_uuid,
                UpdateType::SyncFolderCreate,
                &folder.uuid,
                serde_json::json!({"Id": folder.uuid, "RevisionDate": folder.updated_at}),
            )
            .await;

            let resp = FolderResponse::from_db(&folder);
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn put_folder(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let folder_id = ctx
                .param("id")
                .ok_or(AppError::BadRequest("Missing folder id".into()))?
                .clone();
            let body: FolderRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let mut folder = queries::find_folder_by_uuid(&db, &folder_id)
                .await?
                .ok_or(AppError::NotFound("Folder not found".into()))?;

            if folder.user_uuid != user.uuid {
                return Err(AppError::Forbidden("Not your folder".into()));
            }

            folder.name = body.name;
            folder.updated_at = now_utc();
            queries::update_folder(&db, &folder).await?;

            notifications::send_notification(
                &ctx.env,
                &folder.user_uuid,
                UpdateType::SyncFolderUpdate,
                &folder.uuid,
                serde_json::json!({"Id": folder.uuid, "RevisionDate": folder.updated_at}),
            )
            .await;

            let resp = FolderResponse::from_db(&folder);
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn delete_folder(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let folder_id = ctx
                .param("id")
                .ok_or(AppError::BadRequest("Missing folder id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let folder = queries::find_folder_by_uuid(&db, &folder_id)
                .await?
                .ok_or(AppError::NotFound("Folder not found".into()))?;

            if folder.user_uuid != user.uuid {
                return Err(AppError::Forbidden("Not your folder".into()));
            }

            queries::delete_folder(&db, &folder_id).await?;

            notifications::send_notification(
                &ctx.env,
                &user.uuid,
                UpdateType::SyncFolderDelete,
                &folder_id,
                serde_json::json!({"Id": folder_id}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}
