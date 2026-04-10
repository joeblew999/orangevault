use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::models::{Collection, Membership, Organization};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::organization::{
    CollectionCreateRequest, CollectionResponse, MemberResponse, OrgCreateRequest,
    OrganizationResponse, ShareCipherRequest,
};
use crate::util::{generate_uuid, now_utc};

/// Require the user to be an admin or owner of the org. Returns the membership.
async fn require_admin(
    db: &worker::D1Database,
    user_uuid: &str,
    org_uuid: &str,
) -> crate::error::Result<Membership> {
    let m = require_member(db, user_uuid, org_uuid).await?;
    if m.atype > 1 {
        return Err(AppError::Forbidden("Admin access required".into()));
    }
    Ok(m)
}

/// Require confirmed membership (any role).
async fn require_member(
    db: &worker::D1Database,
    user_uuid: &str,
    org_uuid: &str,
) -> crate::error::Result<Membership> {
    let m = queries::find_membership(db, user_uuid, org_uuid)
        .await?
        .ok_or(AppError::Forbidden("Not a member".into()))?;
    if m.status != 2 {
        return Err(AppError::Forbidden("Membership not confirmed".into()));
    }
    Ok(m)
}

// --- Organization CRUD ---

pub async fn post_organization(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let body: OrgCreateRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let org = Organization {
                uuid: generate_uuid(),
                name: body.name,
                billing_email: body.billing_email,
                private_key: body.keys.as_ref().map(|k| k.encrypted_private_key.clone()),
                public_key: body.keys.as_ref().map(|k| k.public_key.clone()),
            };

            let db = ctx.data.db()?;
            queries::insert_organization(&db, &org).await?;

            let membership = Membership {
                uuid: generate_uuid(),
                user_uuid: user.uuid.clone(),
                org_uuid: org.uuid.clone(),
                akey: Some(body.key),
                atype: 0,  // Owner
                status: 2, // Confirmed
                access_all: true,
                external_id: None,
                reset_password_key: None,
            };
            queries::insert_membership(&db, &membership).await?;

            if let Some(col_name) = body.collection_name
                && !col_name.is_empty()
            {
                let col = Collection {
                    uuid: generate_uuid(),
                    org_uuid: org.uuid.clone(),
                    name: col_name,
                    external_id: None,
                };
                queries::insert_collection(&db, &col).await?;
                queries::set_user_collection(&db, &user.uuid, &col.uuid, false, false, true)
                    .await?;
            }

            let resp = OrganizationResponse::from_db(&org);
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn get_organization(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            require_member(&db, &user.uuid, &org_id).await?;

            let org = queries::find_organization_by_uuid(&db, &org_id)
                .await?
                .ok_or(AppError::NotFound("Organization not found".into()))?;

            Ok(Response::from_json(&OrganizationResponse::from_db(&org))?)
        }
        .await,
    )
}

pub async fn delete_organization(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let m = require_admin(&db, &user.uuid, &org_id).await?;
            if m.atype != 0 {
                return Err(AppError::Forbidden("Only owner can delete".into()));
            }

            queries::delete_organization(&db, &org_id).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

// --- Collections ---

pub async fn get_collections(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            require_member(&db, &user.uuid, &org_id).await?;

            let collections = queries::find_collections_by_org(&db, &org_id).await?;
            let data: Vec<CollectionResponse> = collections
                .iter()
                .map(CollectionResponse::from_db)
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

pub async fn post_collection(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();
            let body: CollectionCreateRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let col = Collection {
                uuid: generate_uuid(),
                org_uuid: org_id,
                name: body.name,
                external_id: body.external_id,
            };
            queries::insert_collection(&db, &col).await?;
            queries::set_user_collection(&db, &user.uuid, &col.uuid, false, false, true).await?;

            Ok(Response::from_json(&CollectionResponse::from_db(&col))?)
        }
        .await,
    )
}

pub async fn delete_collection(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();
            let col_id = ctx
                .param("col_id")
                .ok_or(AppError::BadRequest("Missing col_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let col = queries::find_collection_by_uuid(&db, &col_id)
                .await?
                .ok_or(AppError::NotFound("Collection not found".into()))?;
            if col.org_uuid != org_id {
                return Err(AppError::Forbidden("Collection not in this org".into()));
            }

            queries::delete_collection(&db, &col_id).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

// --- Members ---

pub async fn get_members(
    req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let org_id = ctx
                .param("org_id")
                .ok_or(AppError::BadRequest("Missing org_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            require_member(&db, &user.uuid, &org_id).await?;

            let memberships = queries::find_memberships_by_org(&db, &org_id).await?;
            let mut data = Vec::new();
            for m in &memberships {
                let u = queries::find_user_by_uuid(&db, &m.user_uuid).await?;
                data.push(MemberResponse {
                    id: m.uuid.clone(),
                    user_id: m.user_uuid.clone(),
                    name: u.as_ref().map(|u| u.name.clone()),
                    email: u.map(|u| u.email),
                    r#type: m.atype,
                    status: m.status,
                    access_all: m.access_all,
                    object: "organizationUser".into(),
                });
            }

            Ok(Response::from_json(&serde_json::json!({
                "Data": data,
                "Object": "list",
                "ContinuationToken": null,
            }))?)
        }
        .await,
    )
}

// --- Cipher sharing ---

pub async fn share_cipher(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let cipher_id = ctx
                .param("id")
                .ok_or(AppError::BadRequest("Missing cipher id".into()))?
                .clone();
            let body: ShareCipherRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;

            let mut cipher = queries::find_cipher_by_uuid(&db, &cipher_id)
                .await?
                .ok_or(AppError::NotFound("Cipher not found".into()))?;
            if cipher.user_uuid.as_deref() != Some(&user.uuid) {
                return Err(AppError::Forbidden("Not your cipher".into()));
            }

            let org_uuid = body
                .cipher
                .organization_id
                .as_ref()
                .ok_or(AppError::BadRequest("Organization ID is required".into()))?;

            require_member(&db, &user.uuid, org_uuid).await?;

            let now = now_utc();
            queries::share_cipher_to_org(
                &db,
                &cipher_id,
                org_uuid,
                &body.cipher.data_json(),
                &body.cipher.name,
                body.cipher.key.as_deref(),
                &now,
            )
            .await?;

            queries::clear_cipher_collections(&db, &cipher_id).await?;
            for col_id in &body.collection_ids {
                queries::set_cipher_collection(&db, &cipher_id, col_id).await?;
            }

            // Update local struct instead of re-fetching
            cipher.user_uuid = None;
            cipher.organization_uuid = Some(org_uuid.clone());
            cipher.data = body.cipher.data_json();
            cipher.name = body.cipher.name.clone();
            cipher.key = body.cipher.key.clone();
            cipher.updated_at = now;

            let resp = crate::models::cipher::CipherResponse::from_cipher_resolved(
                &cipher,
                false,
                None,
                body.collection_ids.clone(),
            );
            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}
