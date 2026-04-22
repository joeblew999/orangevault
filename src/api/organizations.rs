use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::models::{Collection, Membership, Organization};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::organization::{
    CollectionCreateRequest, CollectionResponse, CollectionSelectionResponse, ConfirmRequest,
    InviteRequest, MemberResponse, OrgCreateRequest, OrganizationResponse, PolicyRequest,
    PolicyResponse, ShareCipherRequest, UpdateCollectionRequest, UpdateMemberRequest,
};
use crate::notifications::{self, UpdateType};
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
                    collections: None,
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

// --- Member management ---

pub async fn invite_member(
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
            let body: InviteRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            for email in &body.emails {
                let email = email.trim().to_lowercase();
                if email.is_empty() {
                    continue;
                }

                // No SMTP, so invitees must already exist — we can't route an invite token to them otherwise.
                let Some(existing_user) = queries::find_user_by_email(&db, &email).await? else {
                    return Err(AppError::BadRequest(format!(
                        "User {email} has not registered yet — ask them to create an account before inviting."
                    )));
                };
                let user_uuid = existing_user.uuid.clone();

                // Check if already has a membership
                if queries::find_membership(&db, &user_uuid, &org_id)
                    .await?
                    .is_some()
                {
                    continue; // Skip duplicate invites
                }

                let membership = Membership {
                    uuid: generate_uuid(),
                    user_uuid,
                    org_uuid: org_id.clone(),
                    akey: None,
                    atype: body.r#type,
                    status: 1, // Accepted — admin must still Confirm (status 2).
                    access_all: body.access_all,
                    external_id: None,
                    reset_password_key: None,
                };
                queries::insert_membership(&db, &membership).await?;

                // Set collection access
                for col in &body.collections {
                    queries::set_user_collection(
                        &db,
                        &membership.user_uuid,
                        &col.id,
                        col.read_only,
                        col.hide_passwords,
                        col.manage,
                    )
                    .await?;
                }
            }

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn accept_invite(
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
            let member_id = ctx
                .param("member_id")
                .ok_or(AppError::BadRequest("Missing member_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let membership = queries::find_membership_by_uuid(&db, &member_id)
                .await?
                .ok_or(AppError::NotFound("Membership not found".into()))?;

            if membership.org_uuid != org_id {
                return Err(AppError::NotFound("Membership not found".into()));
            }
            if membership.user_uuid != user.uuid {
                return Err(AppError::Forbidden("Not your invitation".into()));
            }
            if membership.status != 0 && membership.status != 1 {
                return Err(AppError::BadRequest("Already accepted".into()));
            }

            queries::update_membership_status_and_key(&db, &member_id, 1, None).await?;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn confirm_member(
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
            let member_id = ctx
                .param("member_id")
                .ok_or(AppError::BadRequest("Missing member_id".into()))?
                .clone();
            let body: ConfirmRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let membership = queries::find_membership_by_uuid(&db, &member_id)
                .await?
                .ok_or(AppError::NotFound("Membership not found".into()))?;

            if membership.org_uuid != org_id {
                return Err(AppError::NotFound("Membership not found".into()));
            }
            if membership.status != 1 {
                return Err(AppError::BadRequest(
                    "Member must be in Accepted state to confirm".into(),
                ));
            }

            queries::update_membership_status_and_key(&db, &member_id, 2, Some(&body.key)).await?;

            notifications::send_notification(
                &ctx.env,
                &membership.user_uuid,
                UpdateType::SyncVault,
                &org_id,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn get_member(
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
            let member_id = ctx
                .param("member_id")
                .ok_or(AppError::BadRequest("Missing member_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            require_member(&db, &user.uuid, &org_id).await?;

            let membership = queries::find_membership_by_uuid(&db, &member_id)
                .await?
                .ok_or(AppError::NotFound("Membership not found".into()))?;

            if membership.org_uuid != org_id {
                return Err(AppError::NotFound("Membership not found".into()));
            }

            let member_user = queries::find_user_by_uuid(&db, &membership.user_uuid).await?;

            // Get collection access
            let user_collections =
                queries::find_user_collections_by_user(&db, &membership.user_uuid).await?;
            let org_collections = queries::find_collections_by_org(&db, &org_id).await?;
            let org_col_uuids: Vec<&str> =
                org_collections.iter().map(|c| c.uuid.as_str()).collect();
            let collections: Vec<CollectionSelectionResponse> = user_collections
                .iter()
                .filter(|uc| org_col_uuids.contains(&uc.collection_uuid.as_str()))
                .map(|uc| CollectionSelectionResponse {
                    id: uc.collection_uuid.clone(),
                    read_only: uc.read_only,
                    hide_passwords: uc.hide_passwords,
                    manage: uc.manage,
                })
                .collect();

            let resp = MemberResponse {
                id: membership.uuid,
                user_id: membership.user_uuid,
                name: member_user.as_ref().map(|u| u.name.clone()),
                email: member_user.map(|u| u.email),
                r#type: membership.atype,
                status: membership.status,
                access_all: membership.access_all,
                collections: Some(collections),
                object: "organizationUser".into(),
            };

            Ok(Response::from_json(&resp)?)
        }
        .await,
    )
}

pub async fn update_member(
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
            let member_id = ctx
                .param("member_id")
                .ok_or(AppError::BadRequest("Missing member_id".into()))?
                .clone();
            let body: UpdateMemberRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let requester = require_admin(&db, &user.uuid, &org_id).await?;

            let membership = queries::find_membership_by_uuid(&db, &member_id)
                .await?
                .ok_or(AppError::NotFound("Membership not found".into()))?;

            if membership.org_uuid != org_id {
                return Err(AppError::NotFound("Membership not found".into()));
            }

            // Only Owners can edit other Owners, and only Owners can grant or
            // revoke Owner/Admin privileges. Admins editing lower-privileged
            // roles (User/Manager) stays allowed.
            if membership.atype == 0 && requester.atype != 0 {
                return Err(AppError::Forbidden(
                    "Only Owners can edit Owner users".into(),
                ));
            }
            if body.r#type != membership.atype
                && (membership.atype <= 1 || body.r#type <= 1)
                && requester.atype != 0
            {
                return Err(AppError::Forbidden(
                    "Only Owners can grant or remove Owner or Admin privileges".into(),
                ));
            }

            // Prevent demoting the last owner
            if membership.atype == 0 && body.r#type != 0 {
                let owner_count = queries::count_org_owners(&db, &org_id).await?;
                if owner_count <= 1 {
                    return Err(AppError::BadRequest("Cannot demote the last owner".into()));
                }
            }

            queries::update_membership(&db, &member_id, body.r#type, body.access_all).await?;

            queries::clear_user_collections_for_user_in_org(&db, &membership.user_uuid, &org_id)
                .await?;
            for col in &body.collections {
                queries::set_user_collection(
                    &db,
                    &membership.user_uuid,
                    &col.id,
                    col.read_only,
                    col.hide_passwords,
                    col.manage,
                )
                .await?;
            }

            notifications::send_notification(
                &ctx.env,
                &membership.user_uuid,
                UpdateType::SyncVault,
                &org_id,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn remove_member(
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
            let member_id = ctx
                .param("member_id")
                .ok_or(AppError::BadRequest("Missing member_id".into()))?
                .clone();

            let db = ctx.data.db()?;
            let requester = require_admin(&db, &user.uuid, &org_id).await?;

            let membership = queries::find_membership_by_uuid(&db, &member_id)
                .await?
                .ok_or(AppError::NotFound("Membership not found".into()))?;

            if membership.org_uuid != org_id {
                return Err(AppError::NotFound("Membership not found".into()));
            }

            // Only Owners may remove other Owners.
            if membership.atype == 0 && requester.atype != 0 {
                return Err(AppError::Forbidden(
                    "Only Owners can remove Owner users".into(),
                ));
            }

            // Prevent removing the last owner
            if membership.atype == 0 {
                let owner_count = queries::count_org_owners(&db, &org_id).await?;
                if owner_count <= 1 {
                    return Err(AppError::BadRequest("Cannot remove the last owner".into()));
                }
            }

            let removed_user_uuid = membership.user_uuid.clone();
            queries::delete_membership(&db, &member_id, &org_id, &removed_user_uuid).await?;

            notifications::send_notification(
                &ctx.env,
                &removed_user_uuid,
                UpdateType::SyncVault,
                &org_id,
                serde_json::json!({}),
            )
            .await;

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn reinvite_member(
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
            require_admin(&db, &user.uuid, &org_id).await?;

            // No-op: we don't send emails, but return success for client compatibility
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

// --- Collection management ---

pub async fn update_collection(
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
            let col_id = ctx
                .param("col_id")
                .ok_or(AppError::BadRequest("Missing col_id".into()))?
                .clone();
            let body: UpdateCollectionRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let col = queries::find_collection_by_uuid(&db, &col_id)
                .await?
                .ok_or(AppError::NotFound("Collection not found".into()))?;
            if col.org_uuid != org_id {
                return Err(AppError::Forbidden("Collection not in this org".into()));
            }

            queries::update_collection_name(&db, &col_id, &body.name, &body.external_id).await?;

            // Update user access if provided
            if !body.users.is_empty() {
                queries::clear_user_collections_for_collection(&db, &col_id).await?;
                for u in &body.users {
                    queries::set_user_collection(
                        &db,
                        &u.id,
                        &col_id,
                        u.read_only,
                        u.hide_passwords,
                        u.manage,
                    )
                    .await?;
                }
            }

            let updated_col = Collection {
                uuid: col_id,
                org_uuid: org_id,
                name: body.name,
                external_id: body.external_id,
            };
            Ok(Response::from_json(&CollectionResponse::from_db(
                &updated_col,
            ))?)
        }
        .await,
    )
}

pub async fn get_collection_users(
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
            require_member(&db, &user.uuid, &org_id).await?;

            let col = queries::find_collection_by_uuid(&db, &col_id)
                .await?
                .ok_or(AppError::NotFound("Collection not found".into()))?;
            if col.org_uuid != org_id {
                return Err(AppError::Forbidden("Collection not in this org".into()));
            }

            let user_collections =
                queries::find_user_collections_by_collection(&db, &col_id).await?;
            let data: Vec<CollectionSelectionResponse> = user_collections
                .iter()
                .map(|uc| CollectionSelectionResponse {
                    id: uc.user_uuid.clone(),
                    read_only: uc.read_only,
                    hide_passwords: uc.hide_passwords,
                    manage: uc.manage,
                })
                .collect();

            Ok(Response::from_json(&data)?)
        }
        .await,
    )
}

pub async fn set_collection_users(
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
            let col_id = ctx
                .param("col_id")
                .ok_or(AppError::BadRequest("Missing col_id".into()))?
                .clone();
            let body: Vec<crate::models::organization::CollectionSelection> = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let col = queries::find_collection_by_uuid(&db, &col_id)
                .await?
                .ok_or(AppError::NotFound("Collection not found".into()))?;
            if col.org_uuid != org_id {
                return Err(AppError::Forbidden("Collection not in this org".into()));
            }

            queries::clear_user_collections_for_collection(&db, &col_id).await?;
            for u in &body {
                queries::set_user_collection(
                    &db,
                    &u.id,
                    &col_id,
                    u.read_only,
                    u.hide_passwords,
                    u.manage,
                )
                .await?;
            }

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

// --- Organization Policies ---

pub async fn get_policies(
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

            let policies = queries::find_policies_by_org(&db, &org_id).await?;
            let data: Vec<PolicyResponse> = policies
                .iter()
                .map(|p| PolicyResponse {
                    id: p.uuid.clone(),
                    organization_id: p.org_uuid.clone(),
                    r#type: p.atype,
                    data: p.data.as_ref().and_then(|d| serde_json::from_str(d).ok()),
                    enabled: p.enabled,
                    object: "policy".into(),
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

pub async fn put_policy(
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
            let policy_type: i32 = ctx
                .param("type")
                .ok_or(AppError::BadRequest("Missing policy type".into()))?
                .parse()
                .map_err(|_| AppError::BadRequest("Invalid policy type".into()))?;

            let body: PolicyRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            require_admin(&db, &user.uuid, &org_id).await?;

            let existing = queries::find_policy_by_org_and_type(&db, &org_id, policy_type).await?;
            let uuid = existing.map(|p| p.uuid).unwrap_or_else(generate_uuid);

            let data_str = body.data.as_ref().map(|d| d.to_string());

            let policy = crate::db::models::OrgPolicy {
                uuid: uuid.clone(),
                org_uuid: org_id.clone(),
                atype: policy_type,
                enabled: body.enabled,
                data: data_str.clone(),
            };
            queries::upsert_policy(&db, &policy).await?;

            Ok(Response::from_json(&PolicyResponse {
                id: uuid,
                organization_id: org_id,
                r#type: policy_type,
                data: body.data,
                enabled: body.enabled,
                object: "policy".into(),
            })?)
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
