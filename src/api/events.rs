use serde::{Deserialize, Serialize};
use worker::{Request, Response, RouteContext};

use crate::auth::guards::auth_from_request;
use crate::config::RequestContext;
use crate::db::models::Event;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::util::{generate_uuid, now_utc};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventCollectItem {
    r#type: i32,
    cipher_id: Option<String>,
    date: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct EventResponse {
    r#type: i32,
    user_id: Option<String>,
    organization_id: Option<String>,
    cipher_id: Option<String>,
    collection_id: Option<String>,
    group_id: Option<String>,
    acting_user_id: Option<String>,
    date: String,
    device_type: Option<i32>,
    ip_address: Option<String>,
    object: String,
}

/// POST /api/collect — Client sends a batch of events.
pub async fn collect_events(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let user = auth_from_request(&req, &ctx.data).await?;
            let items: Vec<EventCollectItem> = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let db = ctx.data.db()?;
            let now = now_utc();

            for item in &items {
                let event = Event {
                    uuid: generate_uuid(),
                    event_type: item.r#type,
                    user_uuid: Some(user.uuid.clone()),
                    org_uuid: None,
                    cipher_uuid: item.cipher_id.clone(),
                    collection_uuid: None,
                    group_uuid: None,
                    member_uuid: None,
                    act_user_uuid: Some(user.uuid.clone()),
                    device_type: None,
                    ip_address: None,
                    event_date: item.date.clone().unwrap_or_else(|| now.clone()),
                };
                queries::insert_event(&db, &event).await?;
            }

            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

/// GET /api/organizations/:org_id/events — Query org events.
pub async fn get_org_events(
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

            let membership = queries::find_membership(&db, &user.uuid, &org_id)
                .await?
                .ok_or(AppError::Forbidden("Not a member".into()))?;
            if membership.status != 2 {
                return Err(AppError::Forbidden("Membership not confirmed".into()));
            }

            let url = req.url()?;
            let params: std::collections::HashMap<String, String> = url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            let default_start = "2000-01-01T00:00:00.000Z".to_string();
            let default_end = "2099-12-31T23:59:59.999Z".to_string();
            let start = params.get("start").unwrap_or(&default_start);
            let end = params.get("end").unwrap_or(&default_end);

            let events = queries::find_events_by_org(&db, &org_id, start, end).await?;

            let data: Vec<EventResponse> = events
                .iter()
                .map(|e| EventResponse {
                    r#type: e.event_type,
                    user_id: e.user_uuid.clone(),
                    organization_id: e.org_uuid.clone(),
                    cipher_id: e.cipher_uuid.clone(),
                    collection_id: e.collection_uuid.clone(),
                    group_id: e.group_uuid.clone(),
                    acting_user_id: e.act_user_uuid.clone(),
                    date: e.event_date.clone(),
                    device_type: e.device_type,
                    ip_address: e.ip_address.clone(),
                    object: "event".into(),
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
