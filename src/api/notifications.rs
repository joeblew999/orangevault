use worker::{Request, Response, RouteContext};

use crate::auth::guards::validate_access_token;
use crate::config::RequestContext;
use crate::error::{self, AppError};
use crate::notifications;

/// GET /notifications/hub — WebSocket upgrade, routed to user's Durable Object.
/// Auth via query param `?access_token=<jwt>` or Authorization header.
pub async fn hub(req: Request, ctx: RouteContext<RequestContext>) -> worker::Result<Response> {
    error::into_response(
        async {
            // Extract token from query param or Authorization header
            let url = req
                .url()
                .map_err(|e| AppError::Internal(format!("url: {e}")))?;
            let token = url
                .query_pairs()
                .find(|(k, _)| k == "access_token")
                .map(|(_, v)| v.to_string())
                .or_else(|| {
                    req.headers()
                        .get("Authorization")
                        .ok()
                        .flatten()
                        .and_then(|h| h.strip_prefix("Bearer ").map(|t| t.to_string()))
                })
                .ok_or_else(|| AppError::Unauthorized("Missing access token".into()))?;

            let kv = ctx.data.kv()?;
            let user = validate_access_token(&format!("Bearer {token}"), &kv).await?;

            // Route to user's Durable Object
            let ns = ctx
                .env
                .durable_object(notifications::DO_BINDING)
                .map_err(|e| AppError::Internal(format!("DO binding: {e}")))?;
            let stub = ns
                .id_from_name(&user.uuid)
                .map_err(|e| AppError::Internal(format!("DO id: {e}")))?
                .get_stub()
                .map_err(|e| AppError::Internal(format!("DO stub: {e}")))?;

            // Forward the original request directly — it already has the WebSocket
            // upgrade headers. The DO distinguishes WS upgrades from /notify by header.
            stub.fetch_with_request(req)
                .await
                .map_err(|e| AppError::Internal(format!("DO fetch: {e}")))
        }
        .await,
    )
}
