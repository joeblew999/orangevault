use worker::{Request, Response, RouteContext};

use crate::config::RequestContext;
use crate::error::{self, AppError};

/// The server origin anchors the FIDO2 trusted-facets list so credentials
/// are scoped to this deployment; the hard-coded mobile app facets match
/// the official Bitwarden iOS and Android clients.
pub async fn get_app_id(
    _req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            if !ctx.data.web_vault_enabled() {
                return Err(AppError::NotFound("Web vault disabled".into()));
            }

            let origin = ctx.data.domain_origin()?;
            let body = serde_json::json!({
                "trustedFacets": [{
                    "version": { "major": 1, "minor": 0 },
                    "ids": [
                        origin,
                        "ios:bundle-id:com.8bit.bitwarden",
                        "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI",
                        "android:apk-key-hash:-UqPJA7QUVi4M_F4UQDyI8AtQwE",
                    ]
                }]
            });

            let mut resp = Response::from_json(&body)?;
            resp.headers_mut()
                .set("Content-Type", "application/fido.trusted-apps+json")?;
            Ok(resp)
        }
        .await,
    )
}
