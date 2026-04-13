use worker::{Request, Response, RouteContext};

use crate::config::RequestContext;
use crate::error::{self, AppError};

/// GET /icons/:domain/icon.png — Fetch and cache favicon for a domain.
pub async fn get_icon(
    _req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let domain = ctx
                .param("domain")
                .ok_or(AppError::BadRequest("Missing domain".into()))?
                .clone();

            // Basic domain validation
            if domain.contains('/')
                || domain.contains('\\')
                || domain.contains(' ')
                || !domain.contains('.')
            {
                return Err(AppError::BadRequest("Invalid domain".into()));
            }

            let kv = ctx.data.kv()?;
            let cache_key = format!("icon:{domain}");

            // Check KV cache first
            if let Ok(Some(cached)) = kv.get(&cache_key).bytes().await {
                let mut resp = Response::from_bytes(cached)?;
                resp.headers_mut().set("Content-Type", "image/x-icon").ok();
                resp.headers_mut()
                    .set("Cache-Control", "public, max-age=604800")
                    .ok();
                return Ok(resp);
            }

            // Try fetching the favicon
            let url = format!("https://{domain}/favicon.ico");
            let fetch_resp = worker::Fetch::Url(
                worker::Url::parse(&url)
                    .map_err(|_| AppError::BadRequest("Invalid domain URL".into()))?,
            )
            .send()
            .await;

            match fetch_resp {
                Ok(mut resp) if resp.status_code() == 200 => {
                    if let Ok(bytes) = resp.bytes().await {
                        if let Ok(builder) = kv.put_bytes(&cache_key, &bytes) {
                            let _ = builder.expiration_ttl(604800).execute().await;
                        }

                        let mut icon_resp = Response::from_bytes(bytes)?;
                        icon_resp
                            .headers_mut()
                            .set("Content-Type", "image/x-icon")
                            .ok();
                        icon_resp
                            .headers_mut()
                            .set("Cache-Control", "public, max-age=604800")
                            .ok();
                        return Ok(icon_resp);
                    }
                    Err(AppError::NotFound("Failed to read icon".into()))
                }
                _ => Err(AppError::NotFound("Icon not found".into())),
            }
        }
        .await,
    )
}
