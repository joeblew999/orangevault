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
            let raw_domain = ctx
                .param("domain")
                .ok_or(AppError::BadRequest("Missing domain".into()))?
                .clone();

            // SSRF guard: only registrable hostnames — no userinfo, port, path, or IP literals.
            let domain = validate_icon_domain(&raw_domain)?;

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
            let parsed = worker::Url::parse(&url)
                .map_err(|_| AppError::BadRequest("Invalid domain URL".into()))?;
            // Re-check the parsed URL — Url::parse normalizes and may accept shapes our string check missed.
            if parsed.host_str() != Some(domain.as_str())
                || parsed.port().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.scheme() != "https"
            {
                return Err(AppError::BadRequest("Invalid domain URL".into()));
            }
            let fetch_resp = worker::Fetch::Url(parsed).send().await;

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

/// Reject anything that isn't a plain hostname. IDN must be punycoded;
/// a non-numeric TLD is required so IPv4 literals (`10.0.0.1`) are rejected.
fn validate_icon_domain(raw: &str) -> crate::error::Result<String> {
    const MAX_LEN: usize = 253;
    if raw.is_empty() || raw.len() > MAX_LEN {
        return Err(AppError::BadRequest("Invalid domain".into()));
    }
    let lower = raw.to_ascii_lowercase();
    let ok = lower
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !ok {
        return Err(AppError::BadRequest("Invalid domain".into()));
    }
    if lower.starts_with('.')
        || lower.ends_with('.')
        || lower.starts_with('-')
        || lower.contains("..")
    {
        return Err(AppError::BadRequest("Invalid domain".into()));
    }
    let Some((_, tld)) = lower.rsplit_once('.') else {
        return Err(AppError::BadRequest("Invalid domain".into()));
    };
    if tld.is_empty() || tld.chars().all(|c| c.is_ascii_digit()) {
        // All-numeric TLD means this is really an IPv4 literal (e.g. 10.0.0.1).
        return Err(AppError::BadRequest("Invalid domain".into()));
    }
    const DENY_SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".internal",
        ".intranet",
        ".cluster.local",
    ];
    if lower == "localhost" || DENY_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return Err(AppError::BadRequest("Invalid domain".into()));
    }
    Ok(lower)
}
