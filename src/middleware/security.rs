use worker::{Response, Result as WorkerResult};

/// Stamp defense-in-depth headers on every non-WebSocket response.
/// The Worker also serves the static web vault, so CSP frame-ancestors blocks
/// clickjacking and HSTS locks it to HTTPS.
pub fn apply_security_headers(mut response: Response) -> WorkerResult<Response> {
    let headers = response.headers_mut();
    headers.set(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    )?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("Referrer-Policy", "no-referrer")?;
    headers.set("X-Frame-Options", "DENY")?;
    headers.set("Content-Security-Policy", "frame-ancestors 'none'")?;
    Ok(response)
}
