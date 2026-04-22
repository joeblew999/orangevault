use worker::{Env, Headers, Response, Result as WorkerResult};

const ALLOWED_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";
const ALLOWED_HEADERS: &str = "Authorization, Content-Type, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version";
const MAX_AGE: &str = "86400";

/// Echo `origin` only when it matches the configured DOMAIN. Returning `None`
/// makes the browser block the cross-origin call.
pub fn resolve_allowed_origin(env: &Env, origin: Option<&str>) -> Option<String> {
    let origin = origin?;
    let domain = env.var("DOMAIN").ok()?.to_string();
    let domain_origin = worker::Url::parse(&domain)
        .ok()
        .map(|u| u.origin().ascii_serialization())?;
    origin
        .eq_ignore_ascii_case(&domain_origin)
        .then(|| origin.to_string())
}

fn set_cors_headers(headers: &Headers, approved_origin: Option<&str>) -> WorkerResult<()> {
    if let Some(o) = approved_origin {
        headers.set("Access-Control-Allow-Origin", o)?;
        headers.set("Vary", "Origin")?;
        headers.set("Access-Control-Allow-Credentials", "true")?;
    }
    headers.set("Access-Control-Allow-Methods", ALLOWED_METHODS)?;
    headers.set("Access-Control-Allow-Headers", ALLOWED_HEADERS)?;
    Ok(())
}

pub fn apply_cors_headers(
    mut response: Response,
    approved_origin: Option<&str>,
) -> WorkerResult<Response> {
    set_cors_headers(response.headers_mut(), approved_origin)?;
    Ok(response)
}

pub fn preflight_response(approved_origin: Option<&str>) -> WorkerResult<Response> {
    let headers = Headers::new();
    set_cors_headers(&headers, approved_origin)?;
    headers.set("Access-Control-Max-Age", MAX_AGE)?;
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}
