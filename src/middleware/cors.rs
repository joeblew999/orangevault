use worker::{Headers, Response, Result as WorkerResult};

const ALLOWED_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";
const ALLOWED_HEADERS: &str = "Authorization, Content-Type, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version";
const MAX_AGE: &str = "86400";

fn set_cors_headers(headers: &Headers, origin: Option<&str>) -> WorkerResult<()> {
    let origin_value = origin.unwrap_or("*");
    headers.set("Access-Control-Allow-Origin", origin_value)?;
    headers.set("Access-Control-Allow-Methods", ALLOWED_METHODS)?;
    headers.set("Access-Control-Allow-Headers", ALLOWED_HEADERS)?;
    // Only set credentials header when a specific origin is echoed back;
    // browsers reject Access-Control-Allow-Credentials with wildcard origin.
    if origin.is_some() {
        headers.set("Access-Control-Allow-Credentials", "true")?;
    }
    Ok(())
}

pub fn apply_cors_headers(mut response: Response, origin: Option<&str>) -> WorkerResult<Response> {
    set_cors_headers(response.headers_mut(), origin)?;
    Ok(response)
}

/// Build a 204 No Content response for OPTIONS preflight requests.
pub fn preflight_response(origin: Option<&str>) -> WorkerResult<Response> {
    let headers = Headers::new();
    set_cors_headers(&headers, origin)?;
    headers.set("Access-Control-Max-Age", MAX_AGE)?;
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}
