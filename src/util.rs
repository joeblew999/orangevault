use uuid::Uuid;

use crate::error::{AppError, Result};
use worker::Request;

/// Upper bound we accept for uploaded file bodies (send files, cipher
/// attachments). Cloudflare Workers caps request bodies at 100 MB on the
/// paid tier anyway, but we want a deterministic 413 rather than whatever
/// the runtime decides to do with an over-sized payload. Also guards memory:
/// we read the whole body with `req.bytes()`.
pub const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024;

fn too_large() -> AppError {
    AppError::PayloadTooLarge(format!("Upload exceeds {MAX_UPLOAD_BYTES} byte limit"))
}

/// Reject a request before draining its body if the declared Content-Length
/// is already over the limit. Clients that omit the header fall through to
/// the post-read check.
pub fn enforce_content_length(req: &Request) -> Result<()> {
    let Ok(Some(cl)) = req.headers().get("Content-Length") else {
        return Ok(());
    };
    let Ok(n) = cl.parse::<usize>() else {
        return Ok(());
    };
    if n > MAX_UPLOAD_BYTES {
        return Err(too_large());
    }
    Ok(())
}

/// Post-read check: defends against clients that lie in (or omit) the
/// Content-Length header.
pub fn enforce_body_len(bytes: usize) -> Result<()> {
    if bytes > MAX_UPLOAD_BYTES {
        return Err(too_large());
    }
    Ok(())
}

/// Validate a client-declared file size (from a JSON body) against the
/// upload limit before we reserve storage or hand out an upload URL.
pub fn enforce_declared_size(size: i64) -> Result<()> {
    if size < 0 || (size as usize) > MAX_UPLOAD_BYTES {
        return Err(too_large());
    }
    Ok(())
}

pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn now_epoch_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// URL-safe base64 with no padding (for JWT).
pub fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn base64url_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| crate::error::AppError::BadRequest(format!("Invalid base64: {e}")))
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| crate::error::AppError::BadRequest(format!("Invalid base64: {e}")))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
