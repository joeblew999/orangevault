use uuid::Uuid;

use crate::error::Result;

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
