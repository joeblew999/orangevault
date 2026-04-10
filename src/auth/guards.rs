use crate::error::{AppError, Result};

/// Represents an authenticated user extracted from a valid JWT.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub premium: bool,
    pub security_stamp: String,
    pub device_uuid: String,
    pub scope: Vec<String>,
}

/// Extract the Bearer token from an Authorization header value.
pub fn extract_bearer_token(auth_header: &str) -> Result<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized(
            "Invalid authorization header".into(),
        ))
}
