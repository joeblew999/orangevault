use worker::kv::KvStore;

use crate::error::{AppError, Result};

use super::claims::LoginClaims;
use super::jwt;

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

/// Validate an access token and return the authenticated user.
pub async fn validate_access_token(auth_header: &str, kv: &KvStore) -> Result<AuthenticatedUser> {
    let token = extract_bearer_token(auth_header)?;
    let public_key = jwt::load_public_key(kv).await?;
    let claims: LoginClaims = jwt::verify_and_decode_jwt(token, &public_key).await?;

    Ok(AuthenticatedUser {
        uuid: claims.sub,
        email: claims.email,
        name: claims.name,
        premium: claims.premium,
        security_stamp: claims.sstamp,
        device_uuid: claims.device,
        scope: claims.scope,
    })
}
