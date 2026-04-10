use worker::Request;
use worker::kv::KvStore;

use crate::config::RequestContext;
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

/// Extract the authenticated user from a request using the RequestContext.
pub async fn auth_from_request(req: &Request, ctx: &RequestContext) -> Result<AuthenticatedUser> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .map_err(|_| AppError::Unauthorized("Missing Authorization header".into()))?
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;
    let kv = ctx.kv()?;
    validate_access_token(&auth_header, &kv).await
}

/// Verify a master password hash against the stored hash for a user.
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid.
pub async fn verify_master_password(
    user: &crate::db::models::User,
    master_password_hash: &str,
) -> Result<bool> {
    let salt = crate::util::base64_decode(&user.salt)?;
    let computed = crate::crypto::pbkdf2::pbkdf2_sha256(
        master_password_hash.as_bytes(),
        &salt,
        user.password_iterations,
        32,
    )
    .await?;
    let stored = crate::util::base64_decode(&user.password_hash)?;
    Ok(computed == stored)
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
