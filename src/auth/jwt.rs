use serde::Serialize;
use serde::de::DeserializeOwned;
use worker::kv::KvStore;

use crate::crypto::rsa;
use crate::db::models::User;
use crate::error::{AppError, Result};
use crate::util::{base64url_decode, base64url_encode, generate_uuid, now_epoch_secs};

use super::claims::{LoginClaims, RefreshClaims, RegisterVerifyClaims};

const KV_PRIVATE_KEY: &str = "RSA_PRIVATE_KEY";
const KV_PUBLIC_KEY: &str = "RSA_PUBLIC_KEY";
const JWT_HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
pub const ACCESS_TOKEN_EXPIRY: i64 = 7_200; // 2 hours
const REFRESH_TOKEN_EXPIRY: i64 = 2_592_000; // 30 days
const REGISTER_VERIFY_EXPIRY: i64 = 1_800; // 30 minutes

/// Load the RSA private key from KV, or generate and store a new pair.
pub async fn load_or_create_signing_key(kv: &KvStore) -> Result<web_sys::CryptoKey> {
    // Try loading existing key
    let existing = kv
        .get(KV_PRIVATE_KEY)
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("KV get private key: {e}")))?;

    if let Some(jwk_json) = existing {
        return rsa::import_private_key_jwk(&jwk_json).await;
    }

    // Generate new key pair
    let pair = rsa::generate_rsa_keypair().await?;
    let private_key: web_sys::CryptoKey = js_sys::Reflect::get(&pair, &"privateKey".into())
        .map_err(|e| AppError::Internal(format!("get privateKey: {e:?}")))?
        .into();
    let public_key: web_sys::CryptoKey = js_sys::Reflect::get(&pair, &"publicKey".into())
        .map_err(|e| AppError::Internal(format!("get publicKey: {e:?}")))?
        .into();

    // Export and store
    let priv_jwk = rsa::export_key_jwk(&private_key).await?;
    let pub_jwk = rsa::export_key_jwk(&public_key).await?;

    kv.put(KV_PRIVATE_KEY, &priv_jwk)
        .map_err(|e| AppError::Internal(format!("KV put private key: {e}")))?
        .execute()
        .await
        .map_err(|e| AppError::Internal(format!("KV put private key exec: {e}")))?;

    kv.put(KV_PUBLIC_KEY, &pub_jwk)
        .map_err(|e| AppError::Internal(format!("KV put public key: {e}")))?
        .execute()
        .await
        .map_err(|e| AppError::Internal(format!("KV put public key exec: {e}")))?;

    Ok(private_key)
}

/// Load the RSA public key from KV.
pub async fn load_public_key(kv: &KvStore) -> Result<web_sys::CryptoKey> {
    let jwk_json = kv
        .get(KV_PUBLIC_KEY)
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("KV get public key: {e}")))?
        .ok_or_else(|| AppError::Internal("RSA public key not found in KV".into()))?;
    rsa::import_public_key_jwk(&jwk_json).await
}

/// Sign a JWT with RS256 using the given private key.
pub async fn sign_jwt(claims: &impl Serialize, private_key: &web_sys::CryptoKey) -> Result<String> {
    let header_b64 = base64url_encode(JWT_HEADER.as_bytes());
    let claims_json = serde_json::to_vec(claims)
        .map_err(|e| AppError::Internal(format!("serialize claims: {e}")))?;
    let claims_b64 = base64url_encode(&claims_json);

    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = rsa::rsa_sign(private_key, signing_input.as_bytes()).await?;
    let sig_b64 = base64url_encode(&signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify and decode a JWT.
///
/// `expected_type` is matched against the `type` claim before deserialization
/// so a refresh token can't masquerade as an access token (or vice versa)
/// even if the target struct happens to accept the same required fields.
/// `iss` and `nbf` are always enforced against `ISSUER` / wall-clock time.
pub async fn verify_and_decode_jwt<T: DeserializeOwned>(
    token: &str,
    public_key: &web_sys::CryptoKey,
    expected_type: &str,
) -> Result<T> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Malformed JWT".into()));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = base64url_decode(parts[2])?;

    let valid = rsa::rsa_verify(public_key, signing_input.as_bytes(), &signature).await?;
    if !valid {
        return Err(AppError::Unauthorized("Invalid JWT signature".into()));
    }

    let claims_bytes = base64url_decode(parts[1])?;

    let value: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|e| AppError::Unauthorized(format!("Invalid JWT claims: {e}")))?;

    let now = now_epoch_secs();
    let exp = value
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::Unauthorized("Missing exp claim".into()))?;
    if exp < now {
        return Err(AppError::Unauthorized("JWT expired".into()));
    }
    if let Some(nbf) = value.get("nbf").and_then(|v| v.as_i64())
        && nbf > now + CLOCK_SKEW_TOLERANCE
    {
        return Err(AppError::Unauthorized("JWT not yet valid".into()));
    }
    let iss = value
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Missing iss claim".into()))?;
    if iss != ISSUER {
        return Err(AppError::Unauthorized("JWT issuer mismatch".into()));
    }
    let type_claim = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Missing type claim".into()))?;
    if type_claim != expected_type {
        return Err(AppError::Unauthorized("JWT type mismatch".into()));
    }

    serde_json::from_value(value)
        .map_err(|e| AppError::Unauthorized(format!("Invalid JWT claims: {e}")))
}

const ISSUER: &str = "|orangevault|";
/// Accept tokens issued up to this many seconds in the future. Cloudflare
/// Workers and clients rarely drift, but a small tolerance keeps us from
/// rejecting an access token minted by the same request's signing step.
const CLOCK_SKEW_TOLERANCE: i64 = 5;

pub const TYPE_ACCESS: &str = "access_token";
pub const TYPE_REFRESH: &str = "refresh_token";
pub const TYPE_REGISTER_VERIFY: &str = "register_verify";

/// Create a signed access token for the given user and device.
pub async fn create_access_token(
    user: &User,
    device_uuid: &str,
    signing_key: &web_sys::CryptoKey,
) -> Result<String> {
    let now = now_epoch_secs();
    let claims = LoginClaims {
        nbf: now,
        exp: now + ACCESS_TOKEN_EXPIRY,
        iss: ISSUER.into(),
        sub: user.uuid.clone(),
        r#type: TYPE_ACCESS.into(),
        premium: true,
        name: user.name.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        sstamp: user.security_stamp.clone(),
        device: device_uuid.into(),
        scope: vec!["api".into(), "offline_access".into()],
        orgowner: vec![],
        orgadmin: vec![],
        orguser: vec![],
        orgmanager: vec![],
    };
    sign_jwt(&claims, signing_key).await
}

/// Create a signed registration-verification token.
pub async fn create_register_verify_token(
    email: &str,
    name: Option<String>,
    verified: bool,
    signing_key: &web_sys::CryptoKey,
) -> Result<String> {
    let now = now_epoch_secs();
    let claims = RegisterVerifyClaims {
        nbf: now,
        exp: now + REGISTER_VERIFY_EXPIRY,
        iss: ISSUER.into(),
        sub: email.to_string(),
        r#type: TYPE_REGISTER_VERIFY.into(),
        name,
        verified,
    };
    sign_jwt(&claims, signing_key).await
}

/// Create a signed refresh token.
pub async fn create_refresh_token(
    user_uuid: &str,
    device_uuid: &str,
    signing_key: &web_sys::CryptoKey,
) -> Result<String> {
    let now = now_epoch_secs();
    let claims = RefreshClaims {
        nbf: now,
        exp: now + REFRESH_TOKEN_EXPIRY,
        iss: ISSUER.into(),
        sub: user_uuid.into(),
        r#type: TYPE_REFRESH.into(),
        token: device_uuid.into(),
        jti: generate_uuid(),
    };
    sign_jwt(&claims, signing_key).await
}
