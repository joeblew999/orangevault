use worker::{Request, Response, RouteContext};

use crate::auth::claims::RefreshClaims;
use crate::auth::guards::verify_master_password;
use crate::auth::jwt;
use crate::config::RequestContext;
use crate::crypto::{pbkdf2, random};
use crate::db::models::{Device, User};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::user::{LoginResponse, RegisterRequest, TokenRequest, UserDecryptionOptions};
use crate::util::{base64_encode, generate_uuid, now_utc};

pub async fn register(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            if !ctx.data.signups_allowed() {
                return Err(AppError::BadRequest("Registration is closed".into()));
            }

            let body: RegisterRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let email = body.email.trim().to_lowercase();
            if !email.contains('@') || email.len() < 5 {
                return Err(AppError::BadRequest("Invalid email address".into()));
            }

            let db = ctx.data.db()?;

            // Server-side re-hash: PBKDF2 the client's masterPasswordHash
            let salt = random::random_bytes(64)?;
            let password_hash =
                pbkdf2::pbkdf2_sha256(body.master_password_hash.as_bytes(), &salt, 600_000, 32)
                    .await?;

            let now = now_utc();
            let user = User {
                uuid: generate_uuid(),
                email,
                name: body.name.unwrap_or_default(),
                password_hash: base64_encode(&password_hash),
                salt: base64_encode(&salt),
                password_iterations: 600_000,
                akey: body.key,
                private_key: body.keys.as_ref().map(|k| k.encrypted_private_key.clone()),
                public_key: body.keys.as_ref().map(|k| k.public_key.clone()),
                security_stamp: generate_uuid(),
                client_kdf_type: body.kdf.unwrap_or(0),
                client_kdf_iter: body.kdf_iterations.unwrap_or(600_000),
                client_kdf_memory: body.kdf_memory,
                client_kdf_parallelism: body.kdf_parallelism,
                api_key: None,
                avatar_color: None,
                email_verified: false,
                totp_recover: None,
                created_at: now.clone(),
                updated_at: now,
            };

            queries::insert_user(&db, &user).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

pub async fn connect_token(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let body_text = req
                .text()
                .await
                .map_err(|e| AppError::BadRequest(format!("Failed to read body: {e}")))?;
            let form: TokenRequest = serde_urlencoded::from_str(&body_text)
                .map_err(|e| AppError::BadRequest(format!("Invalid form data: {e}")))?;

            let db = ctx.data.db()?;
            let kv = ctx.data.kv()?;

            match form.grant_type.as_str() {
                "password" => handle_password_grant(&form, &db, &kv).await,
                "refresh_token" => handle_refresh_grant(&form, &db, &kv).await,
                _ => Err(AppError::OAuth {
                    error: "unsupported_grant_type".into(),
                    error_description: "Unsupported grant type".into(),
                    status: 400,
                    two_factor_providers: None,
                }),
            }
        }
        .await,
    )
}

async fn handle_password_grant(
    form: &TokenRequest,
    db: &worker::D1Database,
    kv: &worker::kv::KvStore,
) -> crate::error::Result<Response> {
    let email = form
        .username
        .as_deref()
        .ok_or_else(|| oauth_invalid_grant("Username is required"))?
        .trim()
        .to_lowercase();
    let password_hash_input = form
        .password
        .as_deref()
        .ok_or_else(|| oauth_invalid_grant("Password is required"))?;

    let user = queries::find_user_by_email(db, &email)
        .await?
        .ok_or_else(|| oauth_invalid_grant("invalid_username_or_password"))?;

    if !verify_master_password(&user, password_hash_input).await? {
        return Err(oauth_invalid_grant("invalid_username_or_password"));
    }

    // Create or update device
    let device_uuid = form
        .device_identifier
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(generate_uuid);
    let now = now_utc();

    // Sign tokens
    let signing_key = jwt::load_or_create_signing_key(kv).await?;
    let access_token = jwt::create_access_token(&user, &device_uuid, &signing_key).await?;
    let refresh_token = jwt::create_refresh_token(&user.uuid, &device_uuid, &signing_key).await?;

    let device = Device {
        uuid: device_uuid,
        user_uuid: user.uuid.clone(),
        name: form.device_name.clone().unwrap_or_else(|| "Unknown".into()),
        atype: form.device_type.unwrap_or(0),
        push_uuid: None,
        push_token: None,
        refresh_token: refresh_token.clone(),
        twofactor_remember: None,
        created_at: now.clone(),
        updated_at: now,
    };
    queries::upsert_device(db, &device).await?;

    let response = build_login_response(access_token, refresh_token, &user);
    Ok(Response::from_json(&response)?)
}

async fn handle_refresh_grant(
    form: &TokenRequest,
    db: &worker::D1Database,
    kv: &worker::kv::KvStore,
) -> crate::error::Result<Response> {
    let refresh_token_str = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| oauth_invalid_grant("Missing refresh token"))?;

    // Verify and decode the refresh JWT
    let public_key = jwt::load_public_key(kv).await?;
    let claims: RefreshClaims = jwt::verify_and_decode_jwt(refresh_token_str, &public_key)
        .await
        .map_err(|_| oauth_invalid_grant("Invalid refresh token"))?;

    let user = queries::find_user_by_uuid(db, &claims.sub)
        .await?
        .ok_or_else(|| oauth_invalid_grant("User not found"))?;

    // Verify device exists and stored refresh token matches
    let device = queries::find_device_by_uuid(db, &claims.token)
        .await?
        .ok_or_else(|| oauth_invalid_grant("Device not found"))?;

    if device.refresh_token != refresh_token_str {
        return Err(oauth_invalid_grant("Refresh token revoked"));
    }

    // Issue new tokens (rotation)
    let signing_key = jwt::load_or_create_signing_key(kv).await?;
    let new_access = jwt::create_access_token(&user, &device.uuid, &signing_key).await?;
    let new_refresh = jwt::create_refresh_token(&user.uuid, &device.uuid, &signing_key).await?;

    queries::update_device_refresh_token(db, &device.uuid, &new_refresh, &now_utc()).await?;

    let response = build_login_response(new_access, new_refresh, &user);
    Ok(Response::from_json(&response)?)
}

fn build_login_response(access_token: String, refresh_token: String, user: &User) -> LoginResponse {
    LoginResponse {
        access_token,
        expires_in: jwt::ACCESS_TOKEN_EXPIRY,
        token_type: "Bearer".into(),
        refresh_token,
        key: user.akey.clone(),
        private_key: user.private_key.clone(),
        kdf: user.client_kdf_type,
        kdf_iterations: user.client_kdf_iter,
        kdf_memory: user.client_kdf_memory,
        kdf_parallelism: user.client_kdf_parallelism,
        unofficial_server: true,
        user_decryption_options: UserDecryptionOptions {
            has_master_password: true,
        },
    }
}

fn oauth_invalid_grant(description: &str) -> AppError {
    AppError::OAuth {
        error: "invalid_grant".into(),
        error_description: description.into(),
        status: 400,
        two_factor_providers: None,
    }
}
