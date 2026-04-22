use worker::{Request, Response, RouteContext};

use crate::auth::claims::{RefreshClaims, RegisterVerifyClaims};
use crate::auth::guards::verify_master_password;
use crate::auth::jwt;
use crate::config::RequestContext;
use crate::crypto::pbkdf2::SERVER_PASSWORD_ITERATIONS;
use crate::crypto::totp::{base32_decode, validate_totp};
use crate::crypto::{constant_time_eq, pbkdf2, random};
use crate::db::models::{Device, User};
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::user::{
    AccountKeys, LoginResponse, MasterPasswordUnlock, MasterPasswordUnlockKdf,
    PublicKeyEncryptionKeyPair, RegisterRequest, RegisterVerificationRequest, TokenRequest,
    UserDecryptionOptions,
};
use crate::util::{base64_encode, generate_uuid, now_epoch_secs, now_utc};

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
            let email = normalize_email(&body.email)?;
            let name = body.name.clone().unwrap_or_default();
            let db = ctx.data.db()?;
            perform_registration(&db, &email, name, false, &body).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

/// No mail transport, so this endpoint returns the verification token inline
/// (as a JSON-encoded string) rather than emailing a link. The client passes
/// it back to `/register/finish`. Accounts created this way remain unverified
/// since we can't confirm the email was received — gate open registration via
/// `SIGNUPS_ALLOWED=false`.
pub async fn register_verification_email(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            if !ctx.data.signups_allowed() {
                return Err(AppError::BadRequest("Registration is closed".into()));
            }
            let body: RegisterVerificationRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;
            let email = normalize_email(&body.email)?;

            let kv = ctx.data.kv()?;
            let signing_key = jwt::load_or_create_signing_key(&kv).await?;
            let token =
                jwt::create_register_verify_token(&email, body.name, false, &signing_key).await?;

            Ok(Response::from_json(&token)?)
        }
        .await,
    )
}

pub async fn register_finish(
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
            let email = normalize_email(&body.email)?;

            let token = body
                .email_verification_token
                .as_deref()
                .ok_or_else(|| AppError::BadRequest("Missing email verification token".into()))?;

            let kv = ctx.data.kv()?;
            let public_key = jwt::load_public_key(&kv).await?;
            let claims: RegisterVerifyClaims =
                jwt::verify_and_decode_jwt(token, &public_key, jwt::TYPE_REGISTER_VERIFY).await?;

            if claims.sub != email {
                return Err(AppError::BadRequest(
                    "Email verification token does not match email".into(),
                ));
            }

            let name = body
                .name
                .clone()
                .or(claims.name.clone())
                .unwrap_or_default();

            let db = ctx.data.db()?;
            perform_registration(&db, &email, name, claims.verified, &body).await?;
            Ok(Response::empty()?.with_status(200))
        }
        .await,
    )
}

fn normalize_email(raw: &str) -> crate::error::Result<String> {
    let email = raw.trim().to_lowercase();
    if !email.contains('@') || email.len() < 5 {
        return Err(AppError::BadRequest("Invalid email address".into()));
    }
    Ok(email)
}

async fn perform_registration(
    db: &worker::D1Database,
    email: &str,
    name: String,
    email_verified: bool,
    body: &RegisterRequest,
) -> crate::error::Result<()> {
    let salt = random::random_bytes(64)?;
    let password_hash = pbkdf2::pbkdf2_sha256(
        body.master_password_hash.as_bytes(),
        &salt,
        SERVER_PASSWORD_ITERATIONS,
        32,
    )
    .await?;

    let now = now_utc();
    let user = User {
        uuid: generate_uuid(),
        email: email.to_string(),
        name,
        password_hash: base64_encode(&password_hash),
        salt: base64_encode(&salt),
        password_iterations: SERVER_PASSWORD_ITERATIONS,
        akey: body.key.clone(),
        private_key: body.keys.as_ref().map(|k| k.encrypted_private_key.clone()),
        public_key: body.keys.as_ref().map(|k| k.public_key.clone()),
        security_stamp: generate_uuid(),
        client_kdf_type: body.kdf.unwrap_or(0),
        client_kdf_iter: body.kdf_iterations.unwrap_or(600_000),
        client_kdf_memory: body.kdf_memory,
        client_kdf_parallelism: body.kdf_parallelism,
        api_key: None,
        avatar_color: None,
        email_verified,
        totp_recover: None,
        created_at: now.clone(),
        updated_at: now,
    };

    queries::insert_user(db, &user).await?;
    Ok(())
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

    let two_factors = queries::find_two_factors_by_user(db, &user.uuid).await?;
    if !two_factors.is_empty() {
        match (form.two_factor_provider, form.two_factor_token.as_deref()) {
            (Some(provider), Some(token)) => {
                match provider {
                    0 => {
                        let tf = two_factors
                            .iter()
                            .find(|t| t.atype == 0)
                            .ok_or_else(|| oauth_invalid_grant("TOTP not configured"))?;
                        let secret = base32_decode(&tf.data)?;
                        let now = now_epoch_secs() as u64;
                        let step = validate_totp(&secret, token, now)
                            .await?
                            .ok_or_else(|| oauth_invalid_grant("Invalid TOTP code"))?;
                        if step <= tf.last_used.unwrap_or(0) {
                            return Err(oauth_invalid_grant("TOTP code already used"));
                        }
                        queries::update_two_factor_last_used(db, &tf.uuid, step).await?;
                    }
                    8 => {
                        // Recovery code
                        let stored = user.totp_recover.as_deref().unwrap_or("");
                        let token_norm = token.replace(' ', "").to_uppercase();
                        let stored_norm = stored.replace(' ', "").to_uppercase();
                        // Defense in depth: if totp_recover ever becomes
                        // absent while 2FA is still enabled (direct DB edit,
                        // lost write, bug), the comparison below would accept
                        // an empty submitted token. Reject before the
                        // constant-time compare so that path is unreachable.
                        if stored_norm.is_empty() || token_norm.is_empty() {
                            return Err(oauth_invalid_grant("Invalid recovery code"));
                        }
                        if !constant_time_eq(token_norm.as_bytes(), stored_norm.as_bytes()) {
                            return Err(oauth_invalid_grant("Invalid recovery code"));
                        }
                        queries::delete_two_factors_for_user(db, &user.uuid).await?;
                        queries::update_user_totp_recover(db, &user.uuid, None).await?;
                    }
                    _ => {
                        return Err(oauth_invalid_grant("Unsupported 2FA provider"));
                    }
                }
            }
            _ => {
                let providers: Vec<i32> = two_factors.iter().map(|t| t.atype).collect();
                return Err(AppError::OAuth {
                    error: "invalid_grant".into(),
                    error_description: "Two factor required.".into(),
                    status: 400,
                    two_factor_providers: Some(providers),
                });
            }
        }
    }

    // Create or update device. If the caller's device_identifier already
    // belongs to another user, don't trust it — `upsert_device` would
    // otherwise keep the existing `user_uuid` while overwriting that user's
    // refresh_token, effectively logging them out and creating a mismatched
    // row. Mint a fresh UUID in that case so the login proceeds cleanly and
    // the victim's session is left alone.
    let device_uuid = match form.device_identifier.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => match queries::find_device_by_uuid(db, id).await? {
            Some(existing) if existing.user_uuid != user.uuid => generate_uuid(),
            _ => id.to_string(),
        },
        None => generate_uuid(),
    };
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
    let claims: RefreshClaims =
        jwt::verify_and_decode_jwt(refresh_token_str, &public_key, jwt::TYPE_REFRESH)
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
    let master_password_unlock = user.akey.as_ref().map(|akey| MasterPasswordUnlock {
        kdf: MasterPasswordUnlockKdf {
            kdf_type: user.client_kdf_type,
            iterations: user.client_kdf_iter,
            memory: user.client_kdf_memory,
            parallelism: user.client_kdf_parallelism,
        },
        master_key_encrypted_user_key: akey.clone(),
        master_key_wrapped_user_key: akey.clone(),
        salt: user.email.clone(),
    });

    let account_keys = match (user.private_key.as_ref(), user.public_key.as_ref()) {
        (Some(private_key), Some(public_key)) => Some(AccountKeys {
            public_key_encryption_key_pair: PublicKeyEncryptionKeyPair {
                wrapped_private_key: private_key.clone(),
                public_key: public_key.clone(),
                object: "publicKeyEncryptionKeyPair",
            },
            object: "privateKeys",
        }),
        _ => None,
    };

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
            master_password_unlock,
            object: "userDecryptionOptions",
        },
        account_keys,
        two_factor_token: None,
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
