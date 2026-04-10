use worker::d1::{D1Database, D1Type};

use crate::error::{AppError, Result};

use super::models::{Device, User};

fn d1_err(e: worker::Error) -> AppError {
    AppError::Internal(format!("D1 error: {e}"))
}

// --- User queries ---

pub async fn find_user_by_email(db: &D1Database, email: &str) -> Result<Option<User>> {
    db.prepare("SELECT * FROM users WHERE email = ?1")
        .bind_refs([&D1Type::Text(email)])
        .map_err(d1_err)?
        .first::<User>(None)
        .await
        .map_err(d1_err)
}

pub async fn find_user_by_uuid(db: &D1Database, uuid: &str) -> Result<Option<User>> {
    db.prepare("SELECT * FROM users WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<User>(None)
        .await
        .map_err(d1_err)
}

pub async fn insert_user(db: &D1Database, user: &User) -> Result<()> {
    let kdf_mem = opt_int(user.client_kdf_memory);
    let kdf_par = opt_int(user.client_kdf_parallelism);
    let akey = opt_text(&user.akey);
    let priv_key = opt_text(&user.private_key);
    let pub_key = opt_text(&user.public_key);
    let api_key = opt_text(&user.api_key);
    let avatar = opt_text(&user.avatar_color);
    let totp = opt_text(&user.totp_recover);

    db.prepare(
        "INSERT INTO users (uuid, email, name, password_hash, salt, password_iterations,
         akey, private_key, public_key, security_stamp,
         client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism,
         api_key, avatar_color, email_verified, totp_recover, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
    )
    .bind_refs([
        &D1Type::Text(&user.uuid),
        &D1Type::Text(&user.email),
        &D1Type::Text(&user.name),
        &D1Type::Text(&user.password_hash),
        &D1Type::Text(&user.salt),
        &D1Type::Integer(user.password_iterations as i32),
        &akey,
        &priv_key,
        &pub_key,
        &D1Type::Text(&user.security_stamp),
        &D1Type::Integer(user.client_kdf_type),
        &D1Type::Integer(user.client_kdf_iter),
        &kdf_mem,
        &kdf_par,
        &api_key,
        &avatar,
        &D1Type::Boolean(user.email_verified),
        &totp,
        &D1Type::Text(&user.created_at),
        &D1Type::Text(&user.updated_at),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            AppError::Conflict("User already exists".into())
        } else {
            d1_err(e)
        }
    })?;
    Ok(())
}

// --- Device queries ---

pub async fn find_device_by_uuid(db: &D1Database, uuid: &str) -> Result<Option<Device>> {
    db.prepare("SELECT * FROM devices WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<Device>(None)
        .await
        .map_err(d1_err)
}

pub async fn upsert_device(db: &D1Database, device: &Device) -> Result<()> {
    let push_uuid = opt_text(&device.push_uuid);
    let push_token = opt_text(&device.push_token);
    let twofactor = opt_text(&device.twofactor_remember);

    db.prepare(
        "INSERT INTO devices (uuid, user_uuid, name, atype, push_uuid, push_token,
         refresh_token, twofactor_remember, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(uuid) DO UPDATE SET
           name = excluded.name,
           atype = excluded.atype,
           refresh_token = excluded.refresh_token,
           updated_at = excluded.updated_at",
    )
    .bind_refs([
        &D1Type::Text(&device.uuid),
        &D1Type::Text(&device.user_uuid),
        &D1Type::Text(&device.name),
        &D1Type::Integer(device.atype),
        &push_uuid,
        &push_token,
        &D1Type::Text(&device.refresh_token),
        &twofactor,
        &D1Type::Text(&device.created_at),
        &D1Type::Text(&device.updated_at),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn update_device_refresh_token(
    db: &D1Database,
    device_uuid: &str,
    new_token: &str,
    now: &str,
) -> Result<()> {
    db.prepare("UPDATE devices SET refresh_token = ?1, updated_at = ?2 WHERE uuid = ?3")
        .bind_refs([
            &D1Type::Text(new_token),
            &D1Type::Text(now),
            &D1Type::Text(device_uuid),
        ])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

// --- Helpers ---

fn opt_text<'a>(val: &'a Option<String>) -> D1Type<'a> {
    match val {
        Some(s) => D1Type::Text(s.as_str()),
        None => D1Type::Null,
    }
}

fn opt_int(val: Option<i32>) -> D1Type<'static> {
    match val {
        Some(i) => D1Type::Integer(i),
        None => D1Type::Null,
    }
}
