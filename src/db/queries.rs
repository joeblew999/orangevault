use worker::d1::{D1Database, D1Type};

use crate::error::{AppError, Result};

use super::models::{
    Cipher, CipherCollection, Collection, Device, Favorite, Folder, FolderCipher, Membership,
    Organization, User, UserCollection,
};

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

// --- Cipher queries ---

pub async fn find_ciphers_by_user(db: &D1Database, user_uuid: &str) -> Result<Vec<Cipher>> {
    db.prepare("SELECT * FROM ciphers WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Cipher>()
        .map_err(d1_err)
}

pub async fn find_cipher_by_uuid(db: &D1Database, uuid: &str) -> Result<Option<Cipher>> {
    db.prepare("SELECT * FROM ciphers WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<Cipher>(None)
        .await
        .map_err(d1_err)
}

pub async fn insert_cipher(db: &D1Database, c: &Cipher) -> Result<()> {
    let notes = opt_text(&c.notes);
    let fields = opt_text(&c.fields);
    let key = opt_text(&c.key);
    let pw_hist = opt_text(&c.password_history);
    let reprompt = opt_int(c.reprompt);
    let deleted = opt_text(&c.deleted_at);
    let user = opt_text(&c.user_uuid);
    let org = opt_text(&c.organization_uuid);

    db.prepare(
        "INSERT INTO ciphers (uuid, user_uuid, organization_uuid, atype, name, notes,
         fields, data, akey, password_history, reprompt, deleted_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )
    .bind_refs([
        &D1Type::Text(&c.uuid),
        &user,
        &org,
        &D1Type::Integer(c.atype),
        &D1Type::Text(&c.name),
        &notes,
        &fields,
        &D1Type::Text(&c.data),
        &key,
        &pw_hist,
        &reprompt,
        &deleted,
        &D1Type::Text(&c.created_at),
        &D1Type::Text(&c.updated_at),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn update_cipher(db: &D1Database, c: &Cipher) -> Result<()> {
    let notes = opt_text(&c.notes);
    let fields = opt_text(&c.fields);
    let key = opt_text(&c.key);
    let pw_hist = opt_text(&c.password_history);
    let reprompt = opt_int(c.reprompt);

    db.prepare(
        "UPDATE ciphers SET name = ?1, notes = ?2, fields = ?3, data = ?4,
         akey = ?5, password_history = ?6, reprompt = ?7, updated_at = ?8
         WHERE uuid = ?9",
    )
    .bind_refs([
        &D1Type::Text(&c.name),
        &notes,
        &fields,
        &D1Type::Text(&c.data),
        &key,
        &pw_hist,
        &reprompt,
        &D1Type::Text(&c.updated_at),
        &D1Type::Text(&c.uuid),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn soft_delete_cipher(db: &D1Database, uuid: &str, now: &str) -> Result<()> {
    db.prepare("UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE uuid = ?2")
        .bind_refs([&D1Type::Text(now), &D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn restore_cipher(db: &D1Database, uuid: &str, now: &str) -> Result<()> {
    db.prepare("UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE uuid = ?2")
        .bind_refs([&D1Type::Text(now), &D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn hard_delete_cipher(db: &D1Database, uuid: &str) -> Result<()> {
    // Delete related rows first (no FK enforcement)
    db.prepare("DELETE FROM folders_ciphers WHERE cipher_uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    db.prepare("DELETE FROM favorites WHERE cipher_uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    db.prepare("DELETE FROM ciphers WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn purge_ciphers_for_user(db: &D1Database, user_uuid: &str) -> Result<()> {
    db.prepare(
        "DELETE FROM folders_ciphers WHERE cipher_uuid IN
         (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
    )
    .bind_refs([&D1Type::Text(user_uuid)])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    db.prepare(
        "DELETE FROM favorites WHERE cipher_uuid IN
         (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
    )
    .bind_refs([&D1Type::Text(user_uuid)])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    db.prepare("DELETE FROM ciphers WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

// --- Folder queries ---

pub async fn find_folders_by_user(db: &D1Database, user_uuid: &str) -> Result<Vec<Folder>> {
    db.prepare("SELECT * FROM folders WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Folder>()
        .map_err(d1_err)
}

pub async fn find_folder_by_uuid(db: &D1Database, uuid: &str) -> Result<Option<Folder>> {
    db.prepare("SELECT * FROM folders WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<Folder>(None)
        .await
        .map_err(d1_err)
}

pub async fn insert_folder(db: &D1Database, f: &Folder) -> Result<()> {
    db.prepare(
        "INSERT INTO folders (uuid, user_uuid, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind_refs([
        &D1Type::Text(&f.uuid),
        &D1Type::Text(&f.user_uuid),
        &D1Type::Text(&f.name),
        &D1Type::Text(&f.created_at),
        &D1Type::Text(&f.updated_at),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn update_folder(db: &D1Database, f: &Folder) -> Result<()> {
    db.prepare("UPDATE folders SET name = ?1, updated_at = ?2 WHERE uuid = ?3")
        .bind_refs([
            &D1Type::Text(&f.name),
            &D1Type::Text(&f.updated_at),
            &D1Type::Text(&f.uuid),
        ])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn delete_folder(db: &D1Database, uuid: &str) -> Result<()> {
    db.prepare("DELETE FROM folders_ciphers WHERE folder_uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    db.prepare("DELETE FROM folders WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

// --- Favorites & folder-cipher links ---

pub async fn find_favorites_by_user(db: &D1Database, user_uuid: &str) -> Result<Vec<Favorite>> {
    db.prepare("SELECT * FROM favorites WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Favorite>()
        .map_err(d1_err)
}

pub async fn set_favorite(db: &D1Database, user_uuid: &str, cipher_uuid: &str) -> Result<()> {
    db.prepare("INSERT OR IGNORE INTO favorites (user_uuid, cipher_uuid) VALUES (?1, ?2)")
        .bind_refs([&D1Type::Text(user_uuid), &D1Type::Text(cipher_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn unset_favorite(db: &D1Database, user_uuid: &str, cipher_uuid: &str) -> Result<()> {
    db.prepare("DELETE FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2")
        .bind_refs([&D1Type::Text(user_uuid), &D1Type::Text(cipher_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn find_folder_ciphers_by_user(
    db: &D1Database,
    user_uuid: &str,
) -> Result<Vec<FolderCipher>> {
    db.prepare(
        "SELECT fc.* FROM folders_ciphers fc
         JOIN folders f ON f.uuid = fc.folder_uuid
         WHERE f.user_uuid = ?1",
    )
    .bind_refs([&D1Type::Text(user_uuid)])
    .map_err(d1_err)?
    .all()
    .await
    .map_err(d1_err)?
    .results::<FolderCipher>()
    .map_err(d1_err)
}

pub async fn set_folder_cipher(
    db: &D1Database,
    cipher_uuid: &str,
    folder_uuid: &str,
) -> Result<()> {
    db.prepare("INSERT OR REPLACE INTO folders_ciphers (cipher_uuid, folder_uuid) VALUES (?1, ?2)")
        .bind_refs([&D1Type::Text(cipher_uuid), &D1Type::Text(folder_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn clear_folder_for_cipher(db: &D1Database, cipher_uuid: &str) -> Result<()> {
    db.prepare("DELETE FROM folders_ciphers WHERE cipher_uuid = ?1")
        .bind_refs([&D1Type::Text(cipher_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

// --- Organization queries ---

pub async fn insert_organization(db: &D1Database, org: &Organization) -> Result<()> {
    let priv_key = opt_text(&org.private_key);
    let pub_key = opt_text(&org.public_key);
    db.prepare(
        "INSERT INTO organizations (uuid, name, billing_email, private_key, public_key)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind_refs([
        &D1Type::Text(&org.uuid),
        &D1Type::Text(&org.name),
        &D1Type::Text(&org.billing_email),
        &priv_key,
        &pub_key,
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn find_organization_by_uuid(
    db: &D1Database,
    uuid: &str,
) -> Result<Option<Organization>> {
    db.prepare("SELECT * FROM organizations WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<Organization>(None)
        .await
        .map_err(d1_err)
}

pub async fn delete_organization(db: &D1Database, uuid: &str) -> Result<()> {
    // Delete in dependency order
    for sql in [
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections WHERE org_uuid = ?1",
        "DELETE FROM org_policies WHERE org_uuid = ?1",
        "DELETE FROM memberships WHERE org_uuid = ?1",
        "DELETE FROM ciphers WHERE organization_uuid = ?1",
        "DELETE FROM organizations WHERE uuid = ?1",
    ] {
        db.prepare(sql)
            .bind_refs([&D1Type::Text(uuid)])
            .map_err(d1_err)?
            .run()
            .await
            .map_err(d1_err)?;
    }
    Ok(())
}

// --- Membership queries ---

pub async fn insert_membership(db: &D1Database, m: &Membership) -> Result<()> {
    let akey = opt_text(&m.akey);
    let ext_id = opt_text(&m.external_id);
    let rpk = opt_text(&m.reset_password_key);
    db.prepare(
        "INSERT INTO memberships (uuid, user_uuid, org_uuid, akey, atype, status,
         access_all, external_id, reset_password_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind_refs([
        &D1Type::Text(&m.uuid),
        &D1Type::Text(&m.user_uuid),
        &D1Type::Text(&m.org_uuid),
        &akey,
        &D1Type::Integer(m.atype),
        &D1Type::Integer(m.status),
        &D1Type::Boolean(m.access_all),
        &ext_id,
        &rpk,
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn find_memberships_by_user(db: &D1Database, user_uuid: &str) -> Result<Vec<Membership>> {
    db.prepare("SELECT * FROM memberships WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Membership>()
        .map_err(d1_err)
}

pub async fn find_memberships_by_org(db: &D1Database, org_uuid: &str) -> Result<Vec<Membership>> {
    db.prepare("SELECT * FROM memberships WHERE org_uuid = ?1")
        .bind_refs([&D1Type::Text(org_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Membership>()
        .map_err(d1_err)
}

pub async fn find_membership(
    db: &D1Database,
    user_uuid: &str,
    org_uuid: &str,
) -> Result<Option<Membership>> {
    db.prepare("SELECT * FROM memberships WHERE user_uuid = ?1 AND org_uuid = ?2")
        .bind_refs([&D1Type::Text(user_uuid), &D1Type::Text(org_uuid)])
        .map_err(d1_err)?
        .first::<Membership>(None)
        .await
        .map_err(d1_err)
}

pub async fn update_membership_status_and_key(
    db: &D1Database,
    membership_uuid: &str,
    status: i32,
    akey: Option<&str>,
) -> Result<()> {
    let key_val = match akey {
        Some(k) => D1Type::Text(k),
        None => D1Type::Null,
    };
    db.prepare("UPDATE memberships SET status = ?1, akey = ?2 WHERE uuid = ?3")
        .bind_refs([
            &D1Type::Integer(status),
            &key_val,
            &D1Type::Text(membership_uuid),
        ])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

// --- Collection queries ---

pub async fn insert_collection(db: &D1Database, c: &Collection) -> Result<()> {
    let ext_id = opt_text(&c.external_id);
    db.prepare(
        "INSERT INTO collections (uuid, org_uuid, name, external_id)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind_refs([
        &D1Type::Text(&c.uuid),
        &D1Type::Text(&c.org_uuid),
        &D1Type::Text(&c.name),
        &ext_id,
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn find_collections_by_org(db: &D1Database, org_uuid: &str) -> Result<Vec<Collection>> {
    db.prepare("SELECT * FROM collections WHERE org_uuid = ?1")
        .bind_refs([&D1Type::Text(org_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Collection>()
        .map_err(d1_err)
}

pub async fn find_collection_by_uuid(db: &D1Database, uuid: &str) -> Result<Option<Collection>> {
    db.prepare("SELECT * FROM collections WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .first::<Collection>(None)
        .await
        .map_err(d1_err)
}

pub async fn delete_collection(db: &D1Database, uuid: &str) -> Result<()> {
    db.prepare("DELETE FROM ciphers_collections WHERE collection_uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    db.prepare("DELETE FROM users_collections WHERE collection_uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    db.prepare("DELETE FROM collections WHERE uuid = ?1")
        .bind_refs([&D1Type::Text(uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn set_user_collection(
    db: &D1Database,
    user_uuid: &str,
    collection_uuid: &str,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
) -> Result<()> {
    db.prepare(
        "INSERT OR REPLACE INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind_refs([
        &D1Type::Text(user_uuid),
        &D1Type::Text(collection_uuid),
        &D1Type::Boolean(read_only),
        &D1Type::Boolean(hide_passwords),
        &D1Type::Boolean(manage),
    ])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn find_user_collections_by_user(
    db: &D1Database,
    user_uuid: &str,
) -> Result<Vec<UserCollection>> {
    db.prepare("SELECT * FROM users_collections WHERE user_uuid = ?1")
        .bind_refs([&D1Type::Text(user_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<UserCollection>()
        .map_err(d1_err)
}

// --- Cipher-collection queries ---

pub async fn set_cipher_collection(
    db: &D1Database,
    cipher_uuid: &str,
    collection_uuid: &str,
) -> Result<()> {
    db.prepare(
        "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid)
         VALUES (?1, ?2)",
    )
    .bind_refs([&D1Type::Text(cipher_uuid), &D1Type::Text(collection_uuid)])
    .map_err(d1_err)?
    .run()
    .await
    .map_err(d1_err)?;
    Ok(())
}

pub async fn clear_cipher_collections(db: &D1Database, cipher_uuid: &str) -> Result<()> {
    db.prepare("DELETE FROM ciphers_collections WHERE cipher_uuid = ?1")
        .bind_refs([&D1Type::Text(cipher_uuid)])
        .map_err(d1_err)?
        .run()
        .await
        .map_err(d1_err)?;
    Ok(())
}

pub async fn find_cipher_collections(
    db: &D1Database,
    cipher_uuid: &str,
) -> Result<Vec<CipherCollection>> {
    db.prepare("SELECT * FROM ciphers_collections WHERE cipher_uuid = ?1")
        .bind_refs([&D1Type::Text(cipher_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<CipherCollection>()
        .map_err(d1_err)
}

pub async fn find_org_ciphers(db: &D1Database, org_uuid: &str) -> Result<Vec<Cipher>> {
    db.prepare("SELECT * FROM ciphers WHERE organization_uuid = ?1")
        .bind_refs([&D1Type::Text(org_uuid)])
        .map_err(d1_err)?
        .all()
        .await
        .map_err(d1_err)?
        .results::<Cipher>()
        .map_err(d1_err)
}

pub async fn find_cipher_collections_by_org(
    db: &D1Database,
    org_uuid: &str,
) -> Result<Vec<CipherCollection>> {
    db.prepare(
        "SELECT cc.* FROM ciphers_collections cc
         INNER JOIN collections c ON cc.collection_uuid = c.uuid
         WHERE c.org_uuid = ?1",
    )
    .bind_refs([&D1Type::Text(org_uuid)])
    .map_err(d1_err)?
    .all()
    .await
    .map_err(d1_err)?
    .results::<CipherCollection>()
    .map_err(d1_err)
}

pub async fn share_cipher_to_org(
    db: &D1Database,
    cipher_uuid: &str,
    org_uuid: &str,
    data: &str,
    name: &str,
    key: Option<&str>,
    now: &str,
) -> Result<()> {
    let key_val = match key {
        Some(k) => D1Type::Text(k),
        None => D1Type::Null,
    };
    db.prepare(
        "UPDATE ciphers SET user_uuid = NULL, organization_uuid = ?1,
         data = ?2, name = ?3, akey = ?4, updated_at = ?5 WHERE uuid = ?6",
    )
    .bind_refs([
        &D1Type::Text(org_uuid),
        &D1Type::Text(data),
        &D1Type::Text(name),
        &key_val,
        &D1Type::Text(now),
        &D1Type::Text(cipher_uuid),
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
