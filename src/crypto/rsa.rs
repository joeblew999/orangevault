use js_sys::{Object, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use crate::error::{AppError, Result};

use super::{js_array, js_set, subtle_crypto};

/// Build the RSASSA-PKCS1-v1_5 / SHA-256 algorithm object used for import/generate.
fn rsa_algo() -> Result<Object> {
    let algo = Object::new();
    js_set(&algo, "name", &"RSASSA-PKCS1-v1_5".into())?;
    let hash_obj = Object::new();
    js_set(&hash_obj, "name", &"SHA-256".into())?;
    js_set(&algo, "hash", &hash_obj.into())?;
    Ok(algo)
}

/// Generate an RSA-2048 key pair for JWT signing (RSASSA-PKCS1-v1_5 with SHA-256).
pub async fn generate_rsa_keypair() -> Result<web_sys::CryptoKeyPair> {
    let subtle = subtle_crypto()?;

    let algo = rsa_algo()?;
    js_set(&algo, "modulusLength", &JsValue::from(2048))?;
    let public_exponent = Uint8Array::from(&[0x01u8, 0x00, 0x01][..]);
    js_set(&algo, "publicExponent", &public_exponent)?;

    let usages = js_array(&["sign", "verify"]);
    let promise = subtle
        .generate_key_with_object(&algo, true, &usages)
        .map_err(|e| AppError::Internal(format!("RSA generateKey failed: {e:?}")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| AppError::Internal(format!("RSA generateKey await failed: {e:?}")))?;

    Ok(result.into())
}

pub async fn export_key_jwk(key: &web_sys::CryptoKey) -> Result<String> {
    let subtle = subtle_crypto()?;
    let promise = subtle
        .export_key("jwk", key)
        .map_err(|e| AppError::Internal(format!("export_key failed: {e:?}")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| AppError::Internal(format!("export_key await failed: {e:?}")))?;
    let json = js_sys::JSON::stringify(&result)
        .map_err(|e| AppError::Internal(format!("JSON.stringify failed: {e:?}")))?;
    Ok(json.into())
}

pub async fn import_private_key_jwk(jwk_json: &str) -> Result<web_sys::CryptoKey> {
    import_key_jwk(jwk_json, &["sign"]).await
}

pub async fn import_public_key_jwk(jwk_json: &str) -> Result<web_sys::CryptoKey> {
    import_key_jwk(jwk_json, &["verify"]).await
}

async fn import_key_jwk(jwk_json: &str, usages: &[&str]) -> Result<web_sys::CryptoKey> {
    let subtle = subtle_crypto()?;
    let jwk_obj: Object = js_sys::JSON::parse(jwk_json)
        .map_err(|e| AppError::Internal(format!("JSON.parse failed: {e:?}")))?
        .into();

    let algo = rsa_algo()?;
    let promise = subtle
        .import_key_with_object("jwk", &jwk_obj, &algo, false, &js_array(usages))
        .map_err(|e| AppError::Internal(format!("import_key failed: {e:?}")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| AppError::Internal(format!("import_key await failed: {e:?}")))?;

    Ok(result.into())
}

pub async fn rsa_sign(private_key: &web_sys::CryptoKey, data: &[u8]) -> Result<Vec<u8>> {
    let subtle = subtle_crypto()?;
    let data_arr = Uint8Array::from(data);
    let promise = subtle
        .sign_with_str_and_buffer_source("RSASSA-PKCS1-v1_5", private_key, &data_arr)
        .map_err(|e| AppError::Internal(format!("RSA sign failed: {e:?}")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| AppError::Internal(format!("RSA sign await failed: {e:?}")))?;

    let buf = Uint8Array::new(&result);
    Ok(buf.to_vec())
}
