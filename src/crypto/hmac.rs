use js_sys::{Object, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use crate::error::{AppError, Result};

use super::{js_array, js_set, subtle_crypto};

pub async fn hmac(hash: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let subtle = subtle_crypto()?;

    let algo = Object::new();
    js_set(&algo, "name", &"HMAC".into())?;
    js_set(&algo, "hash", &JsValue::from_str(hash))?;

    let key_arr = Uint8Array::from(key);
    let import_promise = subtle
        .import_key_with_object("raw", &key_arr, &algo, false, &js_array(&["sign"]))
        .map_err(|e| AppError::Internal(format!("HMAC import_key failed: {e:?}")))?;
    let crypto_key = JsFuture::from(import_promise)
        .await
        .map_err(|e| AppError::Internal(format!("HMAC import_key await failed: {e:?}")))?;

    let data_arr = Uint8Array::from(data);
    let sign_promise = subtle
        .sign_with_object_and_buffer_source(&algo, &crypto_key.into(), &data_arr)
        .map_err(|e| AppError::Internal(format!("HMAC sign failed: {e:?}")))?;
    let result = JsFuture::from(sign_promise)
        .await
        .map_err(|e| AppError::Internal(format!("HMAC sign await failed: {e:?}")))?;

    let buf = Uint8Array::new(&result);
    Ok(buf.to_vec())
}

pub async fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac("SHA-256", key, data).await
}

/// HMAC-SHA1 (for TOTP).
pub async fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac("SHA-1", key, data).await
}
