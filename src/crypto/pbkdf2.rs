use js_sys::{Object, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use crate::error::{AppError, Result};

use super::{js_array, js_set, subtle_crypto};

/// Derive key bytes using PBKDF2-HMAC-SHA256 via SubtleCrypto.
pub async fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: u32,
) -> Result<Vec<u8>> {
    let subtle = subtle_crypto()?;

    let password_arr = Uint8Array::from(password);
    let import_promise = subtle
        .import_key_with_str(
            "raw",
            &password_arr,
            "PBKDF2",
            false,
            &js_array(&["deriveBits"]),
        )
        .map_err(|e| AppError::Internal(format!("PBKDF2 import_key failed: {e:?}")))?;
    let key = JsFuture::from(import_promise)
        .await
        .map_err(|e| AppError::Internal(format!("PBKDF2 import_key await failed: {e:?}")))?;

    let algo = Object::new();
    js_set(&algo, "name", &"PBKDF2".into())?;
    js_set(&algo, "hash", &"SHA-256".into())?;
    js_set(&algo, "salt", &Uint8Array::from(salt))?;
    js_set(&algo, "iterations", &JsValue::from(iterations))?;

    let derive_promise = subtle
        .derive_bits_with_object(&algo, &key.into(), key_len * 8)
        .map_err(|e| AppError::Internal(format!("PBKDF2 derive_bits failed: {e:?}")))?;
    let result = JsFuture::from(derive_promise)
        .await
        .map_err(|e| AppError::Internal(format!("PBKDF2 derive_bits await failed: {e:?}")))?;

    let buf = Uint8Array::new(&result);
    Ok(buf.to_vec())
}
