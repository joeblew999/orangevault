pub mod hmac;
pub mod pbkdf2;
pub mod random;
pub mod rsa;
pub mod totp;

use js_sys::{Object, Reflect};
use wasm_bindgen::JsValue;

use crate::error::{AppError, Result};

/// Get the global Crypto object.
pub fn crypto_global() -> Result<web_sys::Crypto> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &"crypto".into())
        .map_err(|_| AppError::Internal("crypto not available".into()))?;
    Ok(crypto.into())
}

pub fn subtle_crypto() -> Result<web_sys::SubtleCrypto> {
    Ok(crypto_global()?.subtle())
}

/// Set a property on a JS Object, mapping errors to AppError.
pub(crate) fn js_set(obj: &Object, key: &str, val: &JsValue) -> Result<()> {
    Reflect::set(obj, &JsValue::from_str(key), val)
        .map_err(|e| AppError::Internal(format!("set {key} failed: {e:?}")))?;
    Ok(())
}

/// Create a JS array of strings.
pub(crate) fn js_array(values: &[&str]) -> js_sys::Array {
    let arr = js_sys::Array::new();
    for v in values {
        arr.push(&JsValue::from_str(v));
    }
    arr
}

pub async fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    let subtle = subtle_crypto()?;
    let data_arr = js_sys::Uint8Array::from(data);
    let promise = subtle
        .digest_with_str_and_buffer_source("SHA-256", &data_arr)
        .map_err(|e| AppError::Internal(format!("SHA-256 digest failed: {e:?}")))?;
    let result = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| AppError::Internal(format!("SHA-256 await failed: {e:?}")))?;
    let buf = js_sys::Uint8Array::new(&result);
    Ok(buf.to_vec())
}
