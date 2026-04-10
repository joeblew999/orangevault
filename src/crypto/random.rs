use js_sys::Uint8Array;

use crate::error::{AppError, Result};

use super::crypto_global;

pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let crypto = crypto_global()?;
    let arr = Uint8Array::new_with_length(n as u32);
    crypto
        .get_random_values_with_array_buffer_view(&arr)
        .map_err(|e| AppError::Internal(format!("getRandomValues failed: {e:?}")))?;
    Ok(arr.to_vec())
}
