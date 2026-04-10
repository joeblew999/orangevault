use crate::error::{AppError, Result};

use super::hmac::hmac_sha1;

const TOTP_PERIOD: u64 = 30;
const TOTP_DIGITS: u32 = 6;

/// Generate a TOTP code for the given secret and time.
pub async fn generate_totp(secret: &[u8], time: u64) -> Result<String> {
    let counter = time / TOTP_PERIOD;
    let counter_bytes = counter.to_be_bytes();
    let hmac = hmac_sha1(secret, &counter_bytes).await?;
    let code = truncate(&hmac);
    Ok(format!(
        "{:0>width$}",
        code % 10u32.pow(TOTP_DIGITS),
        width = TOTP_DIGITS as usize
    ))
}

/// Validate a TOTP code with ±1 step drift tolerance.
/// Returns true if valid for any of the 3 time windows.
pub async fn validate_totp(secret: &[u8], code: &str, time: u64) -> Result<bool> {
    // Check current step, one step back, one step forward
    for offset in [0i64, -1, 1] {
        let check_time = (time as i64 + offset * TOTP_PERIOD as i64) as u64;
        let expected = generate_totp(secret, check_time).await?;
        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Dynamic truncation per RFC 4226.
fn truncate(hmac: &[u8]) -> u32 {
    let offset = (hmac[hmac.len() - 1] & 0x0F) as usize;
    ((hmac[offset] as u32 & 0x7F) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[idx] as char);
    }
    result
}

pub fn base32_decode(encoded: &str) -> Result<Vec<u8>> {
    let mut buffer: u64 = 0;
    let mut bits = 0;
    let mut result = Vec::new();
    for ch in encoded.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            'a'..='z' => ch as u64 - 'a' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            '=' | ' ' => continue,
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Invalid base32 character: {ch}"
                )));
            }
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Ok(result)
}

fn random_base32(len: usize) -> Result<String> {
    let bytes = super::random::random_bytes(len)?;
    Ok(base32_encode(&bytes))
}

pub fn generate_totp_secret() -> Result<String> {
    random_base32(20)
}

pub fn generate_recovery_code() -> Result<String> {
    random_base32(20)
}
