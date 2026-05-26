//! orangevault-cli — operator CLI for the orangevault server.
//!
//! Currently implements:
//!   register   create a real Bitwarden-compatible account on orangevault
//!              (replaces the missing `bw register` step so account creation
//!              is fully scriptable end-to-end)
//!
//! Crypto leans on the `rbw` library for the well-tested PBKDF2/Argon2
//! master-key derivation; the symmetric-key encryption (CipherString
//! format) and RSA keypair generation are done inline here.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::{Parser, Subcommand};
use rbw::api::KdfType;
use rbw::identity::Identity;
use rbw::locked::Password;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "orangevault-cli", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register a new account on an orangevault server.
    Register {
        /// Server base URL, e.g. https://orangevault.gedw99.workers.dev
        #[arg(long, env = "OV_SERVER")]
        server: String,

        /// Account email.
        #[arg(long, env = "OV_EMAIL")]
        email: String,

        /// Master password. Reads from stdin if omitted.
        #[arg(long, env = "OV_MASTER_PASSWORD")]
        password: Option<String>,

        /// Display name.
        #[arg(long, default_value = "")]
        name: String,

        /// KDF iterations (PBKDF2-HMAC-SHA256). 600_000 matches the
        /// current Bitwarden default.
        #[arg(long, default_value_t = 600_000)]
        kdf_iterations: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Register {
            server,
            email,
            password,
            name,
            kdf_iterations,
        } => {
            let password = match password {
                Some(p) => p,
                None => prompt_password()?,
            };
            register(&server, &email, &password, &name, kdf_iterations).await
        }
    }
}

fn make_password(s: &str) -> Password {
    let mut v = rbw::locked::Vec::new();
    v.extend(s.as_bytes().iter().copied());
    Password::new(v)
}

fn prompt_password() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let mut stderr = std::io::stderr();
    if std::io::stdin().is_terminal() {
        write!(stderr, "master password: ")?;
        stderr.flush()?;
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches('\n').to_string())
}

async fn register(
    server: &str,
    email: &str,
    password: &str,
    name: &str,
    kdf_iterations: u32,
) -> Result<()> {
    // 1. Derive the master key + master_password_hash via rbw.
    let pw = make_password(password);
    let identity = Identity::new(email, &pw, KdfType::Pbkdf2, kdf_iterations, None, None)
        .map_err(|e| anyhow::anyhow!("identity derivation: {e}"))?;

    let master_password_hash_b64 = B64.encode(identity.master_password_hash.hash());

    // 2. Generate a random 64-byte symmetric key (32 enc + 32 mac).
    use rand::RngCore;
    let mut sym_key = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut sym_key);

    // 3. Encrypt sym_key with the master key (AES-256-CBC + HMAC-SHA256).
    //    Bitwarden CipherString type 2 = "2.{iv}|{ct}|{mac}" (all base64).
    let key_cipherstring =
        encrypt_cipherstring_type2(identity.keys.enc_key(), identity.keys.mac_key(), &sym_key)?;

    // 4. Generate an RSA-2048 keypair.
    let mut rng = rand::rngs::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).context("RSA keygen")?;
    let pub_key = RsaPublicKey::from(&priv_key);

    // 5. SubjectPublicKeyInfo DER, base64'd (for the `publicKey` field).
    let pub_key_b64 = B64.encode(
        pub_key
            .to_public_key_der()
            .context("encode public key DER")?
            .as_bytes(),
    );

    // 6. Encrypt the private key with the sym_key (CipherString type 2).
    let priv_key_der = priv_key
        .to_pkcs8_der()
        .context("encode private key DER")?
        .as_bytes()
        .to_vec();
    let priv_enc = &sym_key[0..32];
    let priv_mac = &sym_key[32..64];
    let encrypted_private_key = encrypt_cipherstring_type2(priv_enc, priv_mac, &priv_key_der)?;

    // 7. POST /identity/accounts/register.
    let body = RegisterRequest {
        email: email.to_string(),
        name: if name.is_empty() {
            email.to_string()
        } else {
            name.to_string()
        },
        master_password_hash: master_password_hash_b64,
        master_password_hint: None,
        key: key_cipherstring,
        kdf: 0, // PBKDF2
        kdf_iterations,
        kdf_memory: None,
        kdf_parallelism: None,
        keys: KeyPair {
            public_key: pub_key_b64,
            encrypted_private_key,
        },
    };

    let url = format!("{}/identity/accounts/register", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()?;
    let res = client.post(&url).json(&body).send().await?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();

    if status.is_success() {
        eprintln!("✓ registered {email} on {server}");
        eprintln!();
        eprintln!("Next: log into the web vault, Settings → Security → Keys →");
        eprintln!("View API Key, save client_id/client_secret to fnox:");
        eprintln!("  fnox set --global -p keychain ORANGEVAULT_BW_CLIENTID");
        eprintln!("  fnox set --global -p keychain ORANGEVAULT_BW_CLIENTSECRET");
        Ok(())
    } else {
        bail!("register failed: HTTP {status}\n{text}");
    }
}

/// Bitwarden CipherString type 2: `2.{iv_b64}|{ct_b64}|{mac_b64}`.
/// AES-256-CBC over data with a random 16-byte IV; HMAC-SHA256 over (iv || ct).
fn encrypt_cipherstring_type2(enc_key: &[u8], mac_key: &[u8], data: &[u8]) -> Result<String> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use sha2::Sha256;

    if enc_key.len() != 32 {
        bail!("enc_key must be 32 bytes, got {}", enc_key.len());
    }
    if mac_key.len() != 32 {
        bail!("mac_key must be 32 bytes, got {}", mac_key.len());
    }

    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let ct = Aes256CbcEnc::new(enc_key.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(data);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .map_err(|e| anyhow::anyhow!("hmac key: {e}"))?;
    mac.update(&iv);
    mac.update(&ct);
    let mac_tag = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        B64.encode(iv),
        B64.encode(&ct),
        B64.encode(mac_tag),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    email: String,
    name: String,
    master_password_hash: String,
    master_password_hint: Option<String>,
    key: String,
    kdf: u32,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    keys: KeyPair,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyPair {
    public_key: String,
    encrypted_private_key: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ErrorResponse {
    #[serde(rename = "ErrorModel")]
    error_model: Option<serde_json::Value>,
    #[serde(rename = "Message")]
    message: Option<String>,
}
