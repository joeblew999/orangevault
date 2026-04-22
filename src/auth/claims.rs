use serde::{Deserialize, Serialize};

/// Standard JWT claims for login tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginClaims {
    /// Not before (epoch seconds)
    pub nbf: i64,
    /// Expiration (epoch seconds)
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Subject (user UUID)
    pub sub: String,
    /// Token type: "access_token"
    pub r#type: String,
    /// Premium status
    pub premium: bool,
    /// User name
    pub name: String,
    /// User email
    pub email: String,
    /// Email verified
    pub email_verified: bool,
    /// Security stamp (invalidation token)
    pub sstamp: String,
    /// Device identifier
    pub device: String,
    /// Granted scopes
    pub scope: Vec<String>,
    /// Authorized organization IDs
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub orgowner: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub orgadmin: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub orguser: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub orgmanager: Vec<String>,
}

/// Claims for refresh tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub r#type: String,
    /// Device UUID (links refresh token to device)
    pub token: String,
    /// Unique token ID (ensures each refresh token is distinct)
    pub jti: String,
}

/// Claims for invite tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub r#type: String,
    pub email: String,
    pub org_id: String,
}

/// `sub` holds the lowercased email so `register/finish` can reject a token
/// whose email was tampered with in the finish request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub r#type: String,
    pub name: Option<String>,
    pub verified: bool,
}

/// `sub` holds `"{send_id}/{file_id}"` so the token is bound to one object
/// and can't be replayed against a different file on the same endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendAccessClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub r#type: String,
}
