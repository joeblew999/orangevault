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
    /// Token identifier for revocation
    pub token: String,
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
