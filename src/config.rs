use worker::Env;

use crate::auth::guards::AuthenticatedUser;
use crate::error::{AppError, Result};

/// Client information extracted from Bitwarden-specific headers.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Request context carrying bindings and auth state through the request lifecycle.
pub struct RequestContext {
    pub env: Env,
    pub user: Option<AuthenticatedUser>,
    pub client_info: ClientInfo,
}

impl RequestContext {
    pub fn new(env: Env, client_info: ClientInfo) -> Self {
        Self {
            env,
            user: None,
            client_info,
        }
    }

    pub fn authenticated(&self) -> Result<&AuthenticatedUser> {
        self.user
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".into()))
    }

    pub fn db(&self) -> Result<worker::D1Database> {
        self.env
            .d1("DB")
            .map_err(|e| AppError::Internal(format!("D1 binding error: {e}")))
    }

    pub fn kv(&self) -> Result<worker::kv::KvStore> {
        self.env
            .kv("CACHE")
            .map_err(|e| AppError::Internal(format!("KV binding error: {e}")))
    }

    pub fn r2(&self) -> Result<worker::Bucket> {
        self.env
            .bucket("FILES")
            .map_err(|e| AppError::Internal(format!("R2 binding error: {e}")))
    }

    pub fn var(&self, name: &str) -> Result<String> {
        self.env
            .var(name)
            .map(|v| v.to_string())
            .map_err(|e| AppError::Internal(format!("Missing var {name}: {e}")))
    }

    pub fn secret(&self, name: &str) -> Result<String> {
        self.env
            .secret(name)
            .map(|v| v.to_string())
            .map_err(|e| AppError::Internal(format!("Missing secret {name}: {e}")))
    }

    pub fn domain(&self) -> Result<String> {
        self.var("DOMAIN")
    }

    pub fn domain_origin(&self) -> Result<String> {
        let domain = self.domain()?;
        let url = worker::Url::parse(&domain)
            .map_err(|e| AppError::Internal(format!("Invalid DOMAIN {domain}: {e}")))?;
        Ok(url.origin().ascii_serialization())
    }

    pub fn signups_allowed(&self) -> bool {
        self.var("SIGNUPS_ALLOWED")
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    pub fn web_vault_enabled(&self) -> bool {
        self.var("WEB_VAULT_ENABLED")
            .map(|v| v == "true")
            .unwrap_or(true)
    }
}
