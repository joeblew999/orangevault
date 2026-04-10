use serde::Serialize;
use worker::Response;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    /// 401 Unauthorized
    Unauthorized(String),
    /// 400 Bad Request
    BadRequest(String),
    /// 404 Not Found
    NotFound(String),
    /// 403 Forbidden
    Forbidden(String),
    /// 409 Conflict
    Conflict(String),
    /// 429 Too Many Requests
    TooManyRequests,
    /// 500 Internal Server Error
    Internal(String),
    /// OAuth-style error for identity endpoints
    OAuth {
        error: String,
        error_description: String,
        status: u16,
        two_factor_providers: Option<Vec<i32>>,
    },
}

/// Bitwarden-compatible ErrorModel for API endpoints.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorModel {
    message: String,
    validation_errors: Option<serde_json::Value>,
    exception_message: Option<String>,
    exception_stack_trace: Option<String>,
    inner_exception_message: Option<String>,
    object: String,
}

/// Bitwarden-compatible error response for API endpoints.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ApiErrorResponse {
    error_model: ErrorModel,
    object: String,
}

/// OAuth-style error response for identity endpoints.
#[derive(Debug, Serialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: String,
    #[serde(rename = "ErrorModel")]
    error_model: ErrorModel,
    #[serde(rename = "TwoFactorProviders", skip_serializing_if = "Option::is_none")]
    two_factor_providers: Option<Vec<i32>>,
    #[serde(rename = "Object")]
    object: String,
}

impl AppError {
    pub fn to_response(&self) -> worker::Result<Response> {
        match self {
            AppError::Unauthorized(msg) => {
                let body = api_error_json(msg);
                Response::from_json(&body).map(|r| r.with_status(401))
            }
            AppError::BadRequest(msg) => {
                let body = api_error_json(msg);
                Response::from_json(&body).map(|r| r.with_status(400))
            }
            AppError::NotFound(msg) => {
                let body = api_error_json(msg);
                Response::from_json(&body).map(|r| r.with_status(404))
            }
            AppError::Forbidden(msg) => {
                let body = api_error_json(msg);
                Response::from_json(&body).map(|r| r.with_status(403))
            }
            AppError::Conflict(msg) => {
                let body = api_error_json(msg);
                Response::from_json(&body).map(|r| r.with_status(409))
            }
            AppError::TooManyRequests => {
                let body = api_error_json("Too many requests.");
                Response::from_json(&body).map(|r| r.with_status(429))
            }
            AppError::Internal(msg) => {
                worker::console_error!("Internal error: {msg}");
                let body = api_error_json("An internal error occurred.");
                Response::from_json(&body).map(|r| r.with_status(500))
            }
            AppError::OAuth {
                error,
                error_description,
                status,
                two_factor_providers,
            } => {
                let body = OAuthErrorResponse {
                    error: error.clone(),
                    error_description: error_description.clone(),
                    error_model: ErrorModel {
                        message: error_description.clone(),
                        validation_errors: None,
                        exception_message: None,
                        exception_stack_trace: None,
                        inner_exception_message: None,
                        object: "error".into(),
                    },
                    two_factor_providers: two_factor_providers.clone(),
                    object: "error".into(),
                };
                Response::from_json(&body).map(|r| r.with_status(*status))
            }
        }
    }
}

fn api_error_json(message: &str) -> ApiErrorResponse {
    ApiErrorResponse {
        error_model: ErrorModel {
            message: message.into(),
            validation_errors: None,
            exception_message: None,
            exception_stack_trace: None,
            inner_exception_message: None,
            object: "error".into(),
        },
        object: "error".into(),
    }
}

/// Convert an AppError-based Result into a worker::Result<Response>,
/// rendering errors as proper HTTP error responses.
pub fn into_response(result: Result<Response>) -> worker::Result<Response> {
    match result {
        Ok(resp) => Ok(resp),
        Err(e) => e.to_response(),
    }
}

impl From<worker::Error> for AppError {
    fn from(e: worker::Error) -> Self {
        AppError::Internal(format!("Worker error: {e}"))
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            AppError::NotFound(msg) => write!(f, "Not found: {msg}"),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            AppError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            AppError::TooManyRequests => write!(f, "Too many requests"),
            AppError::Internal(msg) => write!(f, "Internal error: {msg}"),
            AppError::OAuth {
                error,
                error_description,
                ..
            } => write!(f, "OAuth error: {error}: {error_description}"),
        }
    }
}
