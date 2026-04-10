use worker::{Request, Response, RouteContext};

use crate::config::RequestContext;
use crate::db::queries;
use crate::error::{self, AppError};
use crate::models::config::{ConfigResponse, EnvironmentUrls, ServerInfo};
use crate::models::user::{PreloginRequest, PreloginResponse};

pub async fn get_config(
    _req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let domain = ctx.data.domain()?;
            let config = ConfigResponse {
                version: "2024.1.0".into(),
                git_hash: "".into(),
                server: ServerInfo {
                    name: "orangevault".into(),
                    url: "".into(),
                },
                environment: EnvironmentUrls {
                    api: format!("{domain}/api"),
                    identity: format!("{domain}/identity"),
                    notifications: format!("{domain}/notifications"),
                    sso: "".into(),
                },
                feature_states: serde_json::json!({}),
                object: "config".into(),
            };
            Ok(Response::from_json(&config)?)
        }
        .await,
    )
}

pub async fn prelogin(
    mut req: Request,
    ctx: RouteContext<RequestContext>,
) -> worker::Result<Response> {
    error::into_response(
        async {
            let body: PreloginRequest = req
                .json()
                .await
                .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

            let email = body.email.trim().to_lowercase();
            let db = ctx.data.db()?;
            let user = queries::find_user_by_email(&db, &email).await?;

            let response = match user {
                Some(u) => PreloginResponse {
                    kdf: u.client_kdf_type,
                    kdf_iterations: u.client_kdf_iter,
                    kdf_memory: u.client_kdf_memory,
                    kdf_parallelism: u.client_kdf_parallelism,
                },
                None => PreloginResponse {
                    kdf: 0,
                    kdf_iterations: 600000,
                    kdf_memory: None,
                    kdf_parallelism: None,
                },
            };
            Ok(Response::from_json(&response)?)
        }
        .await,
    )
}
