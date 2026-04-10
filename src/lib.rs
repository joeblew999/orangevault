use worker::*;

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod middleware;
mod models;
mod util;

use config::RequestContext;
use middleware::cors;
use middleware::headers::extract_client_info;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let origin = req.headers().get("Origin").ok().flatten();

    if req.method() == Method::Options {
        return cors::preflight_response(origin.as_deref());
    }

    let client_info = extract_client_info(&req);

    let router = Router::with_data(RequestContext::new(env.clone(), client_info));

    let response = router
        // Health checks
        .get("/alive", |_, _| Response::ok(""))
        .get("/api/alive", |_, _| Response::ok(""))
        // Phase 1: Auth / Identity
        .get_async("/api/config", api::accounts::get_config)
        .post_async("/accounts/prelogin", api::accounts::prelogin)
        .post_async("/identity/accounts/register", api::identity::register)
        .post_async("/identity/connect/token", api::identity::connect_token)
        .run(req, env)
        .await;

    // Apply CORS headers to all responses
    match response {
        Ok(resp) => cors::apply_cors_headers(resp, origin.as_deref()),
        Err(e) => {
            console_error!("Router error: {e}");
            let err_resp = Response::error("Internal Server Error", 500)?;
            cors::apply_cors_headers(err_resp, origin.as_deref())
        }
    }
}
