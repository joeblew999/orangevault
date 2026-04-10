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
        // Phase 2: Sync
        .get_async("/api/sync", api::sync::sync)
        // Phase 2: Folders
        .get_async("/api/folders", api::folders::get_folders)
        .post_async("/api/folders", api::folders::post_folder)
        .put_async("/api/folders/:id", api::folders::put_folder)
        .delete_async("/api/folders/:id", api::folders::delete_folder)
        // Phase 2: Ciphers
        .get_async("/api/ciphers", api::ciphers::get_ciphers)
        .get_async("/api/ciphers/:id", api::ciphers::get_cipher)
        .post_async("/api/ciphers", api::ciphers::post_cipher)
        .put_async("/api/ciphers/:id", api::ciphers::put_cipher)
        .delete_async("/api/ciphers/:id", api::ciphers::delete_cipher)
        .put_async("/api/ciphers/:id/delete", api::ciphers::soft_delete_cipher)
        .put_async("/api/ciphers/:id/restore", api::ciphers::restore_cipher)
        .post_async("/api/ciphers/purge", api::ciphers::purge_ciphers)
        .put_async("/api/ciphers/:id/share", api::organizations::share_cipher)
        .post_async("/api/ciphers/:id/share", api::organizations::share_cipher)
        // Phase 4: Two-Factor Auth
        .get_async("/api/two-factor", api::two_factor::get_two_factor)
        .post_async(
            "/api/two-factor/get-authenticator",
            api::two_factor::get_authenticator,
        )
        .post_async(
            "/api/two-factor/authenticator",
            api::two_factor::post_authenticator,
        )
        .put_async(
            "/api/two-factor/authenticator",
            api::two_factor::post_authenticator,
        )
        .post_async("/api/two-factor/get-recover", api::two_factor::get_recover)
        // Phase 3: Organizations
        .post_async("/api/organizations", api::organizations::post_organization)
        .get_async(
            "/api/organizations/:org_id",
            api::organizations::get_organization,
        )
        .delete_async(
            "/api/organizations/:org_id",
            api::organizations::delete_organization,
        )
        .get_async(
            "/api/organizations/:org_id/collections",
            api::organizations::get_collections,
        )
        .post_async(
            "/api/organizations/:org_id/collections",
            api::organizations::post_collection,
        )
        .delete_async(
            "/api/organizations/:org_id/collections/:col_id",
            api::organizations::delete_collection,
        )
        .get_async(
            "/api/organizations/:org_id/users",
            api::organizations::get_members,
        )
        // Phase 5: Sends (specific routes before parameterized ones)
        .get_async("/api/sends", api::sends::get_sends)
        .post_async("/api/sends", api::sends::post_send)
        .post_async("/api/sends/file/v2", api::sends::post_send_file_v2)
        .post_async("/api/sends/access/:access_id", api::sends::post_access)
        .post_async(
            "/api/sends/:send_id/file/:file_id",
            api::sends::post_send_file,
        )
        .post_async(
            "/api/sends/:send_id/access/file/:file_id",
            api::sends::post_access_file,
        )
        .get_async("/api/sends/:send_id/:file_id", api::sends::get_send_file)
        .put_async(
            "/api/sends/:id/remove-password",
            api::sends::put_send_remove_password,
        )
        .get_async("/api/sends/:id", api::sends::get_send)
        .put_async("/api/sends/:id", api::sends::put_send)
        .delete_async("/api/sends/:id", api::sends::delete_send)
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
