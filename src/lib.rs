use worker::*;

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod middleware;
mod models;
pub mod notifications;
mod util;

use config::RequestContext;
use middleware::cors;
use middleware::headers::extract_client_info;

mod jobs;

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
        .get("/alive", |_, _| Response::ok(""))
        .get("/api/alive", |_, _| Response::ok(""))
        .get_async("/api/config", api::accounts::get_config)
        .post_async("/accounts/prelogin", api::accounts::prelogin)
        .post_async("/identity/accounts/register", api::identity::register)
        .post_async("/identity/connect/token", api::identity::connect_token)
        .get_async("/api/accounts/profile", api::accounts::get_profile)
        .put_async("/api/accounts/profile", api::accounts::put_profile)
        .post_async("/api/accounts/password", api::accounts::post_password)
        .put_async("/api/accounts/kdf", api::accounts::put_kdf)
        .put_async("/api/accounts/keys", api::accounts::put_keys)
        .post_async(
            "/api/accounts/verify-password",
            api::accounts::verify_password,
        )
        .post_async(
            "/api/accounts/security-stamp",
            api::accounts::post_security_stamp,
        )
        .post_async("/api/accounts/api-key", api::accounts::post_api_key)
        .post_async(
            "/api/accounts/rotate-api-key",
            api::accounts::rotate_api_key,
        )
        .delete_async("/api/accounts", api::accounts::delete_account)
        .get_async(
            "/api/accounts/revision-date",
            api::accounts::get_revision_date,
        )
        .get_async("/api/settings/domains", api::accounts::get_domains)
        .post_async("/api/settings/domains", api::accounts::post_domains)
        .put_async("/api/settings/domains", api::accounts::post_domains)
        .get_async("/api/sync", api::sync::sync)
        .get_async("/api/folders", api::folders::get_folders)
        .post_async("/api/folders", api::folders::post_folder)
        .put_async("/api/folders/:id", api::folders::put_folder)
        .delete_async("/api/folders/:id", api::folders::delete_folder)
        // Ciphers: static paths must precede parameterized :id routes
        .get_async("/api/ciphers", api::ciphers::get_ciphers)
        .post_async("/api/ciphers", api::ciphers::post_cipher)
        .post_async("/api/ciphers/purge", api::ciphers::purge_ciphers)
        .put_async("/api/ciphers/move", api::ciphers::bulk_move)
        .put_async("/api/ciphers/delete", api::ciphers::bulk_soft_delete)
        .put_async("/api/ciphers/restore", api::ciphers::bulk_restore)
        .post_async("/api/ciphers/import", api::ciphers::import_ciphers)
        .post_async(
            "/api/ciphers/:id/attachment/v2",
            api::ciphers::post_attachment_v2,
        )
        .post_async(
            "/api/ciphers/:id/attachment/:att_id",
            api::ciphers::upload_attachment,
        )
        .get_async(
            "/api/ciphers/:id/attachment/:att_id",
            api::ciphers::get_attachment,
        )
        .delete_async(
            "/api/ciphers/:id/attachment/:att_id",
            api::ciphers::delete_attachment,
        )
        .post_async(
            "/api/ciphers/:id/collections",
            api::ciphers::post_cipher_collections,
        )
        .post_async(
            "/api/ciphers/:id/collections-admin",
            api::ciphers::post_cipher_collections_admin,
        )
        .put_async("/api/ciphers/:id/share", api::organizations::share_cipher)
        .post_async("/api/ciphers/:id/share", api::organizations::share_cipher)
        .get_async("/api/ciphers/:id", api::ciphers::get_cipher)
        .put_async("/api/ciphers/:id", api::ciphers::put_cipher)
        .delete_async("/api/ciphers/:id", api::ciphers::delete_cipher)
        .put_async("/api/ciphers/:id/delete", api::ciphers::soft_delete_cipher)
        .put_async("/api/ciphers/:id/restore", api::ciphers::restore_cipher)
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
        .put_async(
            "/api/two-factor/disable",
            api::two_factor::disable_two_factor,
        )
        .post_async("/api/two-factor/recover", api::two_factor::post_recover)
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
        .post_async(
            "/api/organizations/:org_id/users/invite",
            api::organizations::invite_member,
        )
        .post_async(
            "/api/organizations/:org_id/users/:member_id/accept",
            api::organizations::accept_invite,
        )
        .post_async(
            "/api/organizations/:org_id/users/:member_id/confirm",
            api::organizations::confirm_member,
        )
        .post_async(
            "/api/organizations/:org_id/users/:member_id/reinvite",
            api::organizations::reinvite_member,
        )
        .get_async(
            "/api/organizations/:org_id/users/:member_id",
            api::organizations::get_member,
        )
        .put_async(
            "/api/organizations/:org_id/users/:member_id",
            api::organizations::update_member,
        )
        .delete_async(
            "/api/organizations/:org_id/users/:member_id",
            api::organizations::remove_member,
        )
        .put_async(
            "/api/organizations/:org_id/collections/:col_id/users",
            api::organizations::set_collection_users,
        )
        .get_async(
            "/api/organizations/:org_id/collections/:col_id/users",
            api::organizations::get_collection_users,
        )
        .put_async(
            "/api/organizations/:org_id/collections/:col_id",
            api::organizations::update_collection,
        )
        .get_async(
            "/api/organizations/:org_id/policies",
            api::organizations::get_policies,
        )
        .put_async(
            "/api/organizations/:org_id/policies/:type",
            api::organizations::put_policy,
        )
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
        .post_async("/api/collect", api::events::collect_events)
        .get_async(
            "/api/organizations/:org_id/events",
            api::events::get_org_events,
        )
        .get_async("/icons/:domain/icon.png", api::icons::get_icon)
        .get_async("/notifications/hub", api::notifications::hub)
        .run(req, env)
        .await;

    // WebSocket 101 responses have immutable headers, so CORS can't be applied.
    match response {
        Ok(resp) if resp.status_code() == 101 => Ok(resp),
        Ok(resp) => cors::apply_cors_headers(resp, origin.as_deref()),
        Err(e) => {
            console_error!("Router error: {e}");
            let err_resp = Response::error("Internal Server Error", 500)?;
            cors::apply_cors_headers(err_resp, origin.as_deref())
        }
    }
}
