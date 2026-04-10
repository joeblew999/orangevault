use worker::Request;

use crate::config::ClientInfo;

/// Extract Bitwarden client info from request headers.
pub fn extract_client_info(req: &Request) -> ClientInfo {
    let headers = req.headers();
    ClientInfo {
        name: headers.get("Bitwarden-Client-Name").ok().flatten(),
        version: headers.get("Bitwarden-Client-Version").ok().flatten(),
    }
}
