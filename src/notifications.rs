use serde::{Deserialize, Serialize};
use std::time::Duration;
use worker::*;

const DEFAULT_PING_INTERVAL_SECS: u64 = 15;
pub const DO_BINDING: &str = "USER_NOTIFIER";
const NOTIFY_PATH: &str = "/notify";

/// Handshake response bytes: {}\x1E as binary (JSON empty object + record separator).
const HANDSHAKE_ACCEPT: &[u8] = &[0x7b, 0x7d, 0x1e];

/// Connection state attached to each WebSocket (survives DO hibernation).
#[derive(Serialize, Deserialize)]
struct ConnectionState {
    handshake_complete: bool,
}

/// Request body for the internal /notify endpoint.
#[derive(Serialize, Deserialize)]
pub struct NotifyRequest {
    pub notification_type: u8,
    pub context_id: String,
    pub payload: serde_json::Value,
}

// --- Notification types matching Bitwarden/Vaultwarden ---

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    #[allow(dead_code)]
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    #[allow(dead_code)]
    SyncCiphers = 4,
    SyncVault = 5,
    #[allow(dead_code)]
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    #[allow(dead_code)]
    SyncSettings = 10,
    #[allow(dead_code)]
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
}

// --- MessagePack SignalR framing ---

/// Encode a MessagePack value with VarInt length prefix (SignalR BinaryMessageFormat).
fn serialize_msgpack(value: &rmpv::Value) -> Vec<u8> {
    let mut msgpack_buf = Vec::new();
    rmpv::encode::write_value(&mut msgpack_buf, value).unwrap();

    let mut output = Vec::new();
    let mut len = msgpack_buf.len();
    loop {
        let mut byte = (len & 0x7F) as u8;
        len >>= 7;
        if len > 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if len == 0 {
            break;
        }
    }
    output.extend_from_slice(&msgpack_buf);
    output
}

/// Create a SignalR Invocation message for ReceiveMessage (matching Vaultwarden).
fn create_notification(
    notification_type: u8,
    context_id: &str,
    payload: &serde_json::Value,
) -> rmpv::Value {
    let payload_map = json_to_rmpv(payload);

    rmpv::Value::Array(vec![
        rmpv::Value::from(1),                // type: Invocation
        rmpv::Value::Map(vec![]),            // headers: empty
        rmpv::Value::Nil,                    // invocationId: null (fire-and-forget)
        rmpv::Value::from("ReceiveMessage"), // target
        rmpv::Value::Array(vec![
            // arguments
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("ContextId"),
                    rmpv::Value::from(context_id),
                ),
                (
                    rmpv::Value::from("Type"),
                    rmpv::Value::from(notification_type as i64),
                ),
                (rmpv::Value::from("Payload"), payload_map),
            ]),
        ]),
    ])
}

/// Create a SignalR Ping message (type 6).
fn create_ping() -> rmpv::Value {
    rmpv::Value::Array(vec![rmpv::Value::from(6)])
}

fn json_to_rmpv(val: &serde_json::Value) -> rmpv::Value {
    match val {
        serde_json::Value::Null => rmpv::Value::Nil,
        serde_json::Value::Bool(b) => rmpv::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rmpv::Value::from(i)
            } else if let Some(f) = n.as_f64() {
                rmpv::Value::from(f)
            } else {
                rmpv::Value::Nil
            }
        }
        serde_json::Value::String(s) => rmpv::Value::from(s.as_str()),
        serde_json::Value::Array(arr) => rmpv::Value::Array(arr.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(map) => {
            let entries: Vec<(rmpv::Value, rmpv::Value)> = map
                .iter()
                .map(|(k, v)| (rmpv::Value::from(k.as_str()), json_to_rmpv(v)))
                .collect();
            rmpv::Value::Map(entries)
        }
    }
}

// --- Durable Object ---

#[durable_object]
pub struct UserNotifier {
    state: State,
    env: Env,
}

impl DurableObject for UserNotifier {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        // WebSocket upgrade: distinguished by header, not path
        let is_ws = req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

        if is_ws {
            let pair = WebSocketPair::new()?;
            let server = pair.server;

            server.serialize_attachment(ConnectionState {
                handshake_complete: false,
            })?;

            self.state.accept_web_socket(&server);

            self.state
                .storage()
                .set_alarm(Duration::from_secs(self.ping_interval()))
                .await?;

            return Ok(ResponseBuilder::new()
                .with_status(101)
                .with_websocket(pair.client)
                .empty());
        }

        // Internal POST: notify connected clients
        let url = req.url()?;
        if url.path().ends_with(NOTIFY_PATH) {
            let body: NotifyRequest = req
                .json()
                .await
                .map_err(|e| Error::RustError(format!("bad notify body: {e}")))?;

            let msg = serialize_msgpack(&create_notification(
                body.notification_type,
                &body.context_id,
                &body.payload,
            ));

            for ws in self.state.get_websockets() {
                if let Ok(Some(state)) = ws.deserialize_attachment::<ConnectionState>()
                    && state.handshake_complete
                {
                    let _ = ws.send_with_bytes(&msg);
                }
            }

            return Response::ok("sent");
        }

        Response::error("not found", 404)
    }

    async fn websocket_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        let mut conn_state =
            ws.deserialize_attachment::<ConnectionState>()?
                .unwrap_or(ConnectionState {
                    handshake_complete: false,
                });

        if !conn_state.handshake_complete {
            // First message: JSON text handshake {"protocol":"messagepack","version":1}\x1E
            // Accept unconditionally with {}\x1E as binary bytes.
            match msg {
                WebSocketIncomingMessage::String(_) | WebSocketIncomingMessage::Binary(_) => {
                    ws.send_with_bytes(HANDSHAKE_ACCEPT)?;
                    conn_state.handshake_complete = true;
                    ws.serialize_attachment(&conn_state)?;
                }
            }
            return Ok(());
        }

        // Post-handshake: binary MessagePack frames from client.
        // Bitwarden clients only send Ping ([6]) — no invocations.
        // We ignore all client messages after handshake.
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let websockets = self.state.get_websockets();
        if websockets.is_empty() {
            return Response::empty();
        }

        let ping = serialize_msgpack(&create_ping());
        for ws in &websockets {
            if let Ok(Some(state)) = ws.deserialize_attachment::<ConnectionState>()
                && state.handshake_complete
            {
                let _ = ws.send_with_bytes(&ping);
            }
        }

        self.state
            .storage()
            .set_alarm(Duration::from_secs(self.ping_interval()))
            .await?;

        Response::empty()
    }
}

impl UserNotifier {
    fn ping_interval(&self) -> u64 {
        self.env
            .var("PING_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(DEFAULT_PING_INTERVAL_SECS)
    }
}

// --- Helper for API handlers to send notifications ---

/// Send a notification to a user's Durable Object.
/// Fire-and-forget — errors are logged but not propagated.
pub async fn send_notification(
    env: &Env,
    user_uuid: &str,
    update_type: UpdateType,
    context_id: &str,
    payload: serde_json::Value,
) {
    let result: Result<()> = async {
        let ns = env.durable_object(DO_BINDING)?;
        let stub = ns.id_from_name(user_uuid)?.get_stub()?;

        let body_json = serde_json::to_string(&NotifyRequest {
            notification_type: update_type as u8,
            context_id: context_id.to_string(),
            payload,
        })
        .map_err(|e| Error::RustError(e.to_string()))?;

        let mut init = RequestInit::new();
        init.method = Method::Post;
        init.body = Some(wasm_bindgen::JsValue::from_str(&body_json));
        init.headers.set("Content-Type", "application/json")?;

        let req = Request::new_with_init(&format!("https://do{NOTIFY_PATH}"), &init)?;
        let _resp = stub.fetch_with_request(req).await?;
        Ok(())
    }
    .await;

    if let Err(e) = result {
        console_error!("notification error for {user_uuid}: {e}");
    }
}
