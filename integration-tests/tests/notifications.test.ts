import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { mf, mfUrl } from "./mf";
import {
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
  futureIso,
} from "./helpers";

let authToken: string;
let userEmail: string;

beforeAll(async () => {
  await applyMigrations();

  const user = generateTestUser("notif");
  const regRes = await registerUser(user);
  expect(regRes.status).toBe(200);

  const loginRes = await loginUser(user.email, user.masterPasswordHash);
  expect(loginRes.status).toBe(200);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
  userEmail = user.email;
});

// --- WebSocket helper for MessagePack SignalR ---

interface NotifConnection {
  ws: WebSocket;
  binaryMessages: Uint8Array[];
  close: () => void;
  waitForBinary: (timeoutMs?: number) => Promise<Uint8Array>;
}

function connectHub(token: string): Promise<NotifConnection> {
  const wsUrl = mfUrl.replace("http://", "ws://");

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(
      `${wsUrl}/notifications/hub?access_token=${token}`,
    );
    const binaryMessages: Uint8Array[] = [];
    let handshakeDone = false;

    const binaryWaiters: Array<{
      resolve: (data: Uint8Array) => void;
      reject: (err: Error) => void;
    }> = [];

    ws.binaryType = "arraybuffer";

    ws.addEventListener("message", (event) => {
      if (!handshakeDone) {
        // First message is handshake response: {}\x1E as bytes
        handshakeDone = true;
        resolve(conn);
        return;
      }

      if (event.data instanceof ArrayBuffer) {
        const data = new Uint8Array(event.data);
        binaryMessages.push(data);
        // Notify waiters
        for (let i = binaryWaiters.length - 1; i >= 0; i--) {
          binaryWaiters[i].resolve(data);
          binaryWaiters.splice(i, 1);
        }
      }
    });

    ws.addEventListener("error", () => {
      if (!handshakeDone) {
        reject(new Error("WebSocket error during handshake"));
      }
    });

    ws.addEventListener("open", () => {
      // Send SignalR handshake: {"protocol":"messagepack","version":1}\x1E
      ws.send('{"protocol":"messagepack","version":1}\x1E');
    });

    const conn: NotifConnection = {
      ws,
      binaryMessages,
      close() {
        ws.close();
      },
      waitForBinary(timeoutMs = 5000): Promise<Uint8Array> {
        // Check already-received
        if (binaryMessages.length > 0) {
          return Promise.resolve(binaryMessages[binaryMessages.length - 1]);
        }
        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            reject(
              new Error(
                `Timed out waiting for binary message (${timeoutMs}ms). Got ${binaryMessages.length} messages.`,
              ),
            );
          }, timeoutMs);

          binaryWaiters.push({
            resolve: (data) => {
              clearTimeout(timer);
              resolve(data);
            },
            reject,
          });
        });
      },
    };
  });
}

// --- Tests ---

describe("Notifications WebSocket Hub", () => {
  let conn: NotifConnection | undefined;

  afterEach(() => {
    conn?.close();
    conn = undefined;
  });

  it("completes MessagePack handshake", async () => {
    conn = await connectHub(authToken);
    // If we reach here, the handshake succeeded
    expect(conn.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("rejects unauthenticated connections", async () => {
    await expect(connectHub("invalid-token")).rejects.toThrow();
  });

  it("receives ping after connection", async () => {
    conn = await connectHub(authToken);

    // PING_INTERVAL_SECS=1 in test config, so alarm fires quickly.
    const msg = await conn.waitForBinary(5_000);
    expect(msg).toBeDefined();
    expect(msg.length).toBeGreaterThan(0);

    // A SignalR ping in MessagePack is: [VarInt length][msgpack [6]]
    // msgpack encoding of [6] is: 0x91 0x06 (fixarray(1) + fixint(6))
    // With VarInt prefix: 0x02 0x91 0x06
    expect(msg[0]).toBe(0x02); // VarInt: length = 2
    expect(msg[1]).toBe(0x91); // msgpack fixarray(1)
    expect(msg[2]).toBe(0x06); // msgpack fixint(6) = Ping
  });

  it("receives notification when cipher is created", async () => {
    conn = await connectHub(authToken);

    // Clear any initial messages (ping may arrive first)
    conn.binaryMessages.length = 0;

    // Create a cipher — this should trigger a SyncCipherCreate notification
    const res = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.notif_cipher",
        login: { username: "2.u", password: "2.p" },
      },
    });
    expect(res.status).toBe(200);
    const cipher = (await res.json()) as Record<string, unknown>;

    // Wait for a notification binary message
    const msg = await conn.waitForBinary(5000);
    expect(msg).toBeDefined();
    expect(msg.length).toBeGreaterThan(3);

    // The notification should be a SignalR Invocation (type 1) for ReceiveMessage.
    // We can verify it's a valid VarInt-prefixed MessagePack message.
    // First byte(s) are VarInt length, then MessagePack payload.
    // The payload is an array starting with fixint(1) = Invocation type.
    // Find the msgpack payload start (skip VarInt prefix)
    let offset = 0;
    while (offset < msg.length && (msg[offset] & 0x80) !== 0) {
      offset++;
    }
    offset++; // skip last VarInt byte

    // The msgpack payload should start with a fixarray marker (0x95 = array of 5)
    expect(msg[offset]).toBe(0x95); // fixarray(5) = [type, headers, invocationId, target, args]
    expect(msg[offset + 1]).toBe(0x01); // fixint(1) = Invocation type
  });

  it("receives notification when folder is created", async () => {
    conn = await connectHub(authToken);
    conn.binaryMessages.length = 0;

    const res = await authenticatedFetch("/api/folders", authToken, {
      method: "POST",
      body: { name: "2.notif_folder" },
    });
    expect(res.status).toBe(200);

    const msg = await conn.waitForBinary(5000);
    expect(msg).toBeDefined();
    expect(msg.length).toBeGreaterThan(3);
  });

  it("receives notification when send is created", async () => {
    conn = await connectHub(authToken);
    conn.binaryMessages.length = 0;

    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.notif_send_key",
        name: "2.notif_send",
        text: { text: "2.text" },
        deletionDate: futureIso(),
      },
    });
    expect(res.status).toBe(200);

    const msg = await conn.waitForBinary(5000);
    expect(msg).toBeDefined();
    expect(msg.length).toBeGreaterThan(3);
  });
});
