//! The simulated `https` program (design `http-target` §5, §5.1, §9): the descriptor-driven
//! fake platform store the runner's fake HTTPS attempt reaches under `OPV_SIM_WORLD`.
//!
//! The runner calls it like any other external tool: argv is the HTTP method and the
//! host-plus-path URI, the header pairs travel in the environment (the `Authorization` value
//! is compared and never written anywhere) and the gRPC-Web request body arrives on stdin.
//! The reply is the fixed stdout envelope [`opv::runner_https::encode_reply`] writes, so the
//! same runner path decodes it.
//!
//! The store lives in the simulator's `sim-state.json`, not in `world.json`: one entry per
//! provider, `{provider, version, status, configured}`. `world.json`'s `http` section names
//! the pinned descriptor, the tenant `operator_id`, the accepted `token`, the `providers`
//! the store serves and the `rejected` providers a Save marks `CONNECTION_STATUS_REJECTED`.
//! A Save whose `expected_version` no longer matches replies `ALREADY_EXISTS` (6) as a
//! `0x80` body trailer, exactly as the recorded Zonetico replies do
//! (`tests/fixtures/https/zonetico/README.md`). No secret value is ever stored or echoed:
//! the reply carries the provider, version and status only, never `masked_key`.
//!
//! ```json
//! "http": {
//!   "descriptor": "tests/fixtures/https/zonetico/platform_console.binpb",
//!   "operator_id": "00000000-0000-4000-8000-000000000000",
//!   "token": "CANARY-TOKEN-0123456789",
//!   "providers": ["openrouter", "tavily", "stripe"],
//!   "rejected": ["tavily"]
//! }
//! ```

use std::path::{Path, PathBuf};

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, Value};
use serde_json::{Map, Value as Json, json};
use zeroize::Zeroizing;

use crate::faults::Kind;
use crate::recordings::Reply;
use crate::world::World;

/// The two RPCs the fake store serves (design §3.1).
const LIST: &str = "portal.v1.PlatformConsoleService/ListPlatformConnections";
const SAVE: &str = "portal.v1.PlatformConsoleService/SavePlatformConnection";

/// The gRPC-Web content type every reply carries (design §5.1).
const GRPC_WEB: &str = "application/grpc-web+proto";

/// The `ConnectionStatus` enum values the store uses (design §3.1).
const NOT_CONFIGURED: &str = "CONNECTION_STATUS_NOT_CONFIGURED";
const VERIFIED: &str = "CONNECTION_STATUS_VERIFIED";
const REJECTED: &str = "CONNECTION_STATUS_REJECTED";

/// gRPC status codes the store replies with (design §8).
const ALREADY_EXISTS: i32 = 6;
const UNAUTHENTICATED: i32 = 16;

/// The call words a fault matches: the HTTP method and the RPC path, host left out, so a
/// fault names `POST portal.v1.PlatformConsoleService/SavePlatformConnection`.
pub fn call_words(args: &[String]) -> Vec<String> {
    match args {
        [method, uri, ..] => vec![method.clone(), rpc_path(uri).to_string()],
        _ => args.to_vec(),
    }
}

/// The RPC path of a host-plus-path URI, scheme and authority left out.
fn rpc_path(uri: &str) -> &str {
    let rest = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    match rest.find('/') {
        Some(at) => &rest[at + 1..],
        None => rest,
    }
}

/// Run one `https` call: read the request from stdin and the headers from the environment,
/// answer from the store in `sim-state.json` (design §5).
pub fn run(world: &mut World, args: &[String]) -> Reply {
    let mut body = Vec::new();
    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut body);
    let method = args.first().map(String::as_str).unwrap_or_default();
    let rpc = args.get(1).map(|uri| rpc_path(uri)).unwrap_or_default();
    let authorization = authorization();
    let mut state = world.state();
    let reply = serve(
        &world.doc,
        &mut state,
        method,
        rpc,
        authorization.as_deref(),
        &body,
    );
    world.set_state(&state);
    reply
}

/// The `Authorization` header pair the runner put in the environment. The value is only
/// ever compared, never logged or written (design §4.1).
fn authorization() -> Option<String> {
    ["Authorization", "authorization"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
}

/// The header value must be the world's token, with or without the `Bearer ` scheme the
/// login adds (design §4.1).
fn authorized(doc: &Json, header: Option<&str>) -> bool {
    let Some(expected) = doc["token"].as_str() else {
        return false;
    };
    let Some(header) = header else {
        return false;
    };
    header == expected || header.strip_prefix("Bearer ") == Some(expected)
}

/// Answer one call from the world's `http` section and the store in `state` (design §5.1).
fn serve(
    doc: &Json,
    state: &mut Json,
    method: &str,
    rpc: &str,
    authorization: Option<&str>,
    body: &[u8],
) -> Reply {
    if !authorized(doc, authorization) {
        return error(UNAUTHENTICATED, "Sign in again");
    }
    let pool = match descriptor_pool(doc) {
        Ok(pool) => pool,
        Err(reply) => return reply,
    };
    match rpc {
        LIST => list(doc, state, &pool),
        SAVE => save(doc, state, &pool, body),
        _ => Reply::no_recording(&format!("https {method} {rpc}"), "https/zonetico"),
    }
}

/// The pinned descriptor set named in `world.json`, resolved from this checkout when the
/// path is relative.
fn descriptor_pool(doc: &Json) -> Result<DescriptorPool, Reply> {
    let name = doc["descriptor"].as_str().unwrap_or_default();
    let path = Path::new(name);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
    };
    let bytes = std::fs::read(&full)
        .map_err(|_| Reply::no_recording("the descriptor named in world.json", "https"))?;
    DescriptorPool::decode(bytes.as_slice())
        .map_err(|_| Reply::no_recording("the descriptor could not be read", "https"))
}

/// The world's providers, in order.
fn providers(doc: &Json) -> Vec<String> {
    doc["providers"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a Save of `provider` is rejected by the world (design §6).
fn rejected(doc: &Json, provider: &str) -> bool {
    doc["rejected"]
        .as_array()
        .is_some_and(|rs| rs.iter().any(|r| r.as_str() == Some(provider)))
}

/// `ListPlatformConnections`: seed a store entry for every provider and reply with all of
/// them, version and status read from the store (design §5.1, §6).
fn list(doc: &Json, state: &mut Json, pool: &DescriptorPool) -> Reply {
    let providers = providers(doc);
    let mut connections = Vec::with_capacity(providers.len());
    {
        let entries = entries_mut(state);
        for provider in &providers {
            entries
                .entry(provider.clone())
                .or_insert_with(|| entry(provider, 0, NOT_CONFIGURED, false));
        }
        for provider in &providers {
            let stored = entries.get(provider).cloned().unwrap_or_default();
            let version = stored["version"].as_i64().unwrap_or(0);
            let status = stored["status"].as_str().unwrap_or(NOT_CONFIGURED);
            connections.push(connection_message(pool, provider, version, status));
        }
    }
    let message = connections_message(pool, connections);
    ok(&message)
}

/// `SavePlatformConnection`: conflict when the listed version is stale, else bump it and
/// mark the provider verified (or rejected, when the world says so) (design §6, §9).
fn save(doc: &Json, state: &mut Json, pool: &DescriptorPool, body: &[u8]) -> Reply {
    let request = match decode_request(pool, SAVE, body) {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    let provider = request
        .get_field_by_name("provider")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let expected = request
        .get_field_by_name("expected_version")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // A `version_bumped` fault arms this flag: bump the target before the write, so the
    // request's expected version is stale and the write conflicts (design §6, §9).
    if state["http"]["bump_before_save"].as_bool().unwrap_or(false) {
        {
            let entries = entries_mut(state);
            let stored = entries
                .entry(provider.clone())
                .or_insert_with(|| entry(&provider, 0, NOT_CONFIGURED, false));
            let bumped = stored["version"].as_i64().unwrap_or(0) + 1;
            stored["version"] = json!(bumped);
        }
        state["http"]["bump_before_save"] = json!(false);
    }

    let current = state["http"]["entries"]
        .get(provider.as_str())
        .and_then(|stored| stored["version"].as_i64())
        .unwrap_or(0);
    if expected != current {
        return error(
            ALREADY_EXISTS,
            "This connection changed; reload before saving",
        );
    }

    let status = if rejected(doc, &provider) {
        REJECTED
    } else {
        VERIFIED
    };
    let version = current + 1;
    entries_mut(state).insert(provider.clone(), entry(&provider, version, status, true));
    let connection = connection_message(pool, &provider, version, status);
    let message = result_message(pool, connection);
    ok(&message)
}

/// Arm the `version_bumped` fault: the next Save bumps its provider's stored version before
/// the write, so the listed version no longer matches (design §6, §9).
pub fn arm_version_bump(world: &mut World) {
    let mut state = world.state();
    arm_bump(&mut state);
    world.set_state(&state);
}

/// Set the store's bump flag in `state`.
fn arm_bump(state: &mut Json) {
    if !state.is_object() {
        *state = json!({});
    }
    let root = state.as_object_mut().expect("an object");
    let http = root.entry("http").or_insert_with(|| json!({}));
    if !http.is_object() {
        *http = json!({});
    }
    http.as_object_mut()
        .expect("an object")
        .insert("bump_before_save".to_string(), json!(true));
}

/// A fault's reply, for the kinds the generic runner path does not handle itself.
pub fn fault(kind: Kind, _world: &World, args: &[String]) -> Reply {
    let words = call_words(args).join(" ");
    match kind {
        Kind::CredentialRejected => error(UNAUTHENTICATED, "Sign in again"),
        Kind::Forbidden => error(7, "Platform operator required"),
        Kind::NotFound => error(5, "No such connection"),
        Kind::Unreachable | Kind::ServerError => error(14, "The service is unavailable"),
        Kind::RateLimited => error(8, "Rate limited"),
        _ => Reply::no_recording(
            &format!("{} on https {words}", kind.name()),
            "https/zonetico",
        ),
    }
}

/// One store entry: `{provider, version, status, configured}`.
fn entry(provider: &str, version: i64, status: &str, configured: bool) -> Json {
    json!({
        "provider": provider,
        "version": version,
        "status": status,
        "configured": configured,
    })
}

/// The store's entry map in `sim-state.json`, created when absent.
fn entries_mut(state: &mut Json) -> &mut Map<String, Json> {
    if !state.is_object() {
        *state = json!({});
    }
    let root = state.as_object_mut().expect("an object");
    let http = root.entry("http").or_insert_with(|| json!({}));
    if !http.is_object() {
        *http = json!({});
    }
    let http = http.as_object_mut().expect("an object");
    let entries = http.entry("entries").or_insert_with(|| json!({}));
    if !entries.is_object() {
        *entries = json!({});
    }
    entries.as_object_mut().expect("an object")
}

/// Decode the request's single gRPC-Web message frame against the method's input message
/// (design §5.1).
fn decode_request(pool: &DescriptorPool, rpc: &str, body: &[u8]) -> Result<DynamicMessage, Reply> {
    let method = opv::adapters::http::descriptor::method(pool, rpc)
        .ok_or_else(|| error(3, "the method is not in the descriptor"))?;
    let payload =
        frame_payload(body).ok_or_else(|| error(3, "the gRPC-Web request frame is malformed"))?;
    DynamicMessage::decode(method.input(), payload)
        .map_err(|_| error(3, "the gRPC-Web request did not decode"))
}

/// The payload of the single `0x00` message frame a request body is.
fn frame_payload(body: &[u8]) -> Option<&[u8]> {
    let [0x00, a, b, c, d, rest @ ..] = body else {
        return None;
    };
    let len = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
    (rest.len() == len).then_some(rest)
}

/// A `PlatformConnection` message: provider, version and status only, never `masked_key`.
fn connection_message(
    pool: &DescriptorPool,
    provider: &str,
    version: i64,
    status: &str,
) -> DynamicMessage {
    let descriptor = pool
        .get_message_by_name("portal.v1.PlatformConnection")
        .expect("PlatformConnection in the pinned descriptor");
    let mut message = DynamicMessage::new(descriptor);
    message.set_field_by_name("provider", Value::String(provider.to_string()));
    message.set_field_by_name("version", Value::I64(version));
    let statuses = pool
        .get_enum_by_name("portal.v1.ConnectionStatus")
        .expect("ConnectionStatus in the pinned descriptor");
    let value = statuses
        .get_value_by_name(status)
        .expect("a defined ConnectionStatus");
    message.set_field_by_name("status", Value::EnumNumber(value.number()));
    message
}

/// A `PlatformConnections` reply message from `connections`.
fn connections_message(pool: &DescriptorPool, connections: Vec<DynamicMessage>) -> DynamicMessage {
    let descriptor = pool
        .get_message_by_name("portal.v1.PlatformConnections")
        .expect("PlatformConnections in the pinned descriptor");
    let mut message = DynamicMessage::new(descriptor);
    message.set_field_by_name(
        "connections",
        Value::List(connections.into_iter().map(Value::Message).collect()),
    );
    message
}

/// A `PlatformConnectionResult` reply message from one written `connection`.
fn result_message(pool: &DescriptorPool, connection: DynamicMessage) -> DynamicMessage {
    let descriptor = pool
        .get_message_by_name("portal.v1.PlatformConnectionResult")
        .expect("PlatformConnectionResult in the pinned descriptor");
    let mut message = DynamicMessage::new(descriptor);
    message.set_field_by_name("connection", Value::Message(connection));
    message
}

/// A successful reply: the encoded message frame, then a `grpc-status:0` body trailer.
fn ok(message: &DynamicMessage) -> Reply {
    let mut payload = Vec::new();
    message
        .encode(&mut payload)
        .expect("a message from the descriptor encodes");
    let mut body = message_frame(&payload);
    body.extend_from_slice(&trailer(0, None));
    envelope(body)
}

/// A non-zero-status reply: a trailers-only `0x80` body frame, as recorded Zonetico sends
/// it (design §5.1).
fn error(status: i32, message: &str) -> Reply {
    envelope(trailer(status, Some(message)))
}

/// The reply envelope the runner reads back (design §5).
fn envelope(body: Vec<u8>) -> Reply {
    let reply = opv::runner_https::HttpsReply {
        status: 200,
        content_type: Some(GRPC_WEB.to_string()),
        grpc_status: None,
        grpc_message: None,
        body: Zeroizing::new(body),
    };
    Reply::ok(opv::runner_https::encode_reply(&reply).to_vec())
}

/// A `0x00` gRPC-Web message frame.
fn message_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0x00);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A `0x80` gRPC-Web trailer frame: `name:value\r\n` lines with no space after the colon
/// (design §5.1).
fn trailer(status: i32, message: Option<&str>) -> Vec<u8> {
    let mut text = format!("grpc-status:{status}\r\n");
    if let Some(message) = message {
        text.push_str(&format!("grpc-message:{}\r\n", percent_encode(message)));
    }
    let mut frame = Vec::with_capacity(text.len() + 5);
    frame.push(0x80);
    frame.extend_from_slice(&(text.len() as u32).to_be_bytes());
    frame.extend_from_slice(text.as_bytes());
    frame
}

/// Percent-encode a `grpc-message` the way tonic sends it: everything outside the
/// unreserved set becomes `%XX` (design §5.1).
fn percent_encode(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for byte in message.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use prost::bytes::Bytes;

    use opv::adapters::http::grpc_decode::{DecodedReply, RoleKind, decode_reply, read_role};

    const TOKEN: &str = "CANARY-TOKEN-0123456789";
    const AUTHORIZATION: &str = "Bearer CANARY-TOKEN-0123456789";
    const OPERATOR: &str = "00000000-0000-4000-8000-000000000000";
    const CANARY_VALUE: &str = "CANARY-SECRET-VALUE-0123456789";

    /// The world's `http` section, pointing at the committed recorded descriptor.
    fn world_http() -> Json {
        json!({
            "descriptor": "tests/fixtures/https/zonetico/platform_console.binpb",
            "operator_id": OPERATOR,
            "token": TOKEN,
            "providers": ["openrouter", "tavily", "stripe"],
            "rejected": ["tavily"],
        })
    }

    fn pool() -> DescriptorPool {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/https/zonetico/platform_console.binpb");
        DescriptorPool::decode(std::fs::read(path).expect("descriptor").as_slice())
            .expect("a descriptor pool")
    }

    /// One request as the runner frames it: `0x00`, length, encoded message.
    fn framed(message: DynamicMessage) -> Vec<u8> {
        let mut payload = Vec::new();
        message.encode(&mut payload).expect("encode");
        let mut body = vec![0x00];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
        body
    }

    fn save_body(pool: &DescriptorPool, provider: &str, expected_version: i64) -> Vec<u8> {
        let method =
            opv::adapters::http::descriptor::method(pool, SAVE).expect("Save in the descriptor");
        let mut message = DynamicMessage::new(method.input());
        message.set_field_by_name("operator_id", Value::String(OPERATOR.to_string()));
        message.set_field_by_name("provider", Value::String(provider.to_string()));
        message.set_field_by_name("expected_version", Value::I64(expected_version));
        message.set_field_by_name(
            "secret_value",
            Value::Bytes(Bytes::copy_from_slice(CANARY_VALUE.as_bytes())),
        );
        framed(message)
    }

    fn list_body(pool: &DescriptorPool) -> Vec<u8> {
        let method =
            opv::adapters::http::descriptor::method(pool, LIST).expect("List in the descriptor");
        let mut message = DynamicMessage::new(method.input());
        message.set_field_by_name("operator_id", Value::String(OPERATOR.to_string()));
        framed(message)
    }

    /// Decode a reply through opv's own gRPC-Web decoder.
    fn decode(rpc: &str, reply: &Reply) -> DecodedReply {
        let envelope = opv::runner_https::decode_reply(&reply.stdout).expect("a reply envelope");
        decode_reply(&pool(), rpc, &envelope).expect("a decodable reply")
    }

    /// The version the list reply reports for `provider`.
    fn listed_version(reply: &Reply, provider: &str) -> i64 {
        let decoded = decode(LIST, reply);
        let message = decoded.decoded_message().expect("a listed message");
        let entries = read_role(message, "connections", RoleKind::Messages)
            .expect("connections")
            .as_messages()
            .expect("a repeated message")
            .to_vec();
        for connection in entries {
            if read_role(&connection, "provider", RoleKind::String)
                .expect("provider")
                .as_str()
                == Some(provider)
            {
                return read_role(&connection, "version", RoleKind::Int)
                    .expect("version")
                    .as_int()
                    .expect("an integer");
            }
        }
        panic!("{provider} was not listed");
    }

    #[test]
    fn a_save_then_list_shows_the_bumped_version() {
        let pool = pool();
        let mut state = json!({});
        let doc = world_http();
        let _ = serve(
            &doc,
            &mut state,
            "POST",
            SAVE,
            Some(AUTHORIZATION),
            &save_body(&pool, "openrouter", 0),
        );
        let listed = serve(
            &doc,
            &mut state,
            "POST",
            LIST,
            Some(AUTHORIZATION),
            &list_body(&pool),
        );
        assert_eq!(listed_version(&listed, "openrouter"), 1);
    }

    #[test]
    fn a_version_bump_before_save_conflicts() {
        let pool = pool();
        let mut state = json!({});
        let doc = world_http();
        let _ = serve(
            &doc,
            &mut state,
            "POST",
            SAVE,
            Some(AUTHORIZATION),
            &save_body(&pool, "openrouter", 0),
        );
        arm_bump(&mut state);
        let reply = serve(
            &doc,
            &mut state,
            "POST",
            SAVE,
            Some(AUTHORIZATION),
            &save_body(&pool, "openrouter", 1),
        );
        assert_eq!(decode(SAVE, &reply).grpc_status(), ALREADY_EXISTS);
    }

    #[test]
    fn a_wrong_token_is_unauthenticated() {
        let mut state = json!({});
        let reply = serve(
            &world_http(),
            &mut state,
            "POST",
            LIST,
            Some("Bearer CANARY-WRONG-TOKEN"),
            &list_body(&pool()),
        );
        assert_eq!(decode(LIST, &reply).grpc_status(), UNAUTHENTICATED);
    }

    #[test]
    fn a_saved_secret_value_reaches_neither_the_store_nor_the_reply() {
        let pool = pool();
        let mut state = json!({});
        let reply = serve(
            &world_http(),
            &mut state,
            "POST",
            SAVE,
            Some(AUTHORIZATION),
            &save_body(&pool, "openrouter", 0),
        );
        let stored = serde_json::to_string(&state).expect("the store serializes");
        let printed = String::from_utf8_lossy(&reply.stdout);
        assert!(!stored.contains(CANARY_VALUE) && !printed.contains(CANARY_VALUE));
    }
}
